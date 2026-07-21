import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin, urlsplit

import httpx
import yaml
from bs4 import BeautifulSoup
from defusedxml import ElementTree

from .client import AuthConfig, JenkinsClient
from .collector import Collector
from .models import Finding, TargetResult
from .utils import normalize_target, pin_to_origin, same_origin, target_slug, unique
from .vulnerabilities import VulnerabilityDB


ADJUNCT_PLUGIN_PATHS = {
    "/org/jenkinsci/plugins/scriptsecurity/": "script-security",
}
EventHandler = Optional[Callable[[Dict[str, Any]], None]]


@dataclass
class ScanSettings:
    verify_tls: bool = True
    verify_vulns: bool = False
    timeout: float = 20.0
    request_concurrency: int = 6
    retries: int = 2
    sleep_time: float = 0.0
    max_builds: Optional[int] = None
    collect_console: bool = True
    index_workspace: bool = True


class JenkinsScanner:
    def __init__(
        self,
        output_root: Path,
        vuln_db: VulnerabilityDB,
        settings: Optional[ScanSettings] = None,
        auth: Optional[AuthConfig] = None,
    ):
        self.output_root = output_root
        self.vuln_db = vuln_db
        self.settings = settings or ScanSettings()
        self.auth = auth or AuthConfig()
        checks_path = Path(__file__).parent / "data" / "checks.yml"
        self.check_data = yaml.safe_load(checks_path.read_text(encoding="utf-8")) or {}

    @staticmethod
    def _emit(handler: EventHandler, event: str, **payload: Any) -> None:
        if handler:
            handler({"event": event, **payload})

    async def detect(self, target: str, collector: Collector) -> Tuple[str, Dict[str, Any]]:
        had_scheme = "://" in target
        schemes = [None] if had_scheme else ["https", "http"]
        attempts = []
        async with httpx.AsyncClient(
            verify=self.settings.verify_tls,
            follow_redirects=False,
            timeout=httpx.Timeout(self.settings.timeout, connect=min(8.0, self.settings.timeout)),
            headers={"User-Agent": "jenknums/0.1.0"},
        ) as client:
            for scheme in schemes:
                try:
                    candidate = normalize_target(target, default_scheme=scheme or "https")
                except ValueError as exc:
                    attempts.append({"target": target, "error": str(exc)})
                    continue
                paths = [candidate]
                if urlsplit(candidate).path == "/":
                    paths.append(urljoin(candidate, "jenkins/"))
                for path in unique(paths):
                    current = path
                    try:
                        response = None
                        for _ in range(6):
                            response = await client.get(current)
                            if not response.is_redirect:
                                break
                            location = response.headers.get("location")
                            if not location:
                                break
                            redirected = urljoin(current, location)
                            if not same_origin(path, redirected):
                                break
                            current = redirected
                        if response is None:
                            continue
                        body = response.text[:250000]
                        version = response.headers.get("X-Jenkins") or response.headers.get("X-Hudson")
                        html_version = re.search(
                            r"data-version=[\"']jenkins-([0-9][0-9A-Za-z._-]*)", body, re.I
                        )
                        if not version and html_version:
                            version = html_version.group(1)
                        signature = bool(
                            version
                            or re.search(r"Dashboard(?: \[Jenkins\]| - Jenkins)", body, re.I)
                            or re.search(r"data-version=[\"']jenkins-[\d.]+", body, re.I)
                            or ("Jenkins" in body and "j_acegi_security_check" in body)
                        )
                        attempts.append(
                            {
                                "url": current,
                                "status": response.status_code,
                                "version": version,
                                "signature": signature,
                            }
                        )
                        collector.write_bytes(
                            "detection",
                            current,
                            response.content,
                            suffix=".html",
                            metadata={"url": current, "status": response.status_code},
                        )
                        if signature:
                            base = current
                            parsed = urlsplit(base)
                            if not parsed.path.endswith("/"):
                                base = base.rsplit("/", 1)[0] + "/"
                            return base, {"version": version, "attempts": attempts}
                    except (httpx.HTTPError, OSError) as exc:
                        attempts.append({"url": path, "error": str(exc)})
        raise RuntimeError(f"Jenkins was not detected: {attempts}")

    async def scan(self, target: str, event_handler: EventHandler = None) -> TargetResult:
        target_dir = self.output_root / target_slug(target)
        collector = Collector(target_dir, target)
        result = TargetResult(target=target, collection_dir=str(target_dir))
        try:
            base_url, detection = await self.detect(target, collector)
        except Exception as exc:
            result.add_error("detection", exc)
            result.finish()
            collector.write_json("report", "result", result.to_dict())
            return result

        result.target = base_url
        result.fingerprint.update(detection)
        result.fingerprint["base_url"] = base_url
        self._emit(
            event_handler,
            "detected",
            target=base_url,
            version=detection.get("version"),
            auth_mode=self.auth.mode,
        )
        contexts = ["anonymous"] + (["authenticated"] if self.auth.enabled else [])
        best_context = "authenticated" if self.auth.enabled else "anonymous"

        async with JenkinsClient(
            base_url,
            collector,
            auth=self.auth,
            verify_tls=self.settings.verify_tls,
            timeout=self.settings.timeout,
            concurrency=self.settings.request_concurrency,
            retries=self.settings.retries,
            sleep_time=self.settings.sleep_time,
        ) as client:
            async def emit_findings_after(awaitable) -> None:
                await awaitable
                self._emit(
                    event_handler,
                    "findings",
                    findings=[item.to_dict() for item in result.findings],
                    vulnerabilities=result.vulnerabilities,
                )

            identity_task = asyncio.create_task(
                self._enumerate_identity(
                    client, contexts, result, event_handler=event_handler
                )
            )
            checks_task = asyncio.create_task(
                emit_findings_after(self._run_checks(client, contexts, result))
            )
            services_task = asyncio.create_task(
                self._enumerate_services(client, best_context, result)
            )
            plugin_endpoints_task = asyncio.create_task(
                emit_findings_after(
                    self._enumerate_plugin_endpoints(client, best_context, result)
                )
            )
            system_info_task = asyncio.create_task(
                self._collect_system_info(client, best_context, result)
            )

            # Root inventory uses passive dashboard discoveries collected by identity.
            await identity_task
            await self._enumerate_root(client, best_context, result)
            self._emit(
                event_handler,
                "inventory",
                stage="api",
                auth_mode=self.auth.mode,
                inventory=result.inventory,
            )

            async def enumerate_views() -> None:
                await self._enumerate_views(client, best_context, result)
                self._emit(
                    event_handler,
                    "inventory",
                    stage="views",
                    auth_mode=self.auth.mode,
                    inventory={
                        **result.inventory,
                        "jobs": result.inventory.get("root", {}).get("jobs", []),
                    },
                )

            views_task = asyncio.create_task(enumerate_views())
            jobs_task = asyncio.create_task(
                self._enumerate_jobs(
                    client, best_context, result, event_handler=event_handler
                )
            )
            job_plans, _ = await asyncio.gather(jobs_task, views_task)
            # Views can expose jobs absent from the root API/dashboard.
            job_plans.extend(
                await self._enumerate_jobs(
                    client, best_context, result, event_handler=event_handler
                )
            )

            await asyncio.gather(checks_task, services_task, plugin_endpoints_task)

            plugins = result.inventory.get("plugins", [])
            version = result.fingerprint.get("version")
            result.inventory["plugin_health"] = self.vuln_db.plugin_health(plugins)
            result.vulnerabilities = self.vuln_db.correlate(version, plugins)
            self._add_vulnerability_findings(result)
            self._emit(
                event_handler,
                "findings",
                findings=[item.to_dict() for item in result.findings],
                vulnerabilities=result.vulnerabilities,
            )
            self._emit(event_handler, "quick_complete")

            enrichment_tasks = [
                asyncio.create_task(
                    self._collect_job_configs(client, best_context, result, job_plans)
                ),
                asyncio.create_task(
                    self._collect_view_configs(client, best_context, result)
                ),
                asyncio.create_task(
                    self._collect_build_metadata(client, best_context, result, job_plans)
                ),
                asyncio.create_task(
                    self._enumerate_nodes_and_users(client, best_context, result)
                ),
                system_info_task,
            ]
            if self.settings.collect_console:
                enrichment_tasks.append(
                    asyncio.create_task(
                        self._collect_build_consoles(client, best_context, result)
                    )
                )
            if self.settings.index_workspace:
                enrichment_tasks.append(
                    asyncio.create_task(
                        self._collect_workspaces(
                            client, best_context, result, job_plans
                        )
                    )
                )
            await asyncio.gather(*enrichment_tasks)

            result.coverage = {
                "requests": len(client.request_log),
                "jobs": len(result.inventory.get("jobs", [])),
                "builds": len(result.inventory.get("builds", [])),
                "plugins": len(plugins),
                "users": len(result.inventory.get("users", [])),
                "job_inventory": result.inventory.get("job_inventory_source", "unavailable-or-empty"),
                "build_inventory": result.inventory.get("build_inventory_source", "unavailable-or-empty"),
                "plugin_inventory": result.inventory.get(
                    "plugin_inventory_source", "unavailable-or-empty"
                ),
                "authenticated": self.auth.enabled,
                "vulnerability_db": self.vuln_db.stats(),
            }
            collector.write_json("http", "request-log", client.request_log)

        result.finish()
        collector.write_json("report", "result", result.to_dict())
        return result

    async def _enumerate_identity(
        self,
        client: JenkinsClient,
        contexts: Iterable[str],
        result: TargetResult,
        event_handler: EventHandler = None,
    ) -> None:
        identities = {}
        crumbs = {}
        roots = {}
        dashboards = {}
        for context in contexts:
            try:
                response = await client.request(
                    "GET",
                    "./",
                    context=context,
                    save_as=("root", f"dashboard-{context}"),
                    retries=0,
                    timeout=min(self.settings.timeout, 10.0),
                )
                roots[context] = {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "url": str(response.url),
                }
                if response.status_code == 200 and not self._looks_like_login(response.text):
                    dashboards[context] = self._parse_dashboard_html(
                        client.base_url, str(response.url), response.text
                    )
                    dashboard = dashboards[context]
                    self._emit(
                        event_handler,
                        "inventory",
                        stage="dashboard",
                        auth_mode=self.auth.mode,
                        inventory={
                            "views": dashboard.get("views", []),
                            "jobs": dashboard.get("jobs", []),
                            "plugins": dashboard.get("plugins", []),
                            "nodes": [],
                            "users": [],
                            "credentials": [],
                        },
                    )
                version = response.headers.get("X-Jenkins") or response.headers.get("X-Hudson")
                if version:
                    result.fingerprint["version"] = version
                if response.headers.get("X-Jenkins-Session"):
                    result.fingerprint["session"] = response.headers["X-Jenkins-Session"]
                if response.headers.get("X-SSH-Endpoint"):
                    result.services["ssh_endpoint"] = response.headers["X-SSH-Endpoint"]
                for header in ("X-Hudson-CLI-Port", "X-Jenkins-CLI2-Port"):
                    if response.headers.get(header):
                        result.services[header.lower().replace("-", "_")] = response.headers[header]
            except Exception as exc:
                result.add_error("root", exc, client.base_url)
            try:
                response, data = await client.get_json(
                    "whoAmI/api/json",
                    context=context,
                    save_as=("identity", f"whoami-{context}"),
                    retries=0,
                    timeout=min(self.settings.timeout, 10.0),
                )
                identities[context] = {"status": response.status_code, "data": data}
            except Exception as exc:
                result.add_error("identity", exc, client.url("whoAmI/api/json"))
            try:
                response, data = await client.get_json(
                    "crumbIssuer/api/json",
                    context=context,
                    save_as=("identity", f"crumb-{context}"),
                    retries=0,
                    timeout=min(self.settings.timeout, 10.0),
                )
                crumbs[context] = {"status": response.status_code, "data": data}
            except Exception as exc:
                result.add_error("crumb", exc, client.url("crumbIssuer/api/json"))
        result.auth = {
            "configured_mode": self.auth.mode,
            "username": self.auth.username,
            "identities": identities,
            "crumbs": crumbs,
        }
        result.security["root_access"] = roots
        result.inventory["dashboards"] = dashboards
        if client.base_url.startswith("http://"):
            result.add_finding(
                Finding(
                    id="insecure-http",
                    title="Jenkins is served over cleartext HTTP",
                    severity="medium",
                    category="transport-security",
                    evidence={"url": client.base_url},
                    url=client.base_url,
                )
            )
        for context, root in roots.items():
            headers = {key.lower(): value for key, value in root.get("headers", {}).items()}
            if client.base_url.startswith("https://") and "strict-transport-security" not in headers:
                result.add_finding(
                    Finding(
                        id="missing-hsts",
                        title="HTTPS response does not advertise HSTS",
                        severity="low",
                        category="transport-security",
                        evidence={"status": root.get("status")},
                        url=client.base_url,
                        auth_context=context,
                    )
                )

    async def _enumerate_root(self, client: JenkinsClient, context: str, result: TargetResult) -> None:
        endpoints = {
            "root": "api/json?depth=1",
            "queue": "queue/api/json?depth=2",
            "nodes": "computer/api/json?depth=2",
            "plugins": "pluginManager/api/json?depth=1",
            "users_async": "asynchPeople/api/json?depth=2",
            "users_people": "people/api/json?depth=2",
            "credentials": "credentials/store/system/domain/_/api/json?depth=2",
        }
        async def fetch(name: str, endpoint: str) -> Tuple[str, Any]:
            try:
                response, data = await client.get_json(
                    endpoint,
                    context=context,
                    save_as=("inventory", name),
                    retries=0,
                    timeout=min(self.settings.timeout, 10.0),
                )
                if response.status_code == 200 and data is not None:
                    return name, data
            except Exception as exc:
                result.add_error(name, exc, client.url(endpoint))
            return name, None

        payloads = {
            name: data
            for name, data in await asyncio.gather(
                *(fetch(name, endpoint) for name, endpoint in endpoints.items())
            )
            if data is not None
        }

        root = payloads.get("root", {})
        dashboard = result.inventory.get("dashboards", {}).get(context, {})
        root = dict(root) if isinstance(root, dict) else {}
        api_jobs = root.get("jobs", []) or []
        api_views = root.get("views", []) or []
        dashboard_jobs = dashboard.get("jobs", []) or []
        dashboard_views = dashboard.get("views", []) or []
        root["jobs"] = self._merge_url_items(client.base_url, api_jobs, dashboard_jobs)
        root["views"] = self._merge_url_items(client.base_url, api_views, dashboard_views)
        if not api_jobs and dashboard_jobs:
            root["source"] = "dashboard-html"

        api_plugins = payloads.get("plugins", {}).get("plugins", [])
        inferred_plugins = dashboard.get("plugins", []) or []
        result.inventory["root"] = root
        result.inventory["queue"] = payloads.get("queue", {}).get("items", [])
        result.inventory["nodes"] = payloads.get("nodes", {}).get("computer", [])
        result.inventory["plugins"] = self._merge_plugins(api_plugins, inferred_plugins)
        if api_plugins:
            result.inventory["plugin_inventory_source"] = (
                "api+passive" if inferred_plugins else "api"
            )
        elif inferred_plugins:
            result.inventory["plugin_inventory_source"] = "partial-passive"
        result.inventory["credentials"] = self._extract_credentials(payloads.get("credentials", {}))
        result.inventory["views"] = root.get("views", [])
        result.inventory["jobs"] = []
        result.inventory["builds"] = []
        users = []
        for key in ("users_async", "users_people"):
            for item in payloads.get(key, {}).get("users", []):
                user = item.get("user") if isinstance(item.get("user"), dict) else item
                if isinstance(user, dict):
                    users.append(user)
        result.inventory["users"] = self._dedupe_dicts(users, ("id", "fullName", "absoluteUrl"))

        if root.get("numExecutors", 0) > 0:
            result.add_finding(
                Finding(
                    id="built-in-node-executors",
                    title="Build executors are enabled on the Jenkins built-in node",
                    severity="high",
                    category="controller-isolation",
                    evidence={"numExecutors": root.get("numExecutors")},
                    url=client.base_url,
                    remediation="Set the built-in node executor count to 0 and run builds on agents.",
                )
            )

    async def _enumerate_nodes_and_users(
        self, client: JenkinsClient, context: str, result: TargetResult
    ) -> None:
        for node in result.inventory.get("nodes", []):
            name = node.get("displayName")
            if not name:
                continue
            encoded = quote(str(name), safe="")
            for endpoint, label in (
                (f"computer/{encoded}/config.xml", "config"),
                (f"computer/{encoded}/systemInfo", "system-info"),
                (f"computer/{encoded}/jenkins-agent.jnlp?encrypted=true", "agent-jnlp"),
            ):
                try:
                    response = await client.request(
                        "GET",
                        endpoint,
                        context=context,
                        save_as=("nodes", f"{name}-{label}"),
                    )
                    node[f"{label.replace('-', '_')}_status"] = response.status_code
                except Exception as exc:
                    result.add_error(f"node-{label}", exc, client.url(endpoint))

        await self._enumerate_users(client, context, result)

    async def _enumerate_users(
        self, client: JenkinsClient, context: str, result: TargetResult
    ) -> None:
        for user in result.inventory.get("users", []):
            if "api_status" in user:
                continue
            user_id = user.get("id")
            if not user_id:
                continue
            encoded = quote(str(user_id), safe="")
            for endpoint, label in (
                (f"user/{encoded}/api/json?depth=2", "api"),
                (f"user/{encoded}/configure", "configure"),
                (f"user/{encoded}/security", "security"),
            ):
                try:
                    response = await client.request(
                        "GET",
                        endpoint,
                        context=context,
                        save_as=("users", f"{user_id}-{label}"),
                    )
                    user[f"{label}_status"] = response.status_code
                except Exception as exc:
                    result.add_error(f"user-{label}", exc, client.url(endpoint))

    async def _collect_system_info(self, client: JenkinsClient, context: str, result: TargetResult) -> None:
        try:
            response = await client.request(
                "GET", "systemInfo", context=context, save_as=("system", "system-info")
            )
            if response.status_code != 200 or self._looks_like_login(response.text):
                return
            soup = BeautifulSoup(response.text, "html.parser")
            values = {}
            for row in soup.select("tr"):
                cells = row.find_all(["th", "td"])
                if len(cells) >= 2:
                    key = cells[0].get_text(" ", strip=True)
                    value = cells[1].get_text(" ", strip=True)
                    if key:
                        values[key] = value
            result.inventory["system_info"] = values
        except Exception as exc:
            result.add_error("system-info", exc, client.url("systemInfo"))

    async def _run_checks(self, client: JenkinsClient, contexts: Iterable[str], result: TargetResult) -> None:
        service_state = {}
        for check in self.check_data.get("checks", []):
            if check.get("verify_only") and not self.settings.verify_vulns:
                continue
            allowed_contexts = set(check.get("contexts", ["anonymous"]))
            for context in contexts:
                if context not in allowed_contexts:
                    continue
                try:
                    response = await client.request(
                        "GET",
                        check["path"],
                        context=context,
                        save_as=("checks", f"{check['id']}-{context}"),
                    )
                    matched, detail = self._match_check(check.get("parser", "html"), response)
                    service_state[f"{check['id']}:{context}"] = {
                        "status": response.status_code,
                        "url": str(response.url),
                        "matched": matched,
                    }
                    if matched:
                        result.add_finding(
                            Finding(
                                id=check["id"],
                                title=check["title"],
                                severity=check["severity"],
                                category=check["category"],
                                evidence={"status": response.status_code, "detail": detail},
                                url=str(response.url),
                                auth_context=context,
                            )
                        )
                except Exception as exc:
                    result.add_error(check["id"], exc, client.url(check["path"]))
        result.services["checks"] = service_state

        if self.settings.verify_vulns:
            endpoint = "securityRealm/user/admin/search/index?q=a"
            try:
                response = await client.request(
                    "GET", endpoint, context="anonymous", save_as=("checks", "cve-2018-1000861")
                )
                if response.status_code == 200 and not self._looks_like_login(response.text):
                    result.add_finding(
                        Finding(
                            id="cve-2018-1000861-safe-probe",
                            title="Security realm routing endpoint is accessible without authentication",
                            severity="critical",
                            category="access-control",
                            status="confirmed",
                            evidence={"status": response.status_code},
                            url=str(response.url),
                            cves=["CVE-2018-1000861"],
                            advisory="https://www.jenkins.io/security/advisory/2018-12-05/",
                            auth_context="anonymous",
                        )
                    )
            except Exception as exc:
                result.add_error("cve-2018-1000861-safe-probe", exc, client.url(endpoint))

    def _match_check(self, parser: str, response: httpx.Response) -> Tuple[bool, str]:
        text = response.text
        if parser == "cli":
            return response.status_code in {200, 401, 403}, "CLI endpoint responded"
        if parser == "agent_listener":
            matched = response.status_code == 200 and (
                "Jenkins-Agent-Protocols" in text or "X-Jenkins-Session" in response.headers
            )
            return matched, "agent protocol metadata returned"
        if parser == "instance_identity":
            return response.status_code == 200 and "PUBLIC KEY" in text, "public key returned"
        if parser == "stack_trace":
            matched = response.status_code == 500 and "java.lang." in text and "Exception" in text
            return matched, "Java exception returned"
        if response.status_code != 200 or self._looks_like_login(text):
            return False, "not accessible"
        if parser == "json":
            try:
                response.json()
                return True, "JSON data returned"
            except ValueError:
                return False, "invalid JSON"
        if parser == "root_view_config":
            try:
                root_tag = str(ElementTree.fromstring(text).tag).split("}")[-1]
            except Exception:
                return False, "invalid XML"
            matched = root_tag.endswith("View") or ".view." in root_tag.lower()
            return matched, f"root view configuration XML returned ({root_tag})"
        if parser == "dashboard":
            matched = bool(re.search(r"Dashboard(?: \[Jenkins\]| - Jenkins)", text, re.I))
            return matched, "dashboard title matched"
        if parser == "script_console":
            return "Script Console" in text and "println" in text, "script console form returned"
        if parser == "system_info":
            return "System Information" in text and ("System Properties" in text or "Environment Variables" in text), "system information returned"
        if parser == "signup":
            return bool(re.search(r"Create an account|Sign up|signup", text, re.I)), "signup form returned"
        return True, "HTTP 200 returned"

    async def _enumerate_services(self, client: JenkinsClient, context: str, result: TargetResult) -> None:
        try:
            response = await client.request(
                "HEAD", "jnlpJars/jenkins-cli.jar", context="anonymous", save_as=("services", "jenkins-cli-jar")
            )
            result.services["cli_jar"] = {
                "status": response.status_code,
                "content_length": response.headers.get("content-length"),
                "url": str(response.url),
            }
        except Exception as exc:
            result.add_error("cli-jar", exc, client.url("jnlpJars/jenkins-cli.jar"))

        try:
            response = await client.request(
                "GET", "tcpSlaveAgentListener/", context="anonymous", save_as=("services", "agent-listener")
            )
            if response.status_code == 200:
                parsed = {}
                for line in response.text.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        parsed[key.strip()] = value.strip()
                result.services["agent_listener"] = parsed
        except Exception as exc:
            result.add_error("agent-listener", exc, client.url("tcpSlaveAgentListener/"))

        for endpoint, name in (("wsagents/", "websocket-agents"), ("instance-identity/", "instance-identity")):
            try:
                response = await client.request(
                    "GET", endpoint, context="anonymous", save_as=("services", name)
                )
                result.services[name.replace("-", "_")] = {
                    "status": response.status_code,
                    "url": str(response.url),
                }
            except Exception as exc:
                result.add_error(name, exc, client.url(endpoint))

        websocket_headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "amVua251bXMtcHJvYmUhIQ==",
            "Origin": client.base_url.rstrip("/"),
        }
        try:
            response = await client.request(
                "GET",
                "cli/ws",
                context=context,
                headers=websocket_headers,
                save_as=("services", "cli-websocket"),
            )
            result.services["cli_websocket"] = {
                "status": response.status_code,
                "reachable": response.status_code in {101, 400, 401, 403},
                "url": str(response.url),
            }
        except Exception as exc:
            result.add_error("cli-websocket", exc, client.url("cli/ws"))

    async def _enumerate_views(self, client: JenkinsClient, context: str, result: TargetResult) -> None:
        output = []
        for view in result.inventory.get("views", []):
            url = view.get("url")
            if not url:
                continue
            item = dict(view)
            try:
                response, data = await client.get_json(
                    url.rstrip("/") + "/api/json?depth=1",
                    context=context,
                    save_as=("views", f"{view.get('name', 'view')}-api"),
                )
                item["api_status"] = response.status_code
                if data is not None:
                    item["data"] = data
                    root = result.inventory.setdefault("root", {})
                    root["jobs"] = self._merge_url_items(
                        client.base_url, root.get("jobs", []), data.get("jobs", [])
                    )
            except Exception as exc:
                result.add_error("view-api", exc, url)
            try:
                response = await client.request(
                    "GET",
                    url,
                    context=context,
                    save_as=("views", f"{view.get('name', 'view')}-dashboard"),
                )
                item["html_status"] = response.status_code
                if response.status_code == 200 and not self._looks_like_login(response.text):
                    parsed = self._parse_dashboard_html(
                        client.base_url, str(response.url), response.text
                    )
                    item["discovered_jobs"] = len(parsed.get("jobs", []))
                    root = result.inventory.setdefault("root", {})
                    root["jobs"] = self._merge_url_items(
                        client.base_url, root.get("jobs", []), parsed.get("jobs", [])
                    )
                    result.inventory["plugins"] = self._merge_plugins(
                        result.inventory.get("plugins", []), parsed.get("plugins", [])
                    )
                    if parsed.get("plugins") and not result.inventory.get(
                        "plugin_inventory_source"
                    ):
                        result.inventory["plugin_inventory_source"] = "partial-passive"
            except Exception as exc:
                result.add_error("view-html", exc, url)
            output.append(item)
        result.inventory["views"] = output

    async def _collect_view_configs(
        self, client: JenkinsClient, context: str, result: TargetResult
    ) -> None:
        async def collect(view: Dict[str, Any]) -> None:
            url = view.get("url")
            if not url:
                return
            try:
                response = await client.request(
                    "GET",
                    url.rstrip("/") + "/config.xml",
                    context=context,
                    save_as=("views", f"{view.get('name', 'view')}-config"),
                )
                view["config_status"] = response.status_code
            except Exception as exc:
                result.add_error("view-config", exc, url)

        await asyncio.gather(*(collect(view) for view in result.inventory.get("views", [])))

    async def _enumerate_jobs(
        self,
        client: JenkinsClient,
        context: str,
        result: TargetResult,
        event_handler: EventHandler = None,
    ) -> List[Dict[str, Any]]:
        root_jobs = result.inventory.get("root", {}).get("jobs", [])
        queue = list(root_jobs)
        seen: Set[str] = {
            client.url(item["url"]).rstrip("/") + "/"
            for item in result.inventory.get("jobs", [])
            if item.get("url")
        }
        plans: List[Dict[str, Any]] = []

        async def inspect(job: Dict[str, Any]) -> Dict[str, Any]:
            job_url = job.get("url")
            pinned = client.url(job_url).rstrip("/") + "/"
            job_name = job.get("fullName") or job.get("name") or pinned
            summary: Dict[str, Any] = {
                "name": job_name,
                "url": pinned,
                "class": job.get("_class"),
                "source": job.get("source") or "root-api",
            }
            for key in (
                "displayName",
                "fullName",
                "color",
                "last_successful_build",
                "last_failed_build",
                "lastDuration",
            ):
                if job.get(key) is not None:
                    summary[key] = job[key]

            job_data = None
            nested_jobs = []
            try:
                response, job_data = await client.get_json(
                    pinned + "api/json?depth=1",
                    context=context,
                    save_as=("jobs", f"{job_name}-api"),
                    retries=0,
                    timeout=min(self.settings.timeout, 10.0),
                )
                summary["api_status"] = response.status_code
                if isinstance(job_data, dict):
                    summary["source"] = "api"
                    summary.update(
                        {
                            "displayName": job_data.get("displayName"),
                            "fullName": job_data.get("fullName"),
                            "description": job_data.get("description"),
                            "color": job_data.get("color"),
                            "buildable": job_data.get("buildable"),
                            "inQueue": job_data.get("inQueue"),
                            "nextBuildNumber": job_data.get("nextBuildNumber"),
                        }
                    )
                    nested_jobs = job_data.get("jobs", []) or []
            except Exception as exc:
                result.add_error("job-api", exc, pinned)

            fallback_builds = []
            if not isinstance(job_data, dict):
                try:
                    response = await client.request(
                        "GET",
                        pinned,
                        context=context,
                        save_as=("jobs", f"{job_name}-dashboard"),
                        retries=0,
                        timeout=min(self.settings.timeout, 10.0),
                    )
                    summary["html_status"] = response.status_code
                    if response.status_code == 200 and not self._looks_like_login(
                        response.text
                    ):
                        summary.update(self._parse_job_html(pinned, response.text))
                        history = await client.request(
                            "GET",
                            pinned + "buildHistory/ajax",
                            context=context,
                            save_as=("jobs", f"{job_name}-build-history"),
                            retries=0,
                            timeout=min(self.settings.timeout, 10.0),
                        )
                        summary["build_history_status"] = history.status_code
                        if history.status_code == 200 and not self._looks_like_login(
                            history.text
                        ):
                            fallback_builds = self._parse_build_history_html(
                                client.base_url, pinned, str(job_name), history.text
                            )
                except Exception as exc:
                    result.add_error("job-html", exc, pinned)

            api_builds = []
            references = fallback_builds
            if isinstance(job_data, dict):
                api_builds = job_data.get("builds", []) or []
                if self.settings.max_builds is not None:
                    api_builds = api_builds[: self.settings.max_builds]
                references = [
                    {
                        "job": job_name,
                        "number": build.get("number"),
                        "url": client.url(build.get("url", "")).rstrip("/") + "/",
                        "source": "api",
                    }
                    for build in api_builds
                ]
            elif self.settings.max_builds is not None:
                references = references[: self.settings.max_builds]

            return {
                "summary": summary,
                "nested_jobs": nested_jobs,
                "references": references,
                "plan": {
                    "summary": summary,
                    "url": pinned,
                    "name": str(job_name),
                    "api_builds": api_builds,
                },
            }

        while queue:
            batch = []
            while queue:
                job = queue.pop(0)
                if not job.get("url"):
                    continue
                pinned = client.url(job["url"]).rstrip("/") + "/"
                if pinned in seen:
                    continue
                seen.add(pinned)
                batch.append(asyncio.create_task(inspect(job)))

            for task in asyncio.as_completed(batch):
                discovered = await task
                summary = discovered["summary"]
                references = discovered["references"]
                result.inventory.setdefault("jobs", []).append(summary)
                result.inventory.setdefault("builds", []).extend(references)
                queue.extend(discovered["nested_jobs"])
                plans.append(discovered["plan"])
                self._emit(event_handler, "job", item=summary)
                if references:
                    self._emit(event_handler, "builds", items=references)

        result.inventory["builds"] = self._dedupe_dicts(
            result.inventory.get("builds", []), ("job", "number", "url")
        )
        job_sources = {
            str(item.get("source") or "unknown")
            for item in result.inventory.get("jobs", [])
        }
        build_sources = {
            str(item.get("source") or "unknown")
            for item in result.inventory.get("builds", [])
        }
        if job_sources:
            result.inventory["job_inventory_source"] = (
                "api" if job_sources == {"api"} else "api+passive" if "api" in job_sources else "partial-html"
            )
        if build_sources:
            result.inventory["build_inventory_source"] = (
                "api" if build_sources == {"api"} else "api+html" if "api" in build_sources else "partial-html"
            )
        return plans

    async def _collect_job_configs(
        self,
        client: JenkinsClient,
        context: str,
        result: TargetResult,
        plans: Iterable[Dict[str, Any]],
    ) -> None:
        async def collect(plan: Dict[str, Any]) -> None:
            try:
                response = await client.request(
                    "GET",
                    plan["url"] + "config.xml",
                    context=context,
                    save_as=("jobs", f"{plan['name']}-config"),
                )
                plan["summary"]["config_status"] = response.status_code
            except Exception as exc:
                result.add_error("job-config", exc, plan["url"] + "config.xml")

        await asyncio.gather(*(collect(plan) for plan in plans))

    async def _collect_build_metadata(
        self,
        client: JenkinsClient,
        context: str,
        result: TargetResult,
        plans: Iterable[Dict[str, Any]],
    ) -> None:
        users = list(result.inventory.get("users", []))
        build_index = {
            (item.get("job"), item.get("number"), item.get("url")): item
            for item in result.inventory.get("builds", [])
        }
        async def collect(plan: Dict[str, Any], build: Dict[str, Any]):
            return await self._collect_build(client, context, plan["name"], build)

        collected = await asyncio.gather(
            *(
                collect(plan, build)
                for plan in plans
                for build in plan.get("api_builds", [])
            )
        )
        for build_summary, build_users in collected:
            marker = (
                build_summary.get("job"),
                build_summary.get("number"),
                build_summary.get("url"),
            )
            if marker in build_index:
                build_index[marker].update(build_summary)
            users.extend(build_users)
        result.inventory["users"] = self._dedupe_dicts(
            users, ("id", "fullName", "absoluteUrl")
        )

    async def _collect_build_consoles(
        self, client: JenkinsClient, context: str, result: TargetResult
    ) -> None:
        async def collect(build: Dict[str, Any]) -> None:
            if build.get("source") != "api":
                return
            label = f"{build.get('job')}-build-{build.get('number')}"
            try:
                build["console"] = await client.stream_to_file(
                    build["url"] + "consoleText",
                    "console",
                    label,
                    context=context,
                    suffix=".log",
                )
            except Exception as exc:
                build["console_error"] = str(exc)

        await asyncio.gather(*(collect(build) for build in result.inventory.get("builds", [])))

    async def _collect_workspaces(
        self,
        client: JenkinsClient,
        context: str,
        result: TargetResult,
        plans: Iterable[Dict[str, Any]],
    ) -> None:
        async def collect(plan: Dict[str, Any]) -> None:
            try:
                plan["summary"]["workspace"] = await self._index_workspace(
                    client, plan["url"] + "ws/", context, plan["name"]
                )
            except Exception as exc:
                result.add_error("workspace", exc, plan["url"] + "ws/")

        await asyncio.gather(*(collect(plan) for plan in plans))

    async def _collect_build(
        self,
        client: JenkinsClient,
        context: str,
        job_name: str,
        build: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        build_url = client.url(build.get("url", "")).rstrip("/") + "/"
        number = build.get("number")
        label = f"{job_name}-build-{number}"
        summary: Dict[str, Any] = {
            "job": job_name,
            "number": number,
            "url": build_url,
            "source": "api",
        }
        users: List[Dict[str, Any]] = []
        detail = None
        try:
            response, detail = await client.get_json(
                build_url + "api/json?depth=2",
                context=context,
                save_as=("builds", f"{label}-api"),
            )
            summary["api_status"] = response.status_code
            if isinstance(detail, dict):
                for key in (
                    "result",
                    "timestamp",
                    "duration",
                    "estimatedDuration",
                    "building",
                    "displayName",
                    "fullDisplayName",
                    "description",
                ):
                    summary[key] = detail.get(key)
                summary["artifacts"] = detail.get("artifacts", [])
                users.extend(self._find_users(detail))
        except Exception:
            summary["api_status"] = None

        for endpoint, name in (
            ("testReport/api/json?depth=2", "test-report"),
            ("wfapi/describe", "pipeline"),
            ("injectedEnvVars/api/json", "injected-env"),
        ):
            try:
                response, data = await client.get_json(
                    build_url + endpoint,
                    context=context,
                    save_as=("builds", f"{label}-{name}"),
                )
                if response.status_code == 200 and data is not None:
                    summary[name.replace("-", "_")] = data
            except Exception:
                continue
        return summary, users

    async def _index_workspace(
        self,
        client: JenkinsClient,
        workspace_url: str,
        context: str,
        job_name: str,
    ) -> Dict[str, Any]:
        root = client.url(workspace_url)
        root_path = urlsplit(root).path
        queue = [(root, 0)]
        seen = set()
        entries = []
        while queue and len(entries) < 100000:
            current, depth = queue.pop(0)
            if current in seen or depth > 64:
                continue
            seen.add(current)
            response = await client.request(
                "GET",
                current,
                context=context,
                save_as=("workspace-pages", f"{job_name}-{urlsplit(current).path}"),
            )
            if response.status_code != 200 or self._looks_like_login(response.text):
                if current == root:
                    return {"status": response.status_code, "entries": []}
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if not href or href.startswith(("#", "javascript:")) or href in {"../", "./"}:
                    continue
                absolute = pin_to_origin(client.base_url, urljoin(current, href))
                parsed = urlsplit(absolute)
                if not parsed.path.startswith(root_path):
                    continue
                is_dir = parsed.path.endswith("/")
                entry = {
                    "name": link.get_text(" ", strip=True),
                    "url": absolute,
                    "path": parsed.path[len(root_path) :],
                    "directory": is_dir,
                }
                entries.append(entry)
                if is_dir and absolute not in seen:
                    queue.append((absolute, depth + 1))
        path = client.collector.write_json("workspace-index", job_name, entries)
        return {"status": 200, "entries": len(entries), "path": path}

    async def _enumerate_plugin_endpoints(
        self, client: JenkinsClient, context: str, result: TargetResult
    ) -> None:
        endpoints = []
        for endpoint in self.check_data.get("plugin_endpoints", []):
            try:
                response = await client.request(
                    "GET",
                    endpoint["path"],
                    context=context,
                    save_as=("plugin-endpoints", endpoint["id"]),
                )
                item = {"id": endpoint["id"], "url": str(response.url), "status": response.status_code}
                endpoints.append(item)
                if response.status_code == 200 and not self._looks_like_login(response.text):
                    result.add_finding(
                        Finding(
                            id=f"plugin-endpoint-{endpoint['id']}",
                            title=f"Jenkins plugin endpoint is accessible: {endpoint['id']}",
                            severity="info",
                            category="plugin-surface",
                            evidence={"status": response.status_code},
                            url=str(response.url),
                            auth_context=context,
                        )
                    )
            except Exception as exc:
                result.add_error(endpoint["id"], exc, client.url(endpoint["path"]))
        result.services["plugin_endpoints"] = endpoints

    @staticmethod
    def _parse_dashboard_html(base_url: str, page_url: str, text: str) -> Dict[str, Any]:
        soup = BeautifulSoup(text, "html.parser")
        base_path = urlsplit(base_url).path.rstrip("/") + "/"
        jobs: Dict[str, Dict[str, Any]] = {}
        views: Dict[str, Dict[str, Any]] = {}
        plugins: Dict[str, Dict[str, Any]] = {}

        for link in soup.find_all("a", href=True):
            absolute = pin_to_origin(base_url, urljoin(page_url, link["href"]))
            path = urlsplit(absolute).path
            if not path.startswith(base_path):
                continue
            relative = path[len(base_path) :]

            job_match = re.fullmatch(r"((?:job/[^/]+/)+)", relative)
            if job_match:
                canonical = pin_to_origin(base_url, base_path + job_match.group(1))
                segments = re.findall(r"job/([^/]+)/", job_match.group(1))
                item = jobs.setdefault(
                    canonical,
                    {
                        "name": "/".join(segments),
                        "fullName": "/".join(segments),
                        "url": canonical,
                        "source": "dashboard-html",
                    },
                )
                label = link.get_text(" ", strip=True)
                if label:
                    item["displayName"] = label
                row = link.find_parent("tr")
                if row:
                    status_class = next(
                        (
                            name[len("job-status-") :]
                            for name in row.get("class", [])
                            if name.startswith("job-status-")
                        ),
                        None,
                    )
                    if status_class:
                        item["color"] = status_class
                    for key, suffix in (
                        ("lastSuccessfulBuild", "last_successful_build"),
                        ("lastFailedBuild", "last_failed_build"),
                    ):
                        build_link = row.find("a", href=re.compile(rf"/{key}/?$"))
                        if build_link:
                            number = re.search(r"#(\d+)", build_link.get_text(" ", strip=True))
                            item[suffix] = int(number.group(1)) if number else None
                    cells = row.find_all("td", recursive=False)
                    if len(cells) >= 2:
                        duration = cells[-2].get_text(" ", strip=True)
                        if duration:
                            item["lastDuration"] = duration

            view_match = re.fullmatch(r"view/([^/]+)/", relative)
            if view_match:
                canonical = pin_to_origin(base_url, base_path + view_match.group(0))
                views.setdefault(
                    canonical,
                    {
                        "name": view_match.group(1),
                        "url": canonical,
                        "source": "dashboard-html",
                    },
                )

        for element in soup.find_all(src=True):
            source = str(element.get("src") or "")
            plugin_match = re.search(r"/plugin/([^/]+)/", source, re.I)
            if plugin_match:
                name = plugin_match.group(1)
                plugins.setdefault(
                    name,
                    {
                        "shortName": name,
                        "version": None,
                        "source": "resource-url",
                        "inferred": True,
                    },
                )
            path = urlsplit(urljoin(page_url, source)).path.lower()
            for marker, name in ADJUNCT_PLUGIN_PATHS.items():
                if marker in path:
                    plugins.setdefault(
                        name,
                        {
                            "shortName": name,
                            "version": None,
                            "source": "adjunct-path",
                            "inferred": True,
                        },
                    )

        executor = None
        executor_details = soup.select_one("#executors .pane-header-details")
        if executor_details:
            match = re.search(r"(\d+)\s*/\s*(\d+)", executor_details.get_text(" ", strip=True))
            if match:
                executor = {"busy": int(match.group(1)), "total": int(match.group(2))}

        return {
            "jobs": list(jobs.values()),
            "views": list(views.values()),
            "plugins": list(plugins.values()),
            "executors": executor,
        }

    @staticmethod
    def _parse_job_html(job_url: str, text: str) -> Dict[str, Any]:
        soup = BeautifulSoup(text, "html.parser")
        output: Dict[str, Any] = {"source": "job-html"}
        heading = soup.select_one(".jenkins-app-bar h1") or soup.find("h1")
        if heading:
            output["displayName"] = heading.get_text(" ", strip=True)
        description = soup.select_one("#description-content")
        if description:
            value = description.get_text(" ", strip=True)
            if value:
                output["description"] = value
        properties = soup.select_one("#properties[page-next-build]")
        if properties:
            try:
                output["nextBuildNumber"] = int(properties["page-next-build"])
            except (KeyError, TypeError, ValueError):
                pass
        latest = None
        job_path = re.escape(urlsplit(job_url).path)
        for link in soup.find_all("a", href=True):
            absolute = urljoin(job_url, link["href"])
            match = re.fullmatch(rf"{job_path}(\d+)/", urlsplit(absolute).path)
            if match:
                latest = max(latest or 0, int(match.group(1)))
        if latest is not None:
            output["latestBuildNumber"] = latest
        return output

    @staticmethod
    def _parse_build_history_html(
        base_url: str, job_url: str, job_name: str, text: str
    ) -> List[Dict[str, Any]]:
        soup = BeautifulSoup(text, "html.parser")
        job_path = re.escape(urlsplit(job_url).path)
        builds: Dict[int, Dict[str, Any]] = {}
        for link in soup.find_all("a", href=True):
            absolute = pin_to_origin(base_url, urljoin(job_url, link["href"]))
            match = re.fullmatch(rf"{job_path}(\d+)/", urlsplit(absolute).path)
            if not match:
                continue
            number = int(match.group(1))
            item = builds.setdefault(
                number,
                {
                    "number": number,
                    "url": absolute,
                    "source": "job-history-html",
                },
            )
            container = link.find_parent("div", class_="app-builds-container__item")
            if container:
                status = container.find(attrs={"aria-label": True})
                if status and status.get("aria-label"):
                    item["result"] = str(status["aria-label"]).upper()
                time_element = container.find(attrs={"time": True})
                if time_element:
                    item["timestamp"] = time_element.get("time")
                duration = container.find(attrs={"tooltip": re.compile(r"^Took ")})
                if duration:
                    item["duration_text"] = str(duration.get("tooltip"))[len("Took ") :]
        output = []
        for number in sorted(builds, reverse=True):
            builds[number]["job"] = job_name
            output.append(builds[number])
        return output

    @staticmethod
    def _merge_url_items(
        base_url: str,
        primary: Iterable[Dict[str, Any]],
        secondary: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        output: Dict[str, Dict[str, Any]] = {}
        for item in list(primary or []) + list(secondary or []):
            if not isinstance(item, dict) or not item.get("url"):
                continue
            marker = pin_to_origin(base_url, str(item["url"])).rstrip("/") + "/"
            if marker not in output:
                output[marker] = dict(item)
                output[marker]["url"] = marker
            else:
                for key, value in item.items():
                    if output[marker].get(key) is None and value is not None:
                        output[marker][key] = value
        return list(output.values())

    @staticmethod
    def _merge_plugins(
        primary: Iterable[Dict[str, Any]], secondary: Iterable[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        output: Dict[str, Dict[str, Any]] = {}
        for plugin in list(primary or []) + list(secondary or []):
            if not isinstance(plugin, dict):
                continue
            name = plugin.get("shortName") or plugin.get("name")
            if not name:
                continue
            marker = str(name).lower()
            if marker not in output:
                output[marker] = dict(plugin)
                output[marker].setdefault("shortName", name)
                output[marker].setdefault("source", "plugin-manager-api")
            elif not output[marker].get("version") and plugin.get("version"):
                output[marker].update(plugin)
        return sorted(
            output.values(), key=lambda item: str(item.get("shortName") or item.get("name")).lower()
        )

    def _add_vulnerability_findings(self, result: TargetResult) -> None:
        for vulnerability in result.vulnerabilities:
            result.add_finding(
                Finding(
                    id=str(vulnerability.get("id")),
                    title=vulnerability.get("title") or "Jenkins security warning",
                    severity=vulnerability.get("severity") or "unknown",
                    category="vulnerability",
                    status="affected",
                    evidence={
                        "product": vulnerability.get("product"),
                        "installed_version": vulnerability.get("installed_version"),
                        "fixed_versions": vulnerability.get("fixed_versions"),
                    },
                    url=result.target,
                    cves=vulnerability.get("cves", []),
                    advisory=vulnerability.get("advisory"),
                    source="Jenkins Update Center",
                )
            )

    @staticmethod
    def _extract_credentials(payload: Any) -> List[Dict[str, Any]]:
        output = []

        def walk(value: Any):
            if isinstance(value, dict):
                if "id" in value and any(key in value for key in ("displayName", "description", "typeName")):
                    output.append(value)
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(payload)
        return JenkinsScanner._dedupe_dicts(output, ("id", "displayName", "description"))

    @staticmethod
    def _find_users(payload: Any) -> List[Dict[str, Any]]:
        output = []

        def walk(value: Any):
            if isinstance(value, dict):
                user_id = value.get("userId")
                if not user_id and value.get("_class", "").endswith("User"):
                    user_id = value.get("id")
                full_name = value.get("userName") or value.get("fullName")
                absolute_url = value.get("absoluteUrl")
                if user_id or (full_name and absolute_url):
                    output.append({"id": user_id, "fullName": full_name, "absoluteUrl": absolute_url})
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(payload)
        return JenkinsScanner._dedupe_dicts(output, ("id", "fullName", "absoluteUrl"))

    @staticmethod
    def _dedupe_dicts(values: Iterable[Dict[str, Any]], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for value in values:
            marker = tuple(value.get(key) for key in keys)
            if marker not in seen:
                seen.add(marker)
                output.append(value)
        return output

    @staticmethod
    def _looks_like_login(text: str) -> bool:
        sample = text[:100000]
        return bool(
            re.search(r"Sign in \[Jenkins\]|action=[\"'][^\"']*j_acegi_security_check", sample, re.I)
        )
