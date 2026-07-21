import argparse
import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.markup import escape

from . import __version__
from .client import AuthConfig
from .output import OutputWriter
from .scanner import JenkinsScanner, ScanSettings
from .utils import read_secret
from .vulnerabilities import SEVERITY_ORDER, VulnerabilityDB


console = Console()
_silent = False


def cprint(*args, **kwargs):
    if not _silent:
        console.print(*args, **kwargs)


def banner() -> str:
    return rf"""[bold cyan]
  ▐     ▌
  ▜▘▛▌▛▌▌▌▛▛▌▛▘
▙▖▐▖▌▌▙▌▙▌▌▌▌▄▌ [/bold cyan][dim]v{__version__}[/dim]
[white][dim]pajarori[/dim][/white]
"""


def severity_tag(severity: str) -> str:
    mapping = {
        "critical": "[bold red]\\[crt][/]",
        "high": "[red]\\[hig][/]",
        "medium": "[yellow]\\[med][/]",
        "low": "[blue]\\[low][/]",
        "info": "[cyan]\\[inf][/]",
        "unknown": "[dim]\\[unk][/]",
    }
    return mapping.get(str(severity).lower(), "[dim]\\[unk][/]")


def _text(value: Any, default: str = "unknown") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _state_badge(value: Any) -> str:
    state = _text(value).upper().split("_", 1)[0]
    state = {
        "BLUE": "SUCCESS",
        "RED": "FAILURE",
        "YELLOW": "UNSTABLE",
    }.get(state, state)
    color = {
        "SUCCESS": "green",
        "FAILURE": "red",
        "UNSTABLE": "yellow",
        "ABORTED": "magenta",
        "DISABLED": "dim",
        "NOTBUILT": "dim",
    }.get(state, "white")
    return f"[{color}]{escape(state.lower())}[/]"


def _render_items(
    title: str,
    items: List[Any],
    display_limit: int,
    formatter,
    marker: str = "+",
    color: str = "cyan",
) -> None:
    cprint(f"\n[bold {color}][{marker}][/] [bold]{title.lower()}[/] [dim]({len(items)})[/]")
    shown = items[:display_limit]
    remaining = len(items) - len(shown)
    for item in shown:
        cprint(f"    {formatter(item)}")
    if remaining:
        cprint(f"    [dim]... +{remaining} more in raw output[/]")


def _render_compact(result: Dict[str, Any], display_limit: int) -> None:
    target = result.get("target")
    version = result.get("fingerprint", {}).get("version", "unknown")
    errors = len(result.get("errors", []))
    inventory = result.get("inventory", {})
    cprint(
        f"[bold cyan]{target}[/] [dim]v{version}[/] "
        f"[white]{len(inventory.get('jobs', []))} jobs[/] "
        f"[white]{len(inventory.get('builds', []))} builds[/] "
        f"[white]{len(inventory.get('plugins', []))} plugins[/] "
        f"[yellow]{errors} errors[/]"
    )
    findings = sorted(
        result.get("findings", []),
        key=lambda item: -SEVERITY_ORDER.get(str(item.get("severity", "unknown")).lower(), -1),
    )
    for finding in findings[:display_limit]:
        cves = f" [dim]{','.join(finding.get('cves', []))}[/]" if finding.get("cves") else ""
        cprint(
            f"  {severity_tag(finding.get('severity', 'unknown'))} "
            f"[bold]{finding.get('id')}[/] {finding.get('title')}{cves}"
        )
    if len(findings) > display_limit:
        cprint(f"  [dim]... +{len(findings) - display_limit} more findings[/]")


def render_result(
    result: Dict[str, Any], detailed: bool = True, display_limit: int = 10
) -> None:
    display_limit = max(0, display_limit)
    if not detailed:
        _render_compact(result, display_limit)
        return

    target = escape(_text(result.get("target")))
    fingerprint = result.get("fingerprint", {})
    inventory = result.get("inventory", {})
    coverage = result.get("coverage", {})
    auth = result.get("auth", {})

    counts = []
    for key in ("views", "jobs", "builds", "plugins", "nodes", "users"):
        count = len(inventory.get(key, []))
        if count:
            counts.append(f"{count} {key}")
    cprint(f"[bold cyan][+][/] url: [bold cyan]{target}[/]")
    cprint(f"[bold cyan][+][/] jenkins: {escape(_text(fingerprint.get('version')))}")
    cprint(
        f"[bold cyan][+][/] scan: {escape(_text(auth.get('configured_mode'), 'anonymous'))}"
        + (f" | {' | '.join(counts)}" if counts else "")
    )

    plugins = inventory.get("plugins", [])
    if plugins:
        _render_items(
            "plugins",
            plugins,
            display_limit,
            lambda item: (
                f"[cyan]{escape(_text(item.get('shortName') or item.get('name')))}[/] "
                + (
                    f"v{escape(_text(item.get('version')))}"
                    if item.get("version")
                    else "[yellow]version unknown[/]"
                )
                + (
                    f" [dim](inferred: {escape(_text(item.get('source')))})[/]"
                    if item.get("inferred")
                    else ""
                )
            ),
        )

    jobs = inventory.get("jobs", [])
    if jobs:
        _render_items(
            "jobs",
            jobs,
            display_limit,
            lambda item: (
                f"[cyan]{escape(_text(item.get('fullName') or item.get('displayName') or item.get('name')))}[/]"
                + (f" | {_state_badge(item.get('color'))}" if item.get("color") else "")
                + (
                    f" | latest #{item.get('latestBuildNumber')}"
                    if item.get("latestBuildNumber") is not None
                    else ""
                )
            ),
        )

    nodes = inventory.get("nodes", [])
    if nodes:
        _render_items(
            "nodes",
            nodes,
            display_limit,
            lambda item: (
                f"[cyan]{escape(_text(item.get('displayName') or item.get('name')))}[/]"
                f" | offline={_text(item.get('offline'))}"
                f" | executors={escape(_text(item.get('numExecutors')))}"
            ),
        )

    users = inventory.get("users", [])
    if users:
        _render_items(
            "users",
            users,
            display_limit,
            lambda item: (
                f"[cyan]{escape(_text(item.get('id') or item.get('fullName')))}[/]"
                + (
                    f" | {escape(_text(item.get('fullName')))}"
                    if item.get("fullName") and item.get("fullName") != item.get("id")
                    else ""
                )
            ),
        )

    credentials = inventory.get("credentials", [])
    if credentials:
        _render_items(
            "credential metadata",
            credentials,
            display_limit,
            lambda item: (
                f"[yellow]{escape(_text(item.get('id') or item.get('displayName')))}[/]"
                + (f" | {escape(_text(item.get('typeName')))}" if item.get("typeName") else "")
            ),
            marker="!",
            color="yellow",
        )

    vulnerabilities = sorted(
        result.get("vulnerabilities", []),
        key=lambda item: -SEVERITY_ORDER.get(str(item.get("severity", "unknown")).lower(), -1),
    )
    if vulnerabilities:
        _render_items(
            "vulnerabilities",
            vulnerabilities,
            display_limit,
            lambda item: (
                f"{severity_tag(item.get('severity', 'unknown'))} "
                f"[bold]{escape(_text(item.get('id')))}[/] "
                f"{escape(_text(item.get('product')).lower())} v{escape(_text(item.get('installed_version')))}"
                + (f" | {escape(','.join(item.get('cves', [])))}" if item.get("cves") else "")
            ),
            marker="!",
            color="red",
        )

    findings = sorted(
        (
            item
            for item in result.get("findings", [])
            if item.get("category") != "vulnerability"
        ),
        key=lambda item: -SEVERITY_ORDER.get(str(item.get("severity", "unknown")).lower(), -1),
    )
    if findings:
        _render_items(
            "findings",
            findings,
            display_limit,
            lambda item: (
                f"{severity_tag(item.get('severity', 'unknown'))} "
                f"[bold]{escape(_text(item.get('id')))}[/] "
                f"{escape(_text(item.get('title')).lower())}"
            ),
            marker="!",
            color="yellow",
        )

    errors = result.get("errors", [])
    cprint(
        f"\n[dim]\\[i] raw: [cyan]{escape(_text(result.get('collection_dir')))}[/] "
        f"({escape(_text(coverage.get('requests'), '0'))} requests)[/]"
    )
    if errors:
        _render_items(
            "errors",
            errors,
            display_limit,
            lambda item: (
                f"{escape(_text(item.get('stage')))}: {escape(_text(item.get('error')))}"
                + (f" | {escape(_text(item.get('url')))}" if item.get("url") else "")
            ),
            marker="!",
            color="red",
        )


class SingleTargetStreamRenderer:
    def __init__(self, display_limit: int = 10):
        self.display_limit = max(0, display_limit)
        self.detected = False
        self.scan_line = False
        self.sections = set()
        self.findings_seen = set()
        self.vulnerabilities_seen = set()
        self.findings_shown = 0
        self.vulnerabilities_shown = 0
        self.findings_open = False
        self.vulnerabilities_open = False
        self.findings_closed = False

    def handle(self, event: Dict[str, Any]) -> None:
        event_type = event.get("event")
        if event_type == "detected":
            self.detected = True
            cprint(
                f"[bold cyan][+][/] url: "
                f"[bold cyan]{escape(_text(event.get('target')))}[/]"
            )
            cprint(f"[bold cyan][+][/] jenkins: {escape(_text(event.get('version')))}")
            return

        if event_type == "inventory":
            self._render_inventory(event)
            return

        if event_type == "findings":
            self._render_findings(event)
            return

        if event_type == "quick_complete":
            self._close_findings()

    def _render_inventory(self, event: Dict[str, Any]) -> None:
        inventory = event.get("inventory") or {}
        stage = event.get("stage")
        jobs = inventory.get("jobs") or inventory.get("root", {}).get("jobs", [])
        views = inventory.get("views", [])
        plugins = inventory.get("plugins", [])
        nodes = inventory.get("nodes", [])
        users = inventory.get("users", [])
        credentials = inventory.get("credentials", [])

        if not self.scan_line:
            counts = []
            for name, values in (
                ("views", views),
                ("jobs", jobs),
                ("plugins", plugins),
                ("nodes", nodes),
                ("users", users),
            ):
                if values:
                    counts.append(f"{len(values)} {name}")
            if counts or stage != "dashboard":
                self.scan_line = True
                cprint(
                    f"[bold cyan][+][/] scan: "
                    f"{escape(_text(event.get('auth_mode'), 'anonymous'))}"
                    + (f" | {' | '.join(counts)}" if counts else "")
                )

        if jobs and "jobs" not in self.sections:
            self.sections.add("jobs")
            _render_items(
                "jobs",
                jobs,
                self.display_limit,
                lambda item: (
                    f"[cyan]{escape(_text(item.get('fullName') or item.get('displayName') or item.get('name')))}[/]"
                    + (f" | {_state_badge(item.get('color'))}" if item.get("color") else "")
                    + (
                        f" | latest #{item.get('latestBuildNumber') or item.get('last_successful_build')}"
                        if item.get("latestBuildNumber") is not None
                        or item.get("last_successful_build") is not None
                        else ""
                    )
                ),
            )

        if stage != "dashboard" and plugins and "plugins" not in self.sections:
            self.sections.add("plugins")
            _render_items(
                "plugins",
                plugins,
                self.display_limit,
                lambda item: (
                    f"[cyan]{escape(_text(item.get('shortName') or item.get('name')))}[/] "
                    + (
                        f"v{escape(_text(item.get('version')))}"
                        if item.get("version")
                        else "[yellow]version unknown[/]"
                    )
                    + (
                        f" [dim](inferred: {escape(_text(item.get('source')))})[/]"
                        if item.get("inferred")
                        else ""
                    )
                ),
            )

        if nodes and "nodes" not in self.sections:
            self.sections.add("nodes")
            _render_items(
                "nodes",
                nodes,
                self.display_limit,
                lambda item: (
                    f"[cyan]{escape(_text(item.get('displayName') or item.get('name')))}[/]"
                    f" | offline={_text(item.get('offline'))}"
                    f" | executors={escape(_text(item.get('numExecutors')))}"
                ),
            )

        if users and "users" not in self.sections:
            self.sections.add("users")
            _render_items(
                "users",
                users,
                self.display_limit,
                lambda item: f"[cyan]{escape(_text(item.get('id') or item.get('fullName')))}[/]",
            )

        if credentials and "credentials" not in self.sections:
            self.sections.add("credentials")
            _render_items(
                "credential metadata",
                credentials,
                self.display_limit,
                lambda item: (
                    f"[yellow]{escape(_text(item.get('id') or item.get('displayName')))}[/]"
                    + (
                        f" | {escape(_text(item.get('typeName')))}"
                        if item.get("typeName")
                        else ""
                    )
                ),
                marker="!",
                color="yellow",
            )

    def _render_findings(self, event: Dict[str, Any]) -> None:
        vulnerabilities = sorted(
            event.get("vulnerabilities", []),
            key=lambda item: -SEVERITY_ORDER.get(
                str(item.get("severity", "unknown")).lower(), -1
            ),
        )
        for item in vulnerabilities:
            marker = item.get("id")
            if marker in self.vulnerabilities_seen:
                continue
            self.vulnerabilities_seen.add(marker)
            if not self.vulnerabilities_open:
                self.vulnerabilities_open = True
                cprint("\n[bold red][!][/] [bold]vulnerabilities[/]")
            if self.vulnerabilities_shown < self.display_limit:
                self.vulnerabilities_shown += 1
                cprint(
                    f"    {severity_tag(item.get('severity', 'unknown'))} "
                    f"[bold]{escape(_text(item.get('id')))}[/] "
                    f"{escape(_text(item.get('product')).lower())} "
                    f"v{escape(_text(item.get('installed_version')))}"
                )
        findings = sorted(
            (
                item
                for item in event.get("findings", [])
                if item.get("category") != "vulnerability"
            ),
            key=lambda item: -SEVERITY_ORDER.get(
                str(item.get("severity", "unknown")).lower(), -1
            ),
        )
        for item in findings:
            marker = (item.get("id"), item.get("url"), item.get("auth_context"))
            if marker in self.findings_seen:
                continue
            self.findings_seen.add(marker)
            if not self.findings_open:
                self.findings_open = True
                cprint("\n[bold yellow][!][/] [bold]findings[/]")
            if self.findings_shown < self.display_limit:
                self.findings_shown += 1
                cprint(
                    f"    {severity_tag(item.get('severity', 'unknown'))} "
                    f"[bold]{escape(_text(item.get('id')))}[/] "
                    f"{escape(_text(item.get('title')).lower())}"
                )

    def _close_findings(self) -> None:
        if self.findings_closed:
            return
        self.findings_closed = True
        if len(self.vulnerabilities_seen) > self.vulnerabilities_shown:
            cprint(
                f"    [dim]... +{len(self.vulnerabilities_seen) - self.vulnerabilities_shown} "
                "more in raw output[/]"
            )
        if len(self.findings_seen) > self.findings_shown:
            cprint(
                f"    [dim]... +{len(self.findings_seen) - self.findings_shown} "
                "more in raw output[/]"
            )

    def finish(self, result: Dict[str, Any]) -> None:
        if not self.detected:
            render_result(result, detailed=True, display_limit=self.display_limit)
            return
        self._render_findings(
            {
                "findings": result.get("findings", []),
                "vulnerabilities": result.get("vulnerabilities", []),
            }
        )
        self._close_findings()
        coverage = result.get("coverage", {})
        cprint(
            f"\n[dim]\\[i] raw: [cyan]{escape(_text(result.get('collection_dir')))}[/] "
            f"({escape(_text(coverage.get('requests'), '0'))} requests)[/]"
        )
        errors = result.get("errors", [])
        if errors:
            _render_items(
                "errors",
                errors,
                self.display_limit,
                lambda item: (
                    f"{escape(_text(item.get('stage')))}: "
                    f"{escape(_text(item.get('error')))}"
                ),
                marker="!",
                color="red",
            )


async def run_scan(
    target: str, scanner: JenkinsScanner, display_limit: int = 10
) -> Dict[str, Any]:
    if _silent:
        return (await scanner.scan(target)).to_dict()
    renderer = SingleTargetStreamRenderer(display_limit=display_limit)
    payload = (await scanner.scan(target, event_handler=renderer.handle)).to_dict()
    renderer.finish(payload)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Jenknums - Comprehensive read-only Jenkins enumerator"
    )
    parser.add_argument("-u", "--url", help="Jenkins URL to scan")
    parser.add_argument("-o", "--output", help="Summary report (.json, .csv, .txt)")
    parser.add_argument("--dump-dir", help="Raw collection directory")
    parser.add_argument("--request-concurrency", type=int, default=6, help="Concurrent requests per target (default: 6)")
    parser.add_argument("-s", "--sleep", type=float, default=0.0, help="Delay after requests in seconds")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--user", help="Jenkins username (or JENKINS_USER_ID)")
    parser.add_argument("--token", help="Jenkins API token")
    parser.add_argument("--token-file", help="File containing Jenkins API token")
    parser.add_argument("--cookie", help="Jenkins Cookie header value")
    parser.add_argument("--cookie-file", help="File containing Jenkins Cookie header value")
    parser.add_argument("--verify", action="store_true", help="Run additional safe, read-only vulnerability probes")
    parser.add_argument("--offline", action="store_true", help="Use bundled/cached vulnerability data only")
    parser.add_argument("--update-db", action="store_true", help="Force update vulnerability data and exit")
    parser.add_argument("--max-builds", type=int, help="Limit builds collected per job (default: all)")
    parser.add_argument(
        "--display-limit",
        type=int,
        default=10,
        help="Maximum entries shown per terminal section (default: 10)",
    )
    parser.add_argument("--no-console", action="store_true", help="Do not collect full console logs")
    parser.add_argument("--no-workspace-index", action="store_true", help="Do not recursively index workspaces")
    parser.add_argument("--no-retry", action="store_true", help="Disable request retry")
    parser.add_argument("--json", action="store_true", help="Write JSON results to stdout")
    return parser


def main() -> None:
    global _silent
    parser = build_parser()
    args = parser.parse_args()
    _silent = args.json

    vuln_db = VulnerabilityDB()
    if args.update_db:
        asyncio.run(vuln_db.ensure_fresh(offline=False, force=True))
        payload = vuln_db.stats()
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            cprint(banner())
            cprint(f"[green]vulnerability database updated.[/] {payload}")
        return

    if not args.url:
        if not _silent:
            cprint(banner())
        parser.error("no target provided; use -u")

    username = args.user or os.getenv("JENKINS_USER_ID")
    token = read_secret(args.token, args.token_file, "JENKINS_API_TOKEN")
    cookie = read_secret(args.cookie, args.cookie_file, "JENKINS_COOKIE")
    if bool(username) != bool(token) and not cookie:
        parser.error("--user and token must be provided together")
    auth = AuthConfig(username=username, token=token, cookie=cookie)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = Path(args.dump_dir or f"jenknums-output/{timestamp}")
    output_root.mkdir(parents=True, exist_ok=True)
    os.chmod(output_root, 0o700)

    if not _silent:
        cprint(banner())

    started = time.monotonic()
    asyncio.run(vuln_db.ensure_fresh(offline=args.offline, force=False))
    settings = ScanSettings(
        verify_tls=not args.insecure,
        verify_vulns=args.verify,
        timeout=args.timeout,
        request_concurrency=args.request_concurrency,
        retries=0 if args.no_retry else 2,
        sleep_time=max(0.0, args.sleep),
        max_builds=args.max_builds,
        collect_console=not args.no_console,
        index_workspace=not args.no_workspace_index,
    )
    scanner = JenkinsScanner(output_root, vuln_db, settings=settings, auth=auth)

    try:
        payload = asyncio.run(
            run_scan(
                args.url, scanner, display_limit=max(0, args.display_limit)
            )
        )
    except KeyboardInterrupt:
        cprint("\n[yellow]interrupted.[/]")
        return

    results = [payload]
    OutputWriter(args.output).write(results)
    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2, default=str))
    else:
        elapsed = time.monotonic() - started
        if args.output:
            cprint(f"[dim]summary report saved to [cyan]{args.output}[/][/]")
        cprint(f"\n[bold green]scan complete[/] [dim]in {elapsed:.2f}s[/]")


if __name__ == "__main__":
    main()
