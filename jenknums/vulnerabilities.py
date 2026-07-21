import gzip
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import httpx
import yaml
from defusedxml import ElementTree

from .utils import get_cache_dir


UPDATE_CENTER_URL = "https://updates.jenkins.io/current/update-center.actual.json"
ADVISORY_RSS_URL = "https://www.jenkins.io/security/advisories/rss.xml"
ADVISORY_RAW_URL = "https://raw.githubusercontent.com/jenkins-infra/jenkins.io/master/content/security/advisory/{date}.adoc"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}
CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def _read_json(path: Path) -> Dict[str, Any]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def _severity_max(values: Iterable[str]) -> str:
    normalized = [str(value or "unknown").lower() for value in values]
    return max(normalized or ["unknown"], key=lambda item: SEVERITY_ORDER.get(item, -1))


def _advisory_path(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.path.rstrip("/") + "/"


class VulnerabilityDB:
    def __init__(self, cache_dir: Optional[Path] = None):
        self.package_dir = Path(__file__).parent / "data"
        self.cache_dir = cache_dir or get_cache_dir() / "vuln-db"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cache_dir, 0o700)
        self.update_center: Dict[str, Any] = {}
        self.advisories: Dict[str, Any] = {}
        self._issues_by_advisory: Dict[str, List[Dict[str, Any]]] = {}

    @property
    def cache_path(self) -> Path:
        return self.cache_dir / "update-center.json"

    @property
    def extra_advisories_path(self) -> Path:
        return self.cache_dir / "advisories-extra.json"

    async def ensure_fresh(self, offline: bool = False, force: bool = False) -> bool:
        self.load()
        if offline:
            return False
        fresh = False
        if self.cache_path.exists() and not force:
            modified = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=timezone.utc)
            fresh = datetime.now(timezone.utc) - modified < timedelta(hours=24)
        if not fresh:
            try:
                async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                    response = await client.get(UPDATE_CENTER_URL)
                    response.raise_for_status()
                    payload = response.json()
                temporary = self.cache_path.with_suffix(".tmp")
                temporary.write_text(json.dumps(payload, ensure_ascii=True), encoding="utf-8")
                temporary.replace(self.cache_path)
                os.chmod(self.cache_path, 0o600)
            except (httpx.HTTPError, OSError, ValueError, json.JSONDecodeError):
                pass
        await self._refresh_advisories(force=force)
        self.load()
        return self.cache_path.exists()

    async def _refresh_advisories(self, force: bool = False) -> None:
        if self.extra_advisories_path.exists() and not force:
            modified = datetime.fromtimestamp(
                self.extra_advisories_path.stat().st_mtime, tz=timezone.utc
            )
            if datetime.now(timezone.utc) - modified < timedelta(hours=24):
                return

        known_dates = {item.get("date") for item in self.advisories.get("advisories", [])}
        extra = {"advisories": [], "issues": []}
        if self.extra_advisories_path.exists():
            try:
                extra = _read_json(self.extra_advisories_path)
            except (OSError, ValueError, json.JSONDecodeError):
                extra = {"advisories": [], "issues": []}
        known_dates.update(item.get("date") for item in extra.get("advisories", []))

        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                rss = await client.get(ADVISORY_RSS_URL)
                rss.raise_for_status()
                root = ElementTree.fromstring(rss.content)
                dates = []
                for item in root.findall("./channel/item"):
                    link = item.findtext("link") or ""
                    match = re.search(r"/security/advisory/(\d{4}-\d{2}-\d{2})/", link)
                    if match and match.group(1) not in known_dates:
                        dates.append(match.group(1))
                for date in sorted(set(dates)):
                    response = await client.get(ADVISORY_RAW_URL.format(date=date))
                    if response.status_code != 200:
                        continue
                    parsed = self._parse_advisory_source(date, response.text)
                    extra["advisories"].append(parsed["advisory"])
                    extra["issues"].extend(parsed["issues"])
                    known_dates.add(date)
        except (httpx.HTTPError, ElementTree.ParseError, OSError, ValueError, yaml.YAMLError):
            return

        extra["generated_at"] = datetime.now(timezone.utc).isoformat()
        temporary = self.extra_advisories_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(extra, ensure_ascii=True), encoding="utf-8")
        temporary.replace(self.extra_advisories_path)
        os.chmod(self.extra_advisories_path, 0o600)

    @staticmethod
    def _parse_advisory_source(date: str, text: str) -> Dict[str, Any]:
        content = text[4:] if text.startswith("---\n") else text
        metadata: Dict[str, Any] = {}
        try:
            loaded = yaml.safe_load(content)
            if isinstance(loaded, dict):
                metadata = loaded
        except yaml.YAMLError:
            if text.startswith("---\n"):
                closing = text.find("\n---\n", 4)
                if closing != -1:
                    loaded = yaml.safe_load(text[4:closing])
                    metadata = loaded if isinstance(loaded, dict) else {}

        advisory_url = f"https://www.jenkins.io/security/advisory/{date}/"
        issues = []
        for issue in metadata.get("issues", []) or []:
            products = [
                {
                    "name": plugin.get("name"),
                    "previous": plugin.get("previous"),
                    "fixed": plugin.get("fixed"),
                }
                for plugin in issue.get("plugins", []) or []
            ]
            if not products and (metadata.get("core") or "core" in str(metadata.get("kind", ""))):
                core = metadata.get("core") or {}
                if isinstance(core, dict) and ("lts" in core or "weekly" in core):
                    previous = {
                        key: value.get("previous")
                        for key, value in core.items()
                        if isinstance(value, dict)
                    }
                    fixed = {
                        key: value.get("fixed")
                        for key, value in core.items()
                        if isinstance(value, dict)
                    }
                else:
                    previous = core.get("previous") if isinstance(core, dict) else None
                    fixed = core.get("fixed") if isinstance(core, dict) else None
                products.append({"name": "core", "previous": previous, "fixed": fixed})
            issues.append(
                {
                    "id": str(issue.get("id", "")),
                    "title": issue.get("title"),
                    "cves": sorted(set(CVE_RE.findall(str(issue.get("cve", ""))))),
                    "severity": (issue.get("cvss") or {}).get("severity", "unknown"),
                    "cvss_vector": (issue.get("cvss") or {}).get("vector"),
                    "advisory": advisory_url,
                    "date": date,
                    "products": products,
                    "fix": None,
                    "workaround": None,
                    "description": issue.get("description") or "",
                }
            )
        return {
            "advisory": {
                "date": date,
                "title": metadata.get("title"),
                "kind": metadata.get("kind"),
                "url": advisory_url,
                "structured": bool(metadata.get("issues")),
            },
            "issues": issues,
        }

    def load(self) -> None:
        bundled_update = self.package_dir / "update-center.json.gz"
        bundled_advisories = self.package_dir / "advisories.json.gz"
        if self.cache_path.exists():
            try:
                self.update_center = _read_json(self.cache_path)
            except (OSError, ValueError, json.JSONDecodeError):
                self.update_center = _read_json(bundled_update) if bundled_update.exists() else {}
        elif bundled_update.exists():
            self.update_center = _read_json(bundled_update)
        if bundled_advisories.exists():
            self.advisories = _read_json(bundled_advisories)
        if self.extra_advisories_path.exists():
            try:
                extra = _read_json(self.extra_advisories_path)
                self.advisories.setdefault("advisories", []).extend(extra.get("advisories", []))
                self.advisories.setdefault("issues", []).extend(extra.get("issues", []))
                self.advisories["advisory_count"] = len(self.advisories.get("advisories", []))
                self.advisories["issue_count"] = len(self.advisories.get("issues", []))
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        self._issues_by_advisory = {}
        for issue in self.advisories.get("issues", []):
            path = _advisory_path(issue.get("advisory", ""))
            self._issues_by_advisory.setdefault(path, []).append(issue)

    def stats(self) -> Dict[str, Any]:
        warnings = self.update_center.get("warnings", [])
        return {
            "generation_timestamp": self.update_center.get("generationTimestamp"),
            "current_core": self.update_center.get("core", {}).get("version"),
            "warnings": len(warnings),
            "core_warnings": sum(1 for item in warnings if item.get("type") == "core"),
            "plugin_warnings": sum(1 for item in warnings if item.get("type") == "plugin"),
            "plugins": len(self.update_center.get("plugins", {})),
            "advisories": self.advisories.get("advisory_count", 0),
            "issues": len(self.advisories.get("issues", [])),
        }

    @staticmethod
    def version_matches(version: str, warning: Dict[str, Any]) -> bool:
        for affected in warning.get("versions", []):
            pattern = affected.get("pattern")
            if not pattern:
                continue
            try:
                if re.fullmatch(pattern, version):
                    return True
            except re.error:
                continue
        return False

    def _issue_matches(self, issue: Dict[str, Any], warning: Dict[str, Any], product: str) -> bool:
        warning_id = str(warning.get("id", ""))
        issue_id = str(issue.get("id", ""))
        base_id_match = warning_id == issue_id or warning_id.startswith(issue_id + "-")
        products = {item.get("name") for item in issue.get("products", [])}
        return base_id_match and (not products or product in products)

    def enrich(self, warning: Dict[str, Any], product: str) -> Dict[str, Any]:
        path = _advisory_path(warning.get("url", ""))
        candidates = self._issues_by_advisory.get(path, [])
        matched = [item for item in candidates if self._issue_matches(item, warning, product)]
        if not matched and product == "core":
            matched = [item for item in candidates if any(p.get("name") == "core" for p in item.get("products", []))]
        if not matched and len(candidates) == 1:
            matched = candidates
        cves = sorted({cve for item in matched for cve in item.get("cves", [])})
        fixed = []
        for item in matched:
            for item_product in item.get("products", []):
                if item_product.get("name") == product and item_product.get("fixed"):
                    fixed.append(item_product["fixed"])
        fixed_unique = []
        fixed_seen = set()
        for value in fixed:
            marker = json.dumps(value, sort_keys=True, default=str)
            if marker not in fixed_seen:
                fixed_seen.add(marker)
                fixed_unique.append(value)
        return {
            "cves": cves,
            "severity": _severity_max(item.get("severity", "unknown") for item in matched),
            "issues": [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "cves": item.get("cves", []),
                    "severity": item.get("severity"),
                    "cvss_vector": item.get("cvss_vector"),
                    "fixed": [p.get("fixed") for p in item.get("products", []) if p.get("name") == product and p.get("fixed")],
                    "workaround": item.get("workaround"),
                }
                for item in matched
            ],
            "fixed_versions": fixed_unique,
        }

    def correlate(self, core_version: Optional[str], plugins: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.update_center:
            self.load()
        products: Dict[str, str] = {}
        if core_version:
            products["core"] = core_version
        for plugin in plugins:
            name = plugin.get("shortName") or plugin.get("name")
            version = plugin.get("version")
            if name and version:
                products[str(name)] = str(version)

        findings = []
        for warning in self.update_center.get("warnings", []):
            name = warning.get("name")
            version = products.get(name)
            if not version or not self.version_matches(version, warning):
                continue
            enriched = self.enrich(warning, name)
            findings.append(
                {
                    "id": warning.get("id"),
                    "product": name,
                    "product_type": warning.get("type"),
                    "installed_version": version,
                    "status": "affected",
                    "confidence": "official-version-match",
                    "title": warning.get("message"),
                    "severity": enriched["severity"],
                    "cves": enriched["cves"],
                    "advisory": warning.get("url"),
                    "affected_ranges": warning.get("versions", []),
                    "fixed_versions": enriched["fixed_versions"],
                    "issues": enriched["issues"],
                }
            )
        findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item.get("severity", "unknown"), -1), item.get("product", ""), item.get("id", "")))
        return findings

    def plugin_health(self, plugins: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        catalog = self.update_center.get("plugins", {})
        deprecations = self.update_center.get("deprecations", {})
        output = []
        for plugin in plugins:
            name = plugin.get("shortName") or plugin.get("name")
            version = plugin.get("version")
            if not name:
                continue
            current = catalog.get(name, {})
            output.append(
                {
                    "name": name,
                    "installed_version": version,
                    "latest_version": current.get("version"),
                    "has_update": bool(current.get("version") and version != current.get("version")),
                    "required_core": current.get("requiredCore"),
                    "deprecated": name in deprecations,
                    "deprecation_url": deprecations.get(name, {}).get("url") if name in deprecations else None,
                    "active": plugin.get("active"),
                    "enabled": plugin.get("enabled"),
                }
            )
        return output
