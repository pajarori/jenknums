#!/usr/bin/env python3
import argparse
import gzip
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml


CVE_RE = re.compile(r"CVE-\d{4}-\d+")


def front_matter(path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    lines = text.splitlines(keepends=True)
    closing = next((index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
    if closing is None:
        try:
            parsed = yaml.safe_load("".join(lines[1:])) or {}
            return (parsed, "") if isinstance(parsed, dict) else ({}, text)
        except yaml.YAMLError:
            return {}, text
    raw = "".join(lines[1:closing])
    body = "".join(lines[closing + 1 :])
    return yaml.safe_load(raw) or {}, body


def section(text, heading):
    pattern = re.compile(rf"\*\*{re.escape(heading)}:\*\*\s*\+?\s*(.*?)(?=\n\s*\*\*[A-Za-z ]+:\*\*|\Z)", re.S)
    match = pattern.search(text or "")
    return " ".join(match.group(1).strip().split()) if match else None


def core_product(core):
    if not core:
        return {"name": "core", "previous": None, "fixed": None}
    previous = core.get("previous") if isinstance(core, dict) else None
    fixed = core.get("fixed") if isinstance(core, dict) else None
    if isinstance(core, dict) and ("lts" in core or "weekly" in core):
        previous = {key: value.get("previous") for key, value in core.items() if isinstance(value, dict)}
        fixed = {key: value.get("fixed") for key, value in core.items() if isinstance(value, dict)}
    return {"name": "core", "previous": previous, "fixed": fixed}


def build(source_dir):
    issues = []
    advisories = []
    for path in sorted(source_dir.glob("*.adoc")):
        metadata, body = front_matter(path)
        advisory_url = f"https://www.jenkins.io/security/advisory/{path.stem}/"
        advisories.append(
            {
                "date": path.stem,
                "title": metadata.get("title"),
                "kind": metadata.get("kind"),
                "url": advisory_url,
                "structured": bool(metadata.get("issues")),
            }
        )
        for issue in metadata.get("issues", []) or []:
            products = []
            for plugin in issue.get("plugins", []) or []:
                products.append(
                    {
                        "name": plugin.get("name"),
                        "previous": plugin.get("previous"),
                        "fixed": plugin.get("fixed"),
                    }
                )
            if not products and (metadata.get("core") or "core" in str(metadata.get("kind", ""))):
                products.append(core_product(metadata.get("core")))
            description = issue.get("description") or ""
            issues.append(
                {
                    "id": str(issue.get("id", "")),
                    "title": issue.get("title"),
                    "cves": sorted(set(CVE_RE.findall(str(issue.get("cve", ""))))),
                    "severity": (issue.get("cvss") or {}).get("severity", "unknown"),
                    "cvss_vector": (issue.get("cvss") or {}).get("vector"),
                    "advisory": advisory_url,
                    "date": path.stem,
                    "products": products,
                    "fix": section(description, "Fix Description"),
                    "workaround": section(description, "Workaround"),
                    "description": description,
                }
            )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisory_count": len(advisories),
        "issue_count": len(issues),
        "advisories": advisories,
        "issues": issues,
    }


def main():
    parser = argparse.ArgumentParser(description="Build the bundled Jenkins advisory database")
    parser.add_argument("source", type=Path, help="jenkins.io content/security/advisory directory")
    parser.add_argument("output", type=Path, help="Output .json.gz file")
    args = parser.parse_args()
    payload = build(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(args.output, "wt", encoding="utf-8", compresslevel=9) as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
    print(json.dumps({key: payload[key] for key in ("advisory_count", "issue_count")}, indent=2))


if __name__ == "__main__":
    main()
