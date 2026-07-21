import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class OutputWriter:
    CSV_FIELDS = [
        "target",
        "kind",
        "id",
        "severity",
        "status",
        "title",
        "product",
        "installed_version",
        "cves",
        "advisory",
        "url",
        "auth_context",
    ]

    def __init__(self, output_path: Optional[str] = None):
        self.output_path = Path(output_path) if output_path else None

    def write(self, results: List[Dict[str, Any]]) -> None:
        if not self.output_path:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        extension = self.output_path.suffix.lower()
        if extension == ".json":
            self.output_path.write_text(
                json.dumps(results, ensure_ascii=True, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
        elif extension == ".csv":
            self._write_csv(results)
        else:
            self._write_text(results)

    def _write_csv(self, results: Iterable[Dict[str, Any]]) -> None:
        with self.output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for result in results:
                target = result.get("target")
                for finding in result.get("findings", []):
                    evidence = finding.get("evidence") or {}
                    writer.writerow(
                        {
                            "target": target,
                            "kind": "finding",
                            "id": finding.get("id"),
                            "severity": finding.get("severity"),
                            "status": finding.get("status"),
                            "title": finding.get("title"),
                            "product": evidence.get("product"),
                            "installed_version": evidence.get("installed_version"),
                            "cves": ",".join(finding.get("cves", [])),
                            "advisory": finding.get("advisory"),
                            "url": finding.get("url"),
                            "auth_context": finding.get("auth_context"),
                        }
                    )
                if not result.get("findings"):
                    writer.writerow({"target": target, "kind": "target", "status": "complete"})

    def _write_text(self, results: Iterable[Dict[str, Any]]) -> None:
        lines = []
        for result in results:
            lines.append(f"Target: {result.get('target')}")
            lines.append(f"Version: {result.get('fingerprint', {}).get('version', 'unknown')}")
            lines.append(
                "Inventory: "
                f"{len(result.get('inventory', {}).get('jobs', []))} jobs, "
                f"{len(result.get('inventory', {}).get('builds', []))} builds, "
                f"{len(result.get('inventory', {}).get('plugins', []))} plugins"
            )
            for finding in result.get("findings", []):
                cves = f" ({', '.join(finding.get('cves', []))})" if finding.get("cves") else ""
                lines.append(
                    f"[{str(finding.get('severity', 'info')).upper()}] "
                    f"{finding.get('id')}: {finding.get('title')}{cves}"
                )
            lines.append("")
        self.output_path.write_text("\n".join(lines), encoding="utf-8")
