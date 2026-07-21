from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    status: str = "confirmed"
    evidence: Dict[str, Any] = field(default_factory=dict)
    url: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    advisory: Optional[str] = None
    remediation: Optional[str] = None
    source: str = "jenknums"
    auth_context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetResult:
    target: str
    started_at: str = field(default_factory=utc_now)
    completed_at: Optional[str] = None
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    services: Dict[str, Any] = field(default_factory=dict)
    inventory: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    collection_dir: Optional[str] = None

    def add_error(self, stage: str, error: Exception, url: Optional[str] = None) -> None:
        self.errors.append({"stage": stage, "error": str(error), "url": url})

    def add_finding(self, finding: Finding) -> None:
        key = (finding.id, finding.url, finding.auth_context)
        existing = {(item.id, item.url, item.auth_context) for item in self.findings}
        if key not in existing:
            self.findings.append(finding)

    def finish(self) -> None:
        self.completed_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data
