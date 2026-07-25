"""Data models for dep-scanner findings."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Vulnerability:
    id: str
    cve: str
    aliases: List[str]
    summary: str
    details: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    fixed_versions: List[str]
    published: str

    @classmethod
    def _from_dict(cls, d: Dict[str, Any]) -> "Vulnerability":
        return cls(
            id=d.get("id", ""),
            cve=d.get("cve", ""),
            aliases=d.get("aliases", []),
            summary=d.get("summary", ""),
            details=d.get("details", ""),
            severity=d.get("severity", "MEDIUM"),
            fixed_versions=d.get("fixed_versions", []),
            published=d.get("published", ""),
        )


@dataclass
class PackageFinding:
    package: str
    version: str
    ecosystem: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def highest_severity(self) -> Optional[str]:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(v.severity == sev for v in self.vulnerabilities):
                return sev
        return None

    @property
    def fix_versions(self) -> List[str]:
        """Unique fix versions across all vulnerabilities, sorted."""
        seen: set = set()
        result = []
        for v in self.vulnerabilities:
            for fv in v.fixed_versions:
                if fv not in seen:
                    seen.add(fv)
                    result.append(fv)
        return sorted(result)


@dataclass
class ScanResult:
    source: str
    ecosystem: str
    packages_scanned: int
    findings: List[PackageFinding]
    elapsed_ms: int

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def critical(self) -> List[PackageFinding]:
        return [f for f in self.findings if f.highest_severity == "CRITICAL"]

    @property
    def high(self) -> List[PackageFinding]:
        return [f for f in self.findings if f.highest_severity == "HIGH"]

    @property
    def medium(self) -> List[PackageFinding]:
        return [f for f in self.findings if f.highest_severity == "MEDIUM"]

    @property
    def low(self) -> List[PackageFinding]:
        return [f for f in self.findings if f.highest_severity == "LOW"]

    @property
    def highest_severity(self) -> Optional[str]:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if any(f.highest_severity == sev for f in self.findings):
                return sev
        return None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            items = [f for f in self.findings if f.highest_severity == sev]
            if items:
                result[sev] = [
                    {
                        "package": f.package,
                        "version": f.version,
                        "fix": f.fix_versions[0] if f.fix_versions else None,
                        "vulnerabilities": [
                            {"id": v.cve or v.id, "summary": v.summary, "severity": v.severity}
                            for v in f.vulnerabilities
                        ],
                    }
                    for f in items
                ]
        return result
