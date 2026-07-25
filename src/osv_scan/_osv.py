"""OSV.dev API client for dep-scanner.

Uses the batch query endpoint to check multiple packages in one request.
No API key required — OSV.dev is free and open.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 100          # OSV hard limit is 1000; we use 100 for safety
TIMEOUT = 30              # seconds


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _parse_severity(vuln: Dict[str, Any]) -> str:
    # 1. database_specific.severity (GitHub Advisory style — most reliable)
    db = vuln.get("database_specific") or {}
    raw = str(db.get("severity", "")).lower()
    if raw in _SEV_MAP:
        return _SEV_MAP[raw]

    # 2. database_specific.cvss_score (numeric)
    score = db.get("cvss_score")
    if score is not None:
        return _score_to_sev(float(score))

    # 3. severity array (CVSS vector or numeric string)
    for entry in vuln.get("severity") or []:
        raw_score = entry.get("score", "")
        try:
            return _score_to_sev(float(raw_score))
        except (ValueError, TypeError):
            pass

    return "MEDIUM"     # conservative default


def _score_to_sev(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_fixed_versions(vuln: Dict[str, Any]) -> List[str]:
    fixed: set = set()
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "ECOSYSTEM":
                for event in rng.get("events") or []:
                    if "fixed" in event:
                        fixed.add(event["fixed"])
    return sorted(fixed)


def _get_cve(vuln: Dict[str, Any]) -> str:
    for alias in vuln.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return ""


def _parse_vuln(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": raw.get("id", ""),
        "cve": _get_cve(raw),
        "aliases": raw.get("aliases") or [],
        "summary": raw.get("summary", ""),
        "details": (raw.get("details") or "")[:500],
        "severity": _parse_severity(raw),
        "fixed_versions": _extract_fixed_versions(raw),
        "published": (raw.get("published") or "")[:10],
    }


# ---------------------------------------------------------------------------
# Batch query
# ---------------------------------------------------------------------------

def query_batch(packages: List[Dict[str, str]]) -> List[List[Dict[str, Any]]]:
    """
    Query OSV.dev for vulnerabilities in a list of packages.

    Parameters
    ----------
    packages:
        [{"name": "requests", "version": "2.27.0", "ecosystem": "PyPI"}, ...]

    Returns
    -------
    Parallel list of vulnerability lists — one entry per input package.
    Empty list means no known vulnerabilities for that package.
    """
    if not packages:
        return []

    all_results: List[List[Dict[str, Any]]] = []

    for i in range(0, len(packages), BATCH_SIZE):
        batch = packages[i : i + BATCH_SIZE]
        payload = {
            "queries": [
                {
                    "version": p["version"],
                    "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                }
                for p in batch
            ]
        }
        req = Request(
            OSV_BATCH_URL,
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "osv-scan/0.1.0 (https://github.com/SpiderCob/osv-scan)",
            },
        )
        try:
            with urlopen(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
        except HTTPError as exc:
            raise RuntimeError(f"OSV.dev API returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RuntimeError(f"OSV.dev API unreachable: {exc.reason}") from exc

        for result in data.get("results") or []:
            raw_vulns = result.get("vulns") or []
            all_results.append([_parse_vuln(v) for v in raw_vulns])

    return all_results
