"""OSV.dev API client for osv-scan.

Uses the batch query endpoint to discover vuln IDs, then fetches full
details from the individual /vulns/{id} endpoint (OSV changed the batch
response to return minimal data only).
No API key required — OSV.dev is free and open.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{id}"
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
            # "fixed" events carry the same meaning across all range types
            # (SEMVER, ECOSYSTEM, GIT) — OSV uses SEMVER for npm/Go/crates.io
            # and ECOSYSTEM for PyPI/Maven, so we can't filter to one type.
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
# Individual vuln fetch
# ---------------------------------------------------------------------------

def _fetch_vuln(vuln_id: str) -> Dict[str, Any]:
    """Fetch full vulnerability details from OSV /vulns/{id}."""
    url = OSV_VULN_URL.format(id=vuln_id)
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "osv-scan/0.1.2 (https://github.com/SpiderCob/osv-scan)",
        },
    )
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except (HTTPError, URLError):
        return {"id": vuln_id}   # fall back to minimal data on error


def _fetch_vulns(vuln_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch full details for a list of vuln IDs, deduplicating first."""
    unique_ids: List[str] = list(dict.fromkeys(vuln_ids))
    return {vid: _fetch_vuln(vid) for vid in unique_ids}


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

    # Step 1: batch query to get vuln IDs per package
    pkg_vuln_ids: List[List[str]] = []

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
                "User-Agent": "osv-scan/0.1.2 (https://github.com/SpiderCob/osv-scan)",
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
            ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
            pkg_vuln_ids.append(ids)

    # Step 2: fetch full details for all unique vuln IDs
    all_ids = [vid for ids in pkg_vuln_ids for vid in ids]
    full_vulns = _fetch_vulns(all_ids) if all_ids else {}

    # Step 3: reassemble parallel list matching input packages
    return [
        [_parse_vuln(full_vulns[vid]) for vid in ids if vid in full_vulns]
        for ids in pkg_vuln_ids
    ]
