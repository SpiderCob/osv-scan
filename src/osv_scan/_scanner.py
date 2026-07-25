"""Core scanner logic for osv-scan."""
from __future__ import annotations

import time
from typing import Dict, List

from ._models import PackageFinding, ScanResult, Vulnerability
from ._osv import query_batch
from ._parsers import ECOSYSTEM_MAP, PARSERS, detect_manifest, parse_manifest

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}


def _build_result(
    raw_packages: list,
    ecosystem: str,
    source: str,
    start: float,
) -> ScanResult:
    # Deduplicate by (name, version, ecosystem)
    seen: set = set()
    unique: List[Dict[str, str]] = []
    for name, version, eco in raw_packages:
        key = (name, version, eco)
        if key not in seen:
            seen.add(key)
            unique.append({"name": name, "version": version, "ecosystem": eco})

    if not unique:
        return ScanResult(
            source=source,
            ecosystem=ecosystem,
            packages_scanned=0,
            findings=[],
            elapsed_ms=int((time.time() - start) * 1000),
        )

    osv_results = query_batch(unique)

    findings: List[PackageFinding] = []
    for pkg, vulns in zip(unique, osv_results):
        if not vulns:
            continue
        findings.append(
            PackageFinding(
                package=pkg["name"],
                version=pkg["version"],
                ecosystem=pkg["ecosystem"],
                vulnerabilities=[Vulnerability._from_dict(v) for v in vulns],
            )
        )

    findings.sort(key=lambda f: _SEV_ORDER.get(f.highest_severity, 4))

    return ScanResult(
        source=source,
        ecosystem=ecosystem,
        packages_scanned=len(unique),
        findings=findings,
        elapsed_ms=int((time.time() - start) * 1000),
    )


def scan(path: str) -> ScanResult:
    """
    Scan a dependency manifest file for known CVEs via OSV.dev.

    Supported files: requirements.txt, package.json, package-lock.json,
    go.mod, Cargo.toml, pom.xml

    Parameters
    ----------
    path:
        Path to the manifest file.

    Returns
    -------
    ScanResult
        Findings grouped by severity with fix versions.

    Examples
    --------
    >>> import osv_scan
    >>> result = osv_scan.scan("requirements.txt")
    >>> result.highest_severity
    'CRITICAL'
    >>> result.critical[0].package
    'requests'
    >>> result.critical[0].fix_versions
    ['2.31.0']
    """
    start = time.time()
    packages, ecosystem = parse_manifest(path)
    return _build_result(packages, ecosystem, path, start)


def scan_text(content: str, ecosystem: str, source: str = "<text>") -> ScanResult:
    """
    Scan dependency file content directly (no file needed).

    Parameters
    ----------
    content:
        Raw manifest content as a string.
    ecosystem:
        One of: "PyPI", "npm", "Go", "crates.io", "Maven"
    source:
        Label shown in results (default: "<text>").

    Examples
    --------
    >>> result = osv_scan.scan_text(
    ...     "requests==2.27.0\\ndjango==3.2.1",
    ...     ecosystem="PyPI",
    ... )
    """
    start = time.time()

    eco_to_type = {v: k for k, v in ECOSYSTEM_MAP.items()}
    manifest_type = eco_to_type.get(ecosystem)
    if not manifest_type:
        raise ValueError(
            f"Unknown ecosystem: {ecosystem!r}. "
            f"Valid options: {sorted(ECOSYSTEM_MAP.values())}"
        )

    packages = PARSERS[manifest_type](content)
    return _build_result(packages, ecosystem, source, start)
