"""CLI entry point for osv-scan: dep-scan"""
from __future__ import annotations

import argparse
import json
import os
import sys

from ._parsers import detect_manifest
from ._scanner import scan

# ANSI colours (disabled when not a TTY)
_TTY = sys.stdout.isatty()
_C = {
    "CRITICAL": "\033[91m\033[1m",
    "HIGH":     "\033[93m\033[1m",
    "MEDIUM":   "\033[94m\033[1m",
    "LOW":      "\033[37m",
    "GREEN":    "\033[92m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def _c(text: str, key: str) -> str:
    if not _TTY:
        return text
    return f"{_C.get(key, '')}{text}{_C['RESET']}"


def _print_result(result, use_json: bool, quiet: bool) -> None:
    if use_json:
        out = {
            "source": result.source,
            "ecosystem": result.ecosystem,
            "packages_scanned": result.packages_scanned,
            "highest_severity": result.highest_severity,
            "elapsed_ms": result.elapsed_ms,
            "findings": [
                {
                    "package": f.package,
                    "version": f.version,
                    "severity": f.highest_severity,
                    "fix": f.fix_versions[0] if f.fix_versions else None,
                    "vulnerabilities": [
                        {
                            "id": v.cve or v.id,
                            "summary": v.summary,
                            "severity": v.severity,
                            "fixed_versions": v.fixed_versions,
                        }
                        for v in f.vulnerabilities
                    ],
                }
                for f in result.findings
            ],
        }
        print(json.dumps(out, indent=2))
        return

    if not quiet:
        print(
            f"\n{_c('dep-scan', 'BOLD')}  {result.source} "
            f"{_c(f'({result.ecosystem})', 'DIM')} "
            f"· {result.packages_scanned} packages\n"
        )

    if not result.has_findings:
        if not quiet:
            print(f"  {_c('✓ No vulnerabilities found', 'GREEN')}\n")
        return

    for finding in result.findings:
        sev = finding.highest_severity or "MEDIUM"
        print(f"  {_c(sev.ljust(9), sev)} {_c(finding.package, 'BOLD')} {finding.version}")

        for vuln in finding.vulnerabilities:
            vid = vuln.cve or vuln.id
            print(f"             {_c(vid, 'DIM')}")
            if vuln.summary:
                summary = vuln.summary[:90] + ("…" if len(vuln.summary) > 90 else "")
                print(f"             {summary}")

        if finding.fix_versions:
            print(f"             {_c('Fix: upgrade to ' + finding.fix_versions[0], 'BOLD')}")
        print()

    # Summary line
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = len([f for f in result.findings if f.highest_severity == sev])
        if count:
            parts.append(_c(f"{count} {sev}", sev))

    total = sum(len(f.vulnerabilities) for f in result.findings)
    plural = "s" if total != 1 else ""
    print(
        f"  {' · '.join(parts)}"
        f"  {_c(f'({total} vuln{plural} · {result.elapsed_ms}ms)', 'DIM')}\n"
    )


_FAIL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 99}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_AUTO_DETECT = [
    "requirements.txt", "package-lock.json", "package.json",
    "go.mod", "Cargo.toml", "pom.xml",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dep-scan",
        description=(
            "Scan dependency manifests for known CVEs using OSV.dev.\n"
            "Supports: requirements.txt, package.json, package-lock.json, "
            "go.mod, Cargo.toml, pom.xml"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="FILE",
        help="Manifest files to scan (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=list(_FAIL_ORDER),
        metavar="SEVERITY",
        help="Exit 1 if findings at this level or above (default: critical)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress informational output, print only findings",
    )
    args = parser.parse_args()

    paths = args.paths or [p for p in _AUTO_DETECT if os.path.exists(p)]
    if not paths:
        print("No manifest files found. Pass a file or run from a project directory.", file=sys.stderr)
        sys.exit(0)

    threshold = _FAIL_ORDER[args.fail_on]
    exit_code = 0

    for path in paths:
        if not os.path.exists(path):
            print(f"File not found: {path}", file=sys.stderr)
            continue
        if detect_manifest(path) is None:
            print(f"Unrecognised manifest: {path}", file=sys.stderr)
            continue
        try:
            result = scan(path)
        except Exception as exc:
            print(f"Error scanning {path}: {exc}", file=sys.stderr)
            continue

        _print_result(result, use_json=args.json, quiet=args.quiet)

        if result.highest_severity:
            if _SEV_RANK.get(result.highest_severity, 99) <= threshold:
                exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
