# dep-scanner

Zero-dependency Python library that scans your dependency manifests for known CVEs using the free [OSV.dev](https://osv.dev) API.

No API key. No signup. No rate limits for normal use.

```
pip install osv-scan
```

---

## Why

- `safety` went paid in 2023
- `osv-scanner` is a Go binary — not embeddable in Python
- `pip-audit` is great but Python-only and pulls in several dependencies

`dep-scanner` fills the gap: a **pure stdlib** Python library that scans six ecosystems and works anywhere Python runs.

---

## Supported manifest files

| File | Ecosystem |
|---|---|
| `requirements.txt` | PyPI |
| `package.json` | npm |
| `package-lock.json` | npm |
| `go.mod` | Go |
| `Cargo.toml` | crates.io |
| `pom.xml` | Maven |

---

## CLI

```bash
# auto-detect manifest in current directory
dep-scan

# scan a specific file
dep-scan requirements.txt

# multiple files
dep-scan requirements.txt package-lock.json

# JSON output (great for CI)
dep-scan --json requirements.txt

# fail CI only on HIGH or above (default: critical)
dep-scan --fail-on high requirements.txt

# quiet mode — only print findings
dep-scan -q requirements.txt
```

### Example output

```
dep-scan  requirements.txt (PyPI) · 42 packages

  CRITICAL  django 3.2.1
             CVE-2023-36053
             Potential ReDoS via cached 'urlsplit' results
             Fix: upgrade to 3.2.20

  HIGH      requests 2.27.0
             CVE-2023-32681
             Unintended leak of proxy-authorization header
             Fix: upgrade to 2.31.0

  1 CRITICAL · 1 HIGH  (2 vulns · 840ms)
```

---

## Python API

```python
import dep_scanner

# scan a file on disk
result = dep_scanner.scan("requirements.txt")

print(result.highest_severity)       # 'CRITICAL'
print(result.packages_scanned)       # 42
print(len(result.findings))          # 3

for finding in result.critical:
    print(finding.package, finding.version)
    print("Fix:", finding.fix_versions[0] if finding.fix_versions else "none")

# scan content directly (no file needed)
result = dep_scanner.scan_text(
    "requests==2.27.0\ndjango==3.2.1",
    ecosystem="PyPI",
)

# convert to dict
data = result.to_dict()
# {
#   "CRITICAL": [{"package": "django", "version": "3.2.1", ...}],
#   "HIGH": [{"package": "requests", ...}],
# }
```

### ScanResult properties

| Property | Type | Description |
|---|---|---|
| `source` | `str` | File path or label |
| `ecosystem` | `str` | e.g. `"PyPI"` |
| `packages_scanned` | `int` | Total unique packages checked |
| `findings` | `list[PackageFinding]` | Packages with vulnerabilities |
| `elapsed_ms` | `int` | Wall time in milliseconds |
| `highest_severity` | `str \| None` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"` |
| `critical` | `list[PackageFinding]` | Only CRITICAL findings |
| `high` | `list[PackageFinding]` | Only HIGH findings |
| `has_findings` | `bool` | True if any vulnerabilities found |

---

## GitHub Actions

```yaml
- name: Scan dependencies
  run: |
    pip install dep-scanner
    dep-scan --fail-on high requirements.txt
```

---

## pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/SpiderCob/dep-scanner
    rev: v0.1.0
    hooks:
      - id: dep-scan
```

---

## How it works

1. Parses your manifest file to extract `(name, version, ecosystem)` tuples
2. Sends a single batch POST to `https://api.osv.dev/v1/querybatch`
3. Parses severity from `database_specific.severity` → `cvss_score` → CVSS vector
4. Returns structured findings sorted by severity

Packages with unpinned version ranges (`^1.0`, `>=2.0`) are skipped — OSV requires exact versions.

---

## License

Apache 2.0 — free to use in commercial projects.

Built by [SpiderCob](https://spidercob.com).
