"""osv-scan — zero-dependency CVE scanner for dependency manifests."""
from __future__ import annotations

from ._models import PackageFinding, ScanResult, Vulnerability
from ._scanner import scan, scan_text

__version__ = "0.2.0"
__all__ = [
    "scan",
    "scan_text",
    "ScanResult",
    "PackageFinding",
    "Vulnerability",
    "__version__",
]
