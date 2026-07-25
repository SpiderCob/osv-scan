"""Manifest file parsers for dep-scanner.

Each parser returns List[Tuple[name, version, ecosystem]].
Only pinned / resolved versions are returned — unpinned ranges
cannot be looked up in OSV and are silently skipped.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

# Ecosystem labels used by OSV.dev
ECOSYSTEM_MAP: Dict[str, str] = {
    "requirements": "PyPI",
    "package_json": "npm",
    "package_lock": "npm",
    "go_mod": "Go",
    "cargo_toml": "crates.io",
    "pom_xml": "Maven",
}

Package = Tuple[str, str, str]  # (name, version, ecosystem)


# ---------------------------------------------------------------------------
# Manifest type detection
# ---------------------------------------------------------------------------

def detect_manifest(path: str) -> Optional[str]:
    name = os.path.basename(path).lower()
    if name == "package-lock.json":
        return "package_lock"
    if name == "package.json":
        return "package_json"
    if name == "go.mod":
        return "go_mod"
    if name in ("cargo.toml",):
        return "cargo_toml"
    if name == "pom.xml":
        return "pom_xml"
    # requirements.txt, requirements-dev.txt, requirements/*.txt …
    if "requirements" in name and name.endswith(".txt"):
        return "requirements"
    return None


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

def parse_requirements(content: str) -> List[Package]:
    """Parse requirements.txt — only pinned (==) versions."""
    packages: List[Package] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = line.split("#")[0].split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s,]+)", line)
        if m:
            name = m.group(1).lower().replace("_", "-")
            packages.append((name, m.group(2).strip(), "PyPI"))
    return packages


def parse_package_json(content: str) -> List[Package]:
    """Parse package.json dependencies + devDependencies."""
    try:
        data = json.loads(content)
    except Exception:
        return []

    packages: List[Package] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str):
                continue
            if spec in ("*", "latest", "next", "beta") or re.match(r"^(file:|git[+@]|http)", spec):
                continue
            # Strip leading range operators and take first part
            clean = re.sub(r"^[\^~>=<v]+", "", spec.split("||")[0].strip())
            clean = re.split(r"\s+", clean)[0]
            if re.match(r"^\d+\.\d+", clean):
                packages.append((name, clean, "npm"))
    return packages


def parse_package_lock(content: str) -> List[Package]:
    """Parse package-lock.json (v1, v2, v3)."""
    try:
        data = json.loads(content)
    except Exception:
        return []

    packages: List[Package] = []

    if "packages" in data:
        # v2 / v3
        for path, info in data["packages"].items():
            if not path or not isinstance(info, dict) or info.get("link"):
                continue
            version = info.get("version", "")
            if version and re.match(r"^\d+\.\d+", version):
                name = re.sub(r"^.*node_modules/", "", path)
                packages.append((name, version, "npm"))
    elif "dependencies" in data:
        # v1
        def _walk(deps: dict) -> None:
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                ver = info.get("version", "")
                if ver and re.match(r"^\d+\.\d+", ver):
                    packages.append((name, ver, "npm"))
                if "dependencies" in info:
                    _walk(info["dependencies"])
        _walk(data["dependencies"])

    return packages


def parse_go_mod(content: str) -> List[Package]:
    """Parse go.mod require blocks."""
    packages: List[Package] = []
    in_block = False

    for line in content.splitlines():
        line = line.strip()
        if re.match(r"^require\s*\(", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        # single-line: require github.com/foo/bar v1.2.3
        m = re.match(r"^require\s+(\S+)\s+(v[\d.][^\s]*)", line)
        if m:
            packages.append((m.group(1), m.group(2), "Go"))
            continue
        if in_block and not line.startswith("//"):
            m = re.match(r"^(\S+)\s+(v[\d.][^\s]*)", line)
            if m:
                packages.append((m.group(1), m.group(2), "Go"))

    return packages


def parse_cargo_toml(content: str) -> List[Package]:
    """Parse Cargo.toml [dependencies] / [dev-dependencies] sections."""
    packages: List[Package] = []
    in_deps = False

    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
            in_deps = True
            continue
        if in_deps and stripped.startswith("["):
            in_deps = False
            continue
        if not in_deps or not stripped or stripped.startswith("#"):
            continue

        # name = "1.0.0"  or  name = "^1.0.0"
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
        if m:
            ver = re.sub(r"^[\^~>=<]+", "", m.group(2))
            if re.match(r"^\d+", ver):
                packages.append((m.group(1), ver, "crates.io"))
            continue

        # name = { version = "1.0.0", ... }
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', stripped)
        if m:
            ver = re.sub(r"^[\^~>=<]+", "", m.group(2))
            if re.match(r"^\d+", ver):
                packages.append((m.group(1), ver, "crates.io"))

    return packages


def parse_pom_xml(content: str) -> List[Package]:
    """Parse Maven pom.xml <dependency> blocks."""
    packages: List[Package] = []
    try:
        root = ET.fromstring(content)
    except Exception:
        return []

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    for dep in root.iter(f"{ns}dependency"):
        group = (dep.findtext(f"{ns}groupId") or "").strip()
        artifact = (dep.findtext(f"{ns}artifactId") or "").strip()
        version = (dep.findtext(f"{ns}version") or "").strip()
        if not (group and artifact and version) or version.startswith("$"):
            continue
        packages.append((f"{group}:{artifact}", version, "Maven"))

    return packages


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

PARSERS = {
    "requirements": parse_requirements,
    "package_json": parse_package_json,
    "package_lock": parse_package_lock,
    "go_mod": parse_go_mod,
    "cargo_toml": parse_cargo_toml,
    "pom_xml": parse_pom_xml,
}


def parse_manifest(path: str) -> Tuple[List[Package], str]:
    """
    Parse a dependency manifest and return (packages, ecosystem).

    Raises ValueError for unrecognised files.
    """
    manifest_type = detect_manifest(path)
    if manifest_type is None:
        raise ValueError(
            f"Unrecognised manifest: {path}\n"
            "Supported: requirements.txt, package.json, package-lock.json, "
            "go.mod, Cargo.toml, pom.xml"
        )
    with open(path, encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    return PARSERS[manifest_type](content), ECOSYSTEM_MAP[manifest_type]
