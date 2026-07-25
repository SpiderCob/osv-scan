"""Tests for dep-scanner."""
from __future__ import annotations

import json
import textwrap
import unittest
from unittest.mock import MagicMock, patch

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import osv_scan
from osv_scan._models import PackageFinding, ScanResult, Vulnerability
from osv_scan._parsers import (
    detect_manifest,
    parse_cargo_toml,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_pom_xml,
    parse_requirements,
)
from osv_scan._osv import _parse_severity, _score_to_sev, _extract_fixed_versions


# ---------------------------------------------------------------------------
# Parser tests (no network)
# ---------------------------------------------------------------------------

class TestParseRequirements(unittest.TestCase):
    def test_pinned_versions(self):
        content = textwrap.dedent("""\
            requests==2.27.0
            django==3.2.1
            # comment
            -r other.txt
            flask>=2.0
        """)
        pkgs = parse_requirements(content)
        self.assertEqual(len(pkgs), 2)
        self.assertIn(("requests", "2.27.0", "PyPI"), pkgs)
        self.assertIn(("django", "3.2.1", "PyPI"), pkgs)

    def test_normalises_underscores(self):
        pkgs = parse_requirements("my_package==1.0.0\n")
        self.assertEqual(pkgs[0][0], "my-package")

    def test_inline_comment(self):
        pkgs = parse_requirements("requests==2.27.0  # security fix\n")
        self.assertEqual(pkgs[0][1], "2.27.0")

    def test_unpinned_skipped(self):
        pkgs = parse_requirements("requests>=2.0\nflask\n")
        self.assertEqual(pkgs, [])


class TestParsePackageJson(unittest.TestCase):
    def test_basic(self):
        data = json.dumps({
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"jest": "^29.0.0"},
        })
        pkgs = parse_package_json(data)
        self.assertIn(("express", "4.18.2", "npm"), pkgs)
        self.assertIn(("jest", "29.0.0", "npm"), pkgs)

    def test_skips_wildcards(self):
        data = json.dumps({"dependencies": {"foo": "*", "bar": "latest"}})
        pkgs = parse_package_json(data)
        self.assertEqual(pkgs, [])

    def test_invalid_json(self):
        self.assertEqual(parse_package_json("not json"), [])


class TestParsePackageLock(unittest.TestCase):
    def test_v2_format(self):
        data = json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "": {"version": "1.0.0"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.21", "link": True},
            },
        })
        pkgs = parse_package_lock(data)
        names = [p[0] for p in pkgs]
        self.assertIn("express", names)
        self.assertNotIn("lodash", names)  # link entries skipped

    def test_v1_format(self):
        data = json.dumps({
            "dependencies": {
                "express": {"version": "4.18.2"},
                "nested-pkg": {"version": "1.0.0", "dependencies": {
                    "inner": {"version": "2.0.0"},
                }},
            }
        })
        pkgs = parse_package_lock(data)
        names = [p[0] for p in pkgs]
        self.assertIn("express", names)
        self.assertIn("inner", names)


class TestParseGoMod(unittest.TestCase):
    def test_require_block(self):
        content = textwrap.dedent("""\
            module example.com/app

            require (
                github.com/gin-gonic/gin v1.9.1
                golang.org/x/net v0.17.0
            )
        """)
        pkgs = parse_go_mod(content)
        self.assertIn(("github.com/gin-gonic/gin", "v1.9.1", "Go"), pkgs)
        self.assertIn(("golang.org/x/net", "v0.17.0", "Go"), pkgs)

    def test_single_require(self):
        content = "require github.com/foo/bar v1.2.3\n"
        pkgs = parse_go_mod(content)
        self.assertIn(("github.com/foo/bar", "v1.2.3", "Go"), pkgs)


class TestParseCargoToml(unittest.TestCase):
    def test_simple_versions(self):
        content = textwrap.dedent("""\
            [dependencies]
            serde = "1.0.152"
            tokio = "^1.25.0"

            [dev-dependencies]
            rand = "0.8.5"
        """)
        pkgs = parse_cargo_toml(content)
        self.assertIn(("serde", "1.0.152", "crates.io"), pkgs)
        self.assertIn(("tokio", "1.25.0", "crates.io"), pkgs)
        self.assertIn(("rand", "0.8.5", "crates.io"), pkgs)

    def test_inline_table(self):
        content = textwrap.dedent("""\
            [dependencies]
            serde = { version = "1.0", features = ["derive"] }
        """)
        pkgs = parse_cargo_toml(content)
        self.assertIn(("serde", "1.0", "crates.io"), pkgs)


class TestParsePomXml(unittest.TestCase):
    def test_basic(self):
        content = textwrap.dedent("""\
            <?xml version="1.0"?>
            <project>
              <dependencies>
                <dependency>
                  <groupId>org.springframework</groupId>
                  <artifactId>spring-core</artifactId>
                  <version>5.3.20</version>
                </dependency>
              </dependencies>
            </project>
        """)
        pkgs = parse_pom_xml(content)
        self.assertIn(("org.springframework:spring-core", "5.3.20", "Maven"), pkgs)

    def test_skips_property_versions(self):
        content = textwrap.dedent("""\
            <project>
              <dependencies>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>app</artifactId>
                  <version>${app.version}</version>
                </dependency>
              </dependencies>
            </project>
        """)
        self.assertEqual(parse_pom_xml(content), [])


class TestDetectManifest(unittest.TestCase):
    def test_known_files(self):
        cases = {
            "requirements.txt": "requirements",
            "requirements-dev.txt": "requirements",
            "package.json": "package_json",
            "package-lock.json": "package_lock",
            "go.mod": "go_mod",
            "Cargo.toml": "cargo_toml",
            "pom.xml": "pom_xml",
        }
        for fname, expected in cases.items():
            with self.subTest(fname=fname):
                self.assertEqual(detect_manifest(fname), expected)

    def test_unknown_returns_none(self):
        self.assertIsNone(detect_manifest("setup.py"))
        self.assertIsNone(detect_manifest("Makefile"))


# ---------------------------------------------------------------------------
# OSV helper tests (no network)
# ---------------------------------------------------------------------------

class TestSeverityHelpers(unittest.TestCase):
    def test_score_to_sev(self):
        self.assertEqual(_score_to_sev(9.5), "CRITICAL")
        self.assertEqual(_score_to_sev(7.0), "HIGH")
        self.assertEqual(_score_to_sev(5.0), "MEDIUM")
        self.assertEqual(_score_to_sev(3.0), "LOW")

    def test_parse_severity_database_specific(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        self.assertEqual(_parse_severity(vuln), "HIGH")

    def test_parse_severity_moderate_maps_to_medium(self):
        vuln = {"database_specific": {"severity": "moderate"}}
        self.assertEqual(_parse_severity(vuln), "MEDIUM")

    def test_parse_severity_cvss_score(self):
        vuln = {"database_specific": {"cvss_score": 8.5}}
        self.assertEqual(_parse_severity(vuln), "HIGH")

    def test_parse_severity_default(self):
        self.assertEqual(_parse_severity({}), "MEDIUM")

    def test_extract_fixed_versions(self):
        vuln = {
            "affected": [{
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
                }]
            }]
        }
        self.assertEqual(_extract_fixed_versions(vuln), ["2.31.0"])


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestPackageFinding(unittest.TestCase):
    def _make_vuln(self, severity, fixed=None):
        return Vulnerability(
            id="GHSA-test", cve="CVE-2023-1234", aliases=[],
            summary="Test", details="", severity=severity,
            fixed_versions=fixed or [], published="2023-01-01",
        )

    def test_highest_severity(self):
        finding = PackageFinding(
            package="requests", version="2.27.0", ecosystem="PyPI",
            vulnerabilities=[
                self._make_vuln("LOW"),
                self._make_vuln("CRITICAL"),
                self._make_vuln("HIGH"),
            ]
        )
        self.assertEqual(finding.highest_severity, "CRITICAL")

    def test_fix_versions_deduped_sorted(self):
        finding = PackageFinding(
            package="requests", version="2.27.0", ecosystem="PyPI",
            vulnerabilities=[
                self._make_vuln("HIGH", ["2.31.0", "2.30.0"]),
                self._make_vuln("LOW", ["2.30.0"]),
            ]
        )
        self.assertEqual(finding.fix_versions, ["2.30.0", "2.31.0"])


class TestScanResult(unittest.TestCase):
    def _make_result(self):
        def vuln(sev):
            return Vulnerability(
                id="x", cve="", aliases=[], summary="",
                details="", severity=sev, fixed_versions=[], published="",
            )
        findings = [
            PackageFinding("pkg-a", "1.0", "PyPI", [vuln("CRITICAL")]),
            PackageFinding("pkg-b", "2.0", "PyPI", [vuln("HIGH")]),
            PackageFinding("pkg-c", "3.0", "PyPI", [vuln("MEDIUM")]),
        ]
        return ScanResult(
            source="requirements.txt", ecosystem="PyPI",
            packages_scanned=10, findings=findings, elapsed_ms=100,
        )

    def test_highest_severity(self):
        self.assertEqual(self._make_result().highest_severity, "CRITICAL")

    def test_severity_properties(self):
        r = self._make_result()
        self.assertEqual(len(r.critical), 1)
        self.assertEqual(len(r.high), 1)
        self.assertEqual(len(r.medium), 1)
        self.assertEqual(len(r.low), 0)

    def test_to_dict(self):
        d = self._make_result().to_dict()
        self.assertIn("CRITICAL", d)
        self.assertIn("HIGH", d)
        self.assertNotIn("LOW", d)


# ---------------------------------------------------------------------------
# Integration test (hits OSV.dev — skipped in offline CI)
# ---------------------------------------------------------------------------

@unittest.skipIf(os.environ.get("OFFLINE"), "skipped in offline mode")
class TestLiveOsvScan(unittest.TestCase):
    def test_known_vulnerable_package(self):
        """requests 2.6.0 has known CVEs — OSV should return findings."""
        result = osv_scan.scan_text(
            "requests==2.6.0\n",
            ecosystem="PyPI",
            source="test",
        )
        self.assertGreater(result.packages_scanned, 0)
        self.assertTrue(result.has_findings)
        self.assertIsNotNone(result.highest_severity)

    def test_safe_package(self):
        """A recent, known-safe package should have no findings."""
        result = osv_scan.scan_text(
            "six==1.16.0\n",
            ecosystem="PyPI",
            source="test",
        )
        # May or may not have findings depending on OSV data, just check it runs
        self.assertIsInstance(result, ScanResult)
        self.assertGreater(result.packages_scanned, 0)

    def test_unknown_ecosystem_raises(self):
        with self.assertRaises(ValueError):
            osv_scan.scan_text("foo==1.0\n", ecosystem="UnknownEco")


if __name__ == "__main__":
    unittest.main()
