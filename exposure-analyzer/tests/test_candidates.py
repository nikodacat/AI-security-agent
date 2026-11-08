"""Tests for banner-sourced candidates (v3-1)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from exposure_analyzer.candidates import (
    BANNER_NOT_IN_INVENTORY,
    _ensure_cve_matcher_importable,
    apt_has_version,
    banner_candidates,
    banner_services,
    finding_to_candidate,
)
from exposure_analyzer.cli import main

_VULHUB_STATE = [
    {
        "target": "127.0.0.1", "port": 8080, "protocol": "tcp", "reachable": True,
        "banner": "Apache/2.4.49 (Unix)",
        "service_guess": {"vendor": "apache", "product": "http_server", "version": "2.4.49"},
    }
]


def _fake_finding(cve_id: str, source: str = "banner:8080/tcp",
                  verdict: str = "vulnerable", detail: str = "2.4.49 in affected range"):
    return SimpleNamespace(
        entry=SimpleNamespace(cve_id=cve_id, name=f"{cve_id} name", vendor="Apache",
                              product="HTTP Server", description="d", ransomware=False),
        package=SimpleNamespace(name="http_server", version="2.4.49", vendor="apache",
                                source=source),
        match_score=100.0, match_reason="vendor+product",
        verdict=verdict, verdict_detail=detail,
    )


class TestBannerServices(unittest.TestCase):
    def test_keeps_reachable_with_product_and_version(self):
        self.assertEqual(banner_services(_VULHUB_STATE), _VULHUB_STATE)

    def test_drops_unreachable(self):
        obs = [dict(_VULHUB_STATE[0], reachable=False)]
        self.assertEqual(banner_services(obs), [])

    def test_drops_missing_version_or_product_or_guess(self):
        base = _VULHUB_STATE[0]
        no_version = dict(base, service_guess={"vendor": "apache", "product": "http_server"})
        no_product = dict(base, service_guess={"vendor": "apache", "version": "2.4.49"})
        no_guess = {k: v for k, v in base.items() if k != "service_guess"}
        self.assertEqual(banner_services([no_version, no_product, no_guess]), [])


class TestFindingToCandidate(unittest.TestCase):
    def test_shape_matches_kev_findings_and_is_tagged(self):
        c = finding_to_candidate(_fake_finding("CVE-2021-41773"), banner="Apache/2.4.49 (Unix)")
        for key in ("cve_id", "kev_name", "kev_vendor", "kev_product", "kev_description",
                    "package_name", "package_version", "package_vendor", "match_reason",
                    "match_score", "verdict", "verdict_detail", "ransomware_linked"):
            self.assertIn(key, c)
        self.assertEqual(c["source"], "banner")
        self.assertEqual(c["source_port"], 8080)
        self.assertEqual(c["banner"], "Apache/2.4.49 (Unix)")
        self.assertEqual(c["match_reason"], "banner+vendor+product")
        self.assertIn("2.4.49 in affected range", c["verdict_detail"])
        self.assertIn("service banner", c["verdict_detail"])

    def test_empty_detail_still_says_banner_sourced(self):
        c = finding_to_candidate(_fake_finding("CVE-X", verdict="unknown", detail=""))
        self.assertIn("service banner", c["verdict_detail"])


class TestBannerCandidates(unittest.TestCase):
    def test_returns_candidates_and_skips_existing_ids(self):
        findings = [_fake_finding("CVE-2021-41773"), _fake_finding("CVE-2021-42013")]
        out = banner_candidates(
            _VULHUB_STATE, existing_cve_ids=["CVE-2021-42013"],
            match_fn=lambda services: findings, enrich=False,
        )
        self.assertEqual([c["cve_id"] for c in out], ["CVE-2021-41773"])

    def test_dedupes_same_cve_within_banner_results(self):
        findings = [_fake_finding("CVE-1"), _fake_finding("CVE-1")]
        out = banner_candidates(_VULHUB_STATE, match_fn=lambda s: findings, enrich=False)
        self.assertEqual(len(out), 1)

    def test_no_usable_service_never_calls_matcher(self):
        def boom(_services):
            raise AssertionError("matcher must not run")
        self.assertEqual(
            banner_candidates([dict(_VULHUB_STATE[0], reachable=False)], match_fn=boom), [])

    def test_enrich_runs_and_mutations_land_in_candidates(self):
        findings = [_fake_finding("CVE-1", verdict="unknown", detail="")]

        def enrich(fs):
            fs[0].verdict, fs[0].verdict_detail = "vulnerable", "Installed 2.4.49 in affected range"

        out = banner_candidates(_VULHUB_STATE, match_fn=lambda s: findings, enrich_fn=enrich)
        self.assertEqual(out[0]["verdict"], "vulnerable")
        self.assertIn("affected range", out[0]["verdict_detail"])

    def test_enrich_failure_is_nonfatal_and_logged(self):
        logs: list[str] = []

        def enrich(_fs):
            raise ConnectionError("nvd down")

        out = banner_candidates(
            _VULHUB_STATE, match_fn=lambda s: [_fake_finding("CVE-1", verdict="unknown", detail="")],
            enrich_fn=enrich, log=logs.append,
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["verdict"], "unknown")
        self.assertTrue(any("NVD enrichment failed" in m for m in logs))

    def test_enrich_false_never_calls_enrich(self):
        def boom(_fs):
            raise AssertionError("must not enrich")
        out = banner_candidates(_VULHUB_STATE, match_fn=lambda s: [_fake_finding("CVE-1")],
                                enrich_fn=boom, enrich=False)
        self.assertEqual(len(out), 1)


class TestWithRealCveMatcher(unittest.TestCase):
    """Real cve-matcher KEV matching on a tiny hand-built catalog (offline)."""

    @classmethod
    def setUpClass(cls):
        _ensure_cve_matcher_importable()
        try:
            from cve_matcher.kev import KevCatalog, KevEntry  # type: ignore
        except ImportError:
            raise unittest.SkipTest("cve-matcher not importable")
        cls.KevCatalog, cls.KevEntry = KevCatalog, KevEntry

    def _entry(self, cve_id, vendor, product):
        return self.KevEntry(cve_id=cve_id, vendor=vendor, product=product, name=cve_id,
                             date_added="", description="", required_action="",
                             due_date="", ransomware=False)

    def test_apache_banner_matches_apache_http_server_kev_entries_only(self):
        catalog = self.KevCatalog("t", "t", [
            self._entry("CVE-2021-41773", "Apache", "HTTP Server"),
            self._entry("CVE-2021-42013", "Apache", "HTTP Server"),
            self._entry("CVE-2021-44228", "Apache", "Log4j2"),
            self._entry("CVE-2014-0160", "OpenSSL", "OpenSSL"),
        ])
        out = banner_candidates(_VULHUB_STATE, catalog=catalog, enrich=False)
        self.assertEqual(sorted(c["cve_id"] for c in out),
                         ["CVE-2021-41773", "CVE-2021-42013"])
        self.assertTrue(all(c["source"] == "banner" and c["package_version"] == "2.4.49"
                            for c in out))
        self.assertEqual(out[0]["banner"], "Apache/2.4.49 (Unix)")


class TestCli(unittest.TestCase):
    def test_banner_candidates_requires_network_state(self):
        with tempfile.TemporaryDirectory() as td:
            cand = Path(td) / "c.json"
            cand.write_text(json.dumps({"kev_findings": []}), encoding="utf-8")
            rc = main(["analyze", "--candidates", str(cand), "--banner-candidates",
                       "--output", str(Path(td) / "v.json")])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()


class TestBannerOrigin(unittest.TestCase):
    """The banner step records whether apt could have installed the software."""

    def test_apt_has_version_matches_at_a_boundary(self):
        self.assertTrue(apt_has_version("2.4.38", ["2.4.38-3+deb10u10"]))
        self.assertTrue(apt_has_version("8.4p1", ["1:8.4p1-5+deb11u1"]))   # epoch dropped
        self.assertTrue(apt_has_version("1.18.0", ["1.18.0"]))
        self.assertFalse(apt_has_version("2.4.49", ["2.4.38-3+deb10u10"]))
        self.assertFalse(apt_has_version("2.4.49", ["2.4.499-1"]))          # not a prefix of a longer number
        self.assertFalse(apt_has_version("2.4.49", ["2.4.49.1-1"]))
        self.assertFalse(apt_has_version("", ["2.4.49-1"]))
        self.assertFalse(apt_has_version("2.4.49", []))

    def _run(self, versions):
        return banner_candidates(_VULHUB_STATE, match_fn=lambda s: [_fake_finding("CVE-1")],
                                 enrich=False, installed_apt_versions=versions)

    def test_banner_version_found_in_apt_list_is_dpkg(self):
        self.assertEqual(self._run(["2.4.49-1~deb11u1"])[0]["package_source"], "dpkg")

    def test_the_full_installed_apt_version_is_recorded(self):
        c = self._run(["2.4.38-3+deb10u4", "2.4.49-3+deb10u4"])[0]
        self.assertEqual(c["installed_version"], "2.4.49-3+deb10u4")
        self.assertEqual(c["package_version"], "2.4.49")      # the banner's claim is untouched
        self.assertNotIn("installed_version", self._run(["1.0"])[0])

    def test_banner_version_not_in_apt_list_is_marked(self):
        self.assertEqual(self._run(["2.4.38-3+deb10u10"])[0]["package_source"], BANNER_NOT_IN_INVENTORY)

    def test_unknown_inventory_records_nothing(self):
        self.assertNotIn("package_source", self._run(None)[0])
