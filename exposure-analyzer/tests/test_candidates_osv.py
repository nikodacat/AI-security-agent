"""OSV-sourced candidates: shape and the facade's pass-through of limits."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cve-matcher"))

from exposure_analyzer.candidates import osv_candidate, osv_candidates  # noqa: E402
from exposure_analyzer.prompts import _candidate_summary  # noqa: E402


def _found(**kw):
    base = {"cve_id": "CVE-2016-4437", "ecosystem": "Maven", "name": "org.apache.shiro:shiro-core",
            "version": "1.2.4", "advisories": ["GHSA-xxxx"], "score": 9.8, "severity": "CRITICAL",
            "description": "Shiro RememberMe deserialization", "published": "2016-06-01",
            "path": "/shirodemo-1.0-SNAPSHOT.jar"}
    base.update(kw)
    return base


class OsvCandidateShape(unittest.TestCase):
    def test_is_tagged_osv_and_not_claimed_exploited(self):
        c = osv_candidate(_found())
        self.assertEqual((c["source"], c["match_reason"], c["verdict"]), ("osv", "osv", "vulnerable"))
        self.assertIn("Not in CISA KEV", c["verdict_detail"])
        self.assertIn("org.apache.shiro:shiro-core 1.2.4", c["verdict_detail"])
        self.assertFalse(c["ransomware_linked"])

    def test_says_a_library_on_disk_is_not_proof_of_reachability(self):
        self.assertIn("not necessarily", osv_candidate(_found())["verdict_detail"])

    def test_every_field_the_prompt_reads_is_present(self):
        summary = _candidate_summary(osv_candidate(_found()))
        for key in ("cve_id", "kev_name", "kev_product", "package_name", "package_version",
                    "package_source", "source", "verdict", "verdict_detail"):
            self.assertIn(key, summary)


class OsvCandidatesFacade(unittest.TestCase):
    def test_passes_limits_and_known_ids_through(self):
        seen = {}

        def fake_discover(libs, **kw):
            seen.update(kw, n=len(libs))
            return [_found()]

        out = osv_candidates([{"ecosystem": "Maven", "name": "a:b", "version": "1"}],
                             existing_cve_ids=["CVE-A"], min_cvss=8.0, per_product=3, max_total=9,
                             discover_fn=fake_discover)
        self.assertEqual([c["cve_id"] for c in out], ["CVE-2016-4437"])
        self.assertEqual((seen["min_cvss"], seen["per_product"], seen["max_total"], seen["n"]), (8.0, 3, 9, 1))
        self.assertEqual(seen["exclude_cve_ids"], frozenset({"CVE-A"}))

    def test_defaults_come_from_the_discovery_module(self):
        seen = {}
        osv_candidates([], discover_fn=lambda libs, **kw: seen.update(kw) or [])
        self.assertEqual((seen["min_cvss"], seen["per_product"], seen["max_total"]), (7.0, 15, 60))


if __name__ == "__main__":
    unittest.main()
