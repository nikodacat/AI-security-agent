"""NVD-sourced candidates: shape and the not-exploited / distro-backport wording."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cve-matcher"))

from cve_matcher.inventory import Package  # noqa: E402

from exposure_analyzer.candidates import nvd_candidate, nvd_candidates  # noqa: E402
from exposure_analyzer.prompts import _candidate_summary  # noqa: E402


def _found(pkg, **kw):
    base = {"cve_id": "CVE-2022-0778", "description": "infinite loop in BN_mod_sqrt", "score": 7.5,
            "severity": "HIGH", "published": "2022-03-15", "package": pkg,
            "cpe": "cpe:2.3:a:openssl:openssl:1.1.1d:*:*:*:*:*:*:*", "distro_patched": False}
    base.update(kw)
    return base


class NvdCandidateShape(unittest.TestCase):
    def test_unmanaged_package_is_vulnerable_and_not_claimed_exploited(self):
        c = nvd_candidate(_found(Package(name="redis", version="6.2.6", source="unmanaged-binary")))
        self.assertEqual(c["source"], "nvd-cpe")
        self.assertEqual(c["verdict"], "vulnerable")
        self.assertIn("Not in CISA KEV", c["verdict_detail"])
        self.assertFalse(c["ransomware_linked"])
        self.assertEqual((c["kev_vendor"], c["kev_product"]), ("openssl", "openssl"))

    def test_debian_revision_downgrades_to_unknown_with_backport_warning(self):
        pkg = Package(name="libssl1.1", version="1.1.1d-0+deb10u7", source="dpkg (via host-scanner)")
        c = nvd_candidate(_found(pkg, distro_patched=True))
        self.assertEqual(c["verdict"], "unknown")
        self.assertIn("backports", c["verdict_detail"])
        self.assertIn("1.1.1d-0+deb10u7", c["verdict_detail"])

    def test_every_field_the_prompt_reads_is_present(self):
        c = nvd_candidate(_found(Package(name="redis", version="6.2.6", source="unmanaged-binary")))
        summary = _candidate_summary(c)
        for key in ("cve_id", "kev_name", "kev_product", "package_name", "package_version",
                    "package_source", "source", "verdict", "verdict_detail"):
            self.assertIn(key, summary)


class NvdCandidatesFacade(unittest.TestCase):
    def test_passes_thresholds_and_known_ids_through(self):
        seen = {}

        def fake_discover(packages, **kw):
            seen.update(kw, n=len(packages))
            return [_found(packages[0])]

        pkg = Package(name="redis", version="6.2.6")
        out = nvd_candidates([pkg], existing_cve_ids=["CVE-A"], min_cvss=8.0, per_product=3, max_total=5,
                             discover_fn=fake_discover)
        self.assertEqual([c["cve_id"] for c in out], ["CVE-2022-0778"])
        self.assertEqual((seen["min_cvss"], seen["per_product"], seen["max_total"], seen["n"]), (8.0, 3, 5, 1))
        self.assertEqual(seen["exclude_cve_ids"], frozenset({"CVE-A"}))

    def test_defaults_come_from_the_discovery_module(self):
        seen = {}
        nvd_candidates([], discover_fn=lambda p, **kw: seen.update(kw) or [])
        self.assertEqual((seen["min_cvss"], seen["per_product"], seen["max_total"]), (7.0, 15, 60))


if __name__ == "__main__":
    unittest.main()
