"""Tests for exposure_analyzer.probes."""

from __future__ import annotations

import re
import unittest

from exposure_analyzer.probes import KNOWN_PROBES, ProbeTemplate, lookup_probe


class TestProbeTemplate(unittest.TestCase):
    def test_safe_default_is_true(self):
        p = ProbeTemplate(command="echo ok")
        self.assertTrue(p.safe)

    def test_unsafe_probe_rejected(self):
        with self.assertRaises(ValueError):
            ProbeTemplate(command="rm -rf /", safe=False)


class TestKnownProbes(unittest.TestCase):
    def test_ssh_probe_registered(self):
        probe = lookup_probe("CVE-2023-38408")
        self.assertIsNotNone(probe)
        assert probe is not None
        self.assertEqual(probe.command, "ssh -V")
        self.assertTrue(probe.safe)

    def test_unknown_cve_returns_none(self):
        self.assertIsNone(lookup_probe("CVE-9999-99999"))

    def test_ssh_signals_match_vulnerable_versions(self):
        probe = KNOWN_PROBES["CVE-2023-38408"]
        combined = re.compile("|".join(probe.expected_signals))
        # Known-vulnerable version banners
        for banner in ("OpenSSH_5.5p1", "OpenSSH_8.5p1", "OpenSSH_9.2p1"):
            self.assertRegex(banner, combined, f"expected {banner} to match")

    def test_ssh_signals_do_not_match_patched(self):
        probe = KNOWN_PROBES["CVE-2023-38408"]
        combined = re.compile("|".join(probe.expected_signals))
        for banner in ("OpenSSH_9.3p2", "OpenSSH_9.4p1", "OpenSSH_10.0p1"):
            self.assertNotRegex(banner, combined, f"{banner} should not match")


class TestApacheProbes(unittest.TestCase):
    def test_cve_2021_42013_matches_both_vulnerable_versions(self):
        probe = KNOWN_PROBES["CVE-2021-42013"]
        combined = re.compile("|".join(probe.expected_signals))
        for banner in (
            "Server version: Apache/2.4.49 (Unix)",
            "Server version: Apache/2.4.50 (Unix)",
        ):
            self.assertRegex(banner, combined, f"{banner} should match")

    def test_cve_2021_42013_does_not_match_patched(self):
        probe = KNOWN_PROBES["CVE-2021-42013"]
        combined = re.compile("|".join(probe.expected_signals))
        for banner in (
            "Server version: Apache/2.4.48 (Unix)",  # older
            "Server version: Apache/2.4.51 (Unix)",  # patched
            "Server version: Apache/2.4.62 (Unix)",  # much later
            "Server version: Apache/2.4.38 (Debian)",  # cms-plugin
        ):
            self.assertNotRegex(banner, combined, f"{banner} should not match")

    def test_cve_2021_41773_is_more_restrictive_than_42013(self):
        # 41773 affects only 2.4.49; 42013 affects 2.4.49 AND 2.4.50
        probe_41773 = KNOWN_PROBES["CVE-2021-41773"]
        combined_41773 = re.compile("|".join(probe_41773.expected_signals))
        self.assertRegex("Apache/2.4.49", combined_41773)
        self.assertNotRegex("Apache/2.4.50", combined_41773)  # 41773 patched at 2.4.50


class TestRedisProbe(unittest.TestCase):
    def test_matches_vulnerable_redis_versions(self):
        probe = KNOWN_PROBES["CVE-2022-0543"]
        combined = re.compile("|".join(probe.expected_signals))
        for line in ("redis_version:5.0.9", "redis_version:6.0.16", "redis_version:6.2.6"):
            self.assertRegex(line, combined, f"{line} should match")

    def test_does_not_match_patched_redis(self):
        probe = KNOWN_PROBES["CVE-2022-0543"]
        combined = re.compile("|".join(probe.expected_signals))
        for line in ("redis_version:7.0.0", "redis_version:6.2.7", "redis_version:7.2.4"):
            self.assertNotRegex(line, combined, f"{line} should not match")


class TestLog4jProbe(unittest.TestCase):
    def test_matches_vulnerable_log4j_jars(self):
        probe = KNOWN_PROBES["CVE-2021-44228"]
        combined = re.compile("|".join(probe.expected_signals))
        for path in (
            "/opt/app/lib/log4j-core-2.14.1.jar",
            "/usr/local/lib/log4j-core-2.0.jar",  # exact 2.0
            "/tmp/log4j-core-2.9.0.jar",
        ):
            self.assertRegex(path, combined, f"{path} should match")

    def test_does_not_match_patched_log4j(self):
        probe = KNOWN_PROBES["CVE-2021-44228"]
        combined = re.compile("|".join(probe.expected_signals))
        for path in (
            "/opt/app/lib/log4j-core-2.17.1.jar",   # patched
            "/opt/app/lib/log4j-core-2.15.0.jar",   # partial mitigation, not initial CVE
            "/opt/app/lib/log4j-core-2.20.0.jar",   # much later
        ):
            self.assertNotRegex(path, combined, f"{path} should not match")


class TestProbeLibraryContract(unittest.TestCase):
    """Whole-library invariants that catch drift when new probes are added."""

    def test_every_probe_is_safe(self):
        for cve_id, probe in KNOWN_PROBES.items():
            self.assertTrue(probe.safe, f"{cve_id} probe must be safe=True in v1")

    def test_every_probe_has_signals_and_hint(self):
        for cve_id, probe in KNOWN_PROBES.items():
            self.assertTrue(
                probe.expected_signals,
                f"{cve_id}: expected_signals must not be empty",
            )
            self.assertTrue(
                probe.interpretation_hint.strip(),
                f"{cve_id}: interpretation_hint must not be empty",
            )

    def test_every_probe_compiles_as_regex(self):
        for cve_id, probe in KNOWN_PROBES.items():
            for pat in probe.expected_signals:
                try:
                    re.compile(pat)
                except re.error as e:
                    self.fail(f"{cve_id}: pattern {pat!r} does not compile: {e}")


if __name__ == "__main__":
    unittest.main()
