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

    def test_probe_is_frozen_cannot_be_mutated(self):
        # Chunk V (verification) finding: catches accidental post-construction
        # mutation like `p.safe = False`. Not a security boundary (a subclass
        # can still bypass __post_init__), just a developer-mistake guard.
        p = ProbeTemplate(command="echo ok")
        with self.assertRaises(Exception) as cm:
            p.safe = False  # type: ignore[misc]
        # dataclass frozen raises FrozenInstanceError which is a subclass of AttributeError
        self.assertIn("cannot assign", str(cm.exception).lower())


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


class TestEvalCmsPluginProbes(unittest.TestCase):
    """Signals for the OpenSSL / bash / ghostscript / Apache-proxy probes."""

    def _hits(self, cve_id: str, output: str) -> bool:
        return any(re.search(p, output, re.M) for p in KNOWN_PROBES[cve_id].expected_signals)

    def test_heartbleed_only_matches_1_0_1_through_f(self):
        self.assertTrue(self._hits("CVE-2014-0160", "OpenSSL 1.0.1f 6 Jan 2014"))
        self.assertTrue(self._hits("CVE-2014-0160", "OpenSSL 1.0.1 14 Mar 2012"))
        self.assertFalse(self._hits("CVE-2014-0160", "OpenSSL 1.0.1g 7 Apr 2014"))
        self.assertFalse(self._hits("CVE-2014-0160", "OpenSSL 1.1.1d  10 Sep 2019"))

    def test_shellshock_matches_only_when_marker_is_echoed(self):
        self.assertTrue(self._hits("CVE-2014-6278", "SHELLSHOCK_VULNERABLE\nprobe_done"))
        self.assertFalse(self._hits("CVE-2014-6278", "probe_done"))

    def test_ghostscript_matches_before_9_21(self):
        self.assertTrue(self._hits("CVE-2017-8291", "9.20\nghostscript\t9.20~dfsg-3"))
        self.assertTrue(self._hits("CVE-2017-8291", "9.5"))
        self.assertFalse(self._hits("CVE-2017-8291", "9.21"))
        self.assertFalse(self._hits("CVE-2017-8291", "9.27"))

    def test_openssl_0778_range(self):
        self.assertTrue(self._hits("CVE-2022-0778", "OpenSSL 1.1.1m  14 Dec 2021"))
        self.assertTrue(self._hits("CVE-2022-0778", "OpenSSL 1.1.1d  10 Sep 2019"))
        self.assertFalse(self._hits("CVE-2022-0778", "OpenSSL 1.1.1n  15 Mar 2022"))
        self.assertFalse(self._hits("CVE-2022-0778", "OpenSSL 3.0.2 15 Mar 2022"))

    def test_openssl_3711_range(self):
        self.assertTrue(self._hits("CVE-2021-3711", "OpenSSL 1.1.1k  25 Mar 2021"))
        self.assertFalse(self._hits("CVE-2021-3711", "OpenSSL 1.1.1l  24 Aug 2021"))

    def test_apache_proxy_matches_only_with_module_loaded(self):
        self.assertTrue(self._hits("CVE-2021-40438", " proxy_module (shared)\nServer version: Apache/2.4.48"))
        self.assertFalse(self._hits("CVE-2021-40438", "Server version: Apache/2.4.38 (Debian)"))

    def test_apache_probes_fall_back_to_apache2_binary(self):
        for cve in ("CVE-2021-42013", "CVE-2021-41773"):
            self.assertIn("apache2 -v", KNOWN_PROBES[cve].command)


class TestPhpProbes(unittest.TestCase):
    def _hits(self, cve_id: str, output: str) -> bool:
        return any(re.search(p, output) for p in KNOWN_PROBES[cve_id].expected_signals)

    def test_vulnerable_versions_match(self):
        for v in ("7.4.21", "7.3.0", "8.0.30", "8.1.2", "8.2.34", "8.2.0", "8.3.35", "8.4.26", "8.5.11"):
            self.assertTrue(self._hits("CVE-2026-109618", f"PHP {v} (cli)"), v)
            self.assertTrue(self._hits("CVE-2026-109619", f"PHP {v} (cli)"), v)

    def test_fixed_versions_do_not_match(self):
        for v in ("8.2.35", "8.2.40", "8.3.36", "8.4.27", "8.5.12", "8.5.20", "9.0.0"):
            self.assertFalse(self._hits("CVE-2026-109618", f"PHP {v} (cli)"), v)
            self.assertFalse(self._hits("CVE-2026-109619", f"PHP {v} (cli)"), v)

    def test_range_start_differs_between_the_two(self):
        self.assertFalse(self._hits("CVE-2026-109618", "PHP 7.2.10 (cli)"))
        self.assertTrue(self._hits("CVE-2026-109619", "PHP 7.2.10 (cli)"))
        self.assertTrue(self._hits("CVE-2026-109619", "PHP 5.4.0 (cli)"))
        self.assertFalse(self._hits("CVE-2026-109619", "PHP 5.3.29 (cli)"))


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
