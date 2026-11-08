"""Tests for the compact services summary handed to the analyzer."""

from __future__ import annotations

import unittest

from exposure_analyzer.hoststate import MAX_DIRECTIVES, summarize_services
from exposure_analyzer.prompts import _candidate_summary

_SERVICES = {
    "status": "completed",
    "listening": [{"port": 80, "bind": "0.0.0.0", "loopback_only": False, "pids": [1],
                   "exe": "/usr/sbin/apache2", "cmdline": "apache2 -DFOREGROUND", "family": "ipv4"}],
    "apache": {"modules": ["rewrite_module"], "has_mod_proxy": False, "has_mod_cgi": False,
               "has_mod_php": True, "has_mod_rewrite": True, "config_files": ["a", "b"],
               "directives": [f"d{i}" for i in range(100)]},
    "nginx": {},
    "php": {"ini_files": ["x.ini"], "settings": {"expose_php": "Off"}},
}


class TestSummarizeServices(unittest.TestCase):
    def test_keeps_decision_facts_and_drops_bulk(self):
        s = summarize_services(_SERVICES)
        self.assertEqual(s["listening"][0], {"port": 80, "bind": "0.0.0.0", "loopback_only": False,
                                              "exe": "/usr/sbin/apache2", "cmdline": "apache2 -DFOREGROUND"})
        self.assertIs(s["apache"]["mod_proxy_loaded"], False)
        self.assertIs(s["apache"]["mod_php_loaded"], True)
        self.assertEqual(len(s["apache"]["directives"]), MAX_DIRECTIVES)
        self.assertNotIn("config_files", s["apache"])
        self.assertEqual(s["php_ini"], {"expose_php": "Off"})
        self.assertNotIn("nginx", s)

    def test_absent_or_failed_scanner_gives_empty(self):
        self.assertEqual(summarize_services(None), {})
        self.assertEqual(summarize_services({}), {})
        self.assertEqual(summarize_services({"status": "error", "error": "x"}), {})
        self.assertEqual(summarize_services({"status": "skipped"}), {})


class TestCandidateSummaryKeepsOrigin(unittest.TestCase):
    def test_banner_and_package_source_fields_reach_the_prompt(self):
        cand = {"cve_id": "CVE-X", "package_source": "unmanaged-binary", "source": "banner",
                "source_port": 8080, "banner": "Apache/2.4.49", "internal_only": "dropped"}
        out = _candidate_summary(cand)
        self.assertEqual(out["package_source"], "unmanaged-binary")
        self.assertEqual(out["banner"], "Apache/2.4.49")
        self.assertNotIn("internal_only", out)


if __name__ == "__main__":
    unittest.main()
