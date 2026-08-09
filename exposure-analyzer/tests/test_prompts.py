"""Tests for exposure_analyzer.prompts."""

from __future__ import annotations

import unittest

from exposure_analyzer.prompts import SYSTEM_PROMPT, build_verdict_prompt


_SAMPLE_CANDIDATE = {
    "cve_id": "CVE-2023-38408",
    "kev_name": "OpenSSH PKCS#11 Vulnerability",
    "kev_vendor": "OpenSSH",
    "kev_product": "OpenSSH",
    "kev_description": "OpenSSH between 5.5 and 9.3p1 contains a PKCS#11 vulnerability.",
    "cwes": ["CWE-428"],
    "package_name": "openssh-server",
    "package_version": "8.5p1",
    "verdict": "vulnerable",
    "verdict_detail": "8.5p1 in affected range",
    "ransomware_linked": True,
}

_SAMPLE_HOST_STATE = {
    "os": "Ubuntu 22.04",
    "services": [{"name": "sshd", "status": "running", "port": 22}],
}


class TestSystemPrompt(unittest.TestCase):
    def test_declares_all_five_verdicts(self):
        for verdict in (
            "CONFIRMED",
            "MITIGATED_BY_CONFIG",
            "MITIGATED_BY_EXPOSURE",
            "NOT_RUNNING",
            "NO_EVIDENCE",
        ):
            self.assertIn(verdict, SYSTEM_PROMPT)

    def test_demands_json_only_response(self):
        # If we relax "ONLY a single JSON object", the parser breaks.
        self.assertIn("ONLY", SYSTEM_PROMPT)
        self.assertIn('"verdict"', SYSTEM_PROMPT)


class TestBuildVerdictPromptNoProbe(unittest.TestCase):
    def test_includes_cve_id_and_metadata(self):
        prompt = build_verdict_prompt(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE)
        self.assertIn("CVE-2023-38408", prompt)
        self.assertIn("openssh-server", prompt)
        self.assertIn("8.5p1", prompt)

    def test_notes_no_probe(self):
        prompt = build_verdict_prompt(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE)
        self.assertIn("(none)", prompt)

    def test_includes_host_state(self):
        prompt = build_verdict_prompt(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE)
        self.assertIn("Ubuntu 22.04", prompt)
        self.assertIn("sshd", prompt)


class TestBuildVerdictPromptWithProbe(unittest.TestCase):
    def test_includes_probe_command_and_output(self):
        prompt = build_verdict_prompt(
            _SAMPLE_CANDIDATE,
            _SAMPLE_HOST_STATE,
            probe_command="ssh -V",
            probe_output="OpenSSH_8.5p1, LibreSSL 3.3.6",
        )
        self.assertIn("ssh -V", prompt)
        self.assertIn("OpenSSH_8.5p1", prompt)

    def test_truncates_huge_probe_output(self):
        huge = "A" * 10_000
        prompt = build_verdict_prompt(
            _SAMPLE_CANDIDATE,
            _SAMPLE_HOST_STATE,
            probe_command="cat /var/log/big",
            probe_output=huge,
        )
        # Should have truncation notice
        self.assertIn("truncated", prompt)
        # And not contain the full 10k A's
        self.assertLess(prompt.count("A"), 10_000)


class TestPromptSizeDefense(unittest.TestCase):
    def test_truncates_massive_host_state(self):
        big_state = {"blob": "X" * 50_000}
        prompt = build_verdict_prompt(_SAMPLE_CANDIDATE, big_state)
        self.assertIn("truncated", prompt)


if __name__ == "__main__":
    unittest.main()
