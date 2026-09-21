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


# --- v2: network_state integration -------------------------------------------


_SSH_OBSERVATION = {
    "target": "eval-web-vuln",
    "port": 22,
    "protocol": "tcp",
    "reachable": True,
    "banner": "OpenSSH 8.5p1 Ubuntu-1ubuntu1",
    "service_guess": {"vendor": "OpenSSH", "product": "OpenSSH", "version": "8.5p1"},
}
_REDIS_OBSERVATION = {
    "target": "eval-db-exposed",
    "port": 6379,
    "protocol": "tcp",
    "reachable": True,
    "banner": "Redis key-value store 6.2.6",
    "service_guess": {"vendor": "Redis", "product": "Redis", "version": "6.2.6"},
}
_CLOSED_OBSERVATION = {
    "target": "eval-web-vuln",
    "port": 443,
    "protocol": "tcp",
    "reachable": False,
}


class TestNetworkStateAbsent(unittest.TestCase):
    """v1 baseline behavior — no network_state, no external-attacker section."""

    def test_none_omits_section_entirely(self):
        prompt = build_verdict_prompt(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE, network_state=None)
        self.assertNotIn("External-attacker view", prompt)

    def test_default_is_none(self):
        """Backward compat: existing callers pass 3 or 4 positional args and
        must keep working without opting into v2."""
        prompt_v1 = build_verdict_prompt(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE)
        self.assertNotIn("External-attacker view", prompt_v1)


class TestNetworkStatePresent(unittest.TestCase):
    def test_matching_observation_shown(self):
        prompt = build_verdict_prompt(
            _SAMPLE_CANDIDATE,  # kev_product=OpenSSH, package_name=openssh-server
            _SAMPLE_HOST_STATE,
            network_state=[_SSH_OBSERVATION, _REDIS_OBSERVATION],
        )
        self.assertIn("External-attacker view", prompt)
        self.assertIn("OpenSSH", prompt)
        # Redis is not this CVE's service; filter should exclude it
        self.assertNotIn("Redis key-value store", prompt)

    def test_no_token_match_falls_back_to_reachable_ports(self):
        """If nothing service-matches, we still surface reachable observations
        so the model can note them (better than empty context)."""
        redis_cve = dict(_SAMPLE_CANDIDATE)
        redis_cve.update({
            "cve_id": "CVE-2022-0543",
            "kev_product": "Redis",
            "kev_vendor": "Redis",
            "package_name": "redis-server",
        })
        prompt = build_verdict_prompt(
            redis_cve, _SAMPLE_HOST_STATE,
            network_state=[_SSH_OBSERVATION, _REDIS_OBSERVATION, _CLOSED_OBSERVATION],
        )
        self.assertIn("Redis key-value store", prompt)
        # Closed port has no banner — the fallback filter still keeps it out
        self.assertNotIn('"port": 443', prompt)

    def test_empty_list_shown_as_no_observations(self):
        prompt = build_verdict_prompt(
            _SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE, network_state=[]
        )
        self.assertIn("External-attacker view", prompt)
        self.assertIn("no observations", prompt)

    def test_shown_count_hint_when_filter_dropped_observations(self):
        prompt = build_verdict_prompt(
            _SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE,
            network_state=[_SSH_OBSERVATION, _REDIS_OBSERVATION],
        )
        # Filter kept 1 of 2 — the preamble should say so
        self.assertIn("1 of 2", prompt)


class TestSystemPromptExternalAttackerRule(unittest.TestCase):
    def test_system_prompt_describes_network_state_rule(self):
        # Must mention the section name the user prompt uses, so the model
        # can connect the two.
        self.assertIn("network_state", SYSTEM_PROMPT)
        self.assertIn("External-attacker", SYSTEM_PROMPT)

    def test_system_prompt_still_forbids_exploitation(self):
        """v2 additions must not weaken the defender-only stance."""
        self.assertIn("Never propose exploitation", SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
