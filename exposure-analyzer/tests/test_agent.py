"""Tests for exposure_analyzer.agent."""

from __future__ import annotations

import asyncio
import json
import unittest

from exposure_analyzer.agent import (
    AgentConfig,
    ExposureAgent,
    _parse_verdict_response,
)
from exposure_analyzer.probes import ProbeTemplate
from exposure_analyzer.verdicts import Verdict, VerdictType


_SAMPLE_CANDIDATE = {
    "cve_id": "CVE-2023-38408",
    "kev_name": "OpenSSH PKCS#11 Vulnerability",
    "package_name": "openssh-server",
    "package_version": "8.5p1",
    "verdict": "vulnerable",
    "verdict_detail": "8.5p1 in affected range",
}

_SAMPLE_HOST_STATE = {"os": "Ubuntu 22.04"}


def _fake_probe_runner(template: ProbeTemplate) -> tuple[str, str]:
    return template.command, "OpenSSH_8.5p1, LibreSSL 3.3.6"


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


class TestParseVerdictResponse(unittest.TestCase):
    def test_plain_json(self):
        raw = json.dumps(
            {"verdict": "CONFIRMED", "reason": "R", "evidence": {"k": "v"}}
        )
        parsed = _parse_verdict_response(raw)
        self.assertEqual(parsed["verdict"], "CONFIRMED")
        self.assertEqual(parsed["evidence"], {"k": "v"})

    def test_code_fenced_json(self):
        raw = '```json\n{"verdict": "NO_EVIDENCE", "reason": "R"}\n```'
        parsed = _parse_verdict_response(raw)
        self.assertEqual(parsed["verdict"], "NO_EVIDENCE")
        self.assertEqual(parsed["evidence"], {})

    def test_json_with_prose_around_it(self):
        raw = 'Sure: {"verdict": "NOT_RUNNING", "reason": "sshd stopped"}. Done.'
        parsed = _parse_verdict_response(raw)
        self.assertEqual(parsed["verdict"], "NOT_RUNNING")

    def test_rejects_unknown_verdict_value(self):
        raw = '{"verdict": "MAYBE", "reason": "..."}'
        with self.assertRaises(ValueError):
            _parse_verdict_response(raw)

    def test_rejects_missing_json(self):
        with self.assertRaises(ValueError):
            _parse_verdict_response("no json here at all")


class TestExposureAgentBatch(unittest.TestCase):
    def test_analyze_runs_probe_when_registered(self):
        seen: dict = {}

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            seen["prompt"] = user_prompt
            return json.dumps(
                {
                    "verdict": "CONFIRMED",
                    "reason": "banner in affected range",
                    "evidence": {"banner": "OpenSSH_8.5p1"},
                }
            )

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(),
            probe_runner=_fake_probe_runner,
        )
        verdict = _run(agent.analyze(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE))

        self.assertEqual(verdict.cve_id, "CVE-2023-38408")
        self.assertIs(verdict.verdict, VerdictType.CONFIRMED)
        self.assertEqual(verdict.probe_command, "ssh -V")
        self.assertIn("OpenSSH_8.5p1", verdict.probe_output)
        self.assertIn("ssh -V", seen["prompt"])

    def test_analyze_skips_probe_when_no_template(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-9999-99999")

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            self.assertIn("(none)", user_prompt)
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "no probe"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(),
            probe_runner=_fake_probe_runner,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertIs(verdict.verdict, VerdictType.NO_EVIDENCE)
        self.assertEqual(verdict.probe_command, "")

    def test_analyze_batch_serial_order(self):
        calls: list[str] = []

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            calls.append(user_prompt.splitlines()[0])
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "..."})

        candidates = [
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-A"),
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-B"),
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-C"),
        ]
        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=False),
        )
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual([v.cve_id for v in verdicts], ["CVE-A", "CVE-B", "CVE-C"])
        self.assertEqual(calls, ["Candidate: CVE-A", "Candidate: CVE-B", "Candidate: CVE-C"])


# --- v2: network_state passthrough -------------------------------------------


class TestExposureAgentNetworkState(unittest.TestCase):
    """The agent's job is to pass network_state through to the prompt, not to
    interpret it. These tests pin down that plumbing so v2-5's per-CVE prompt
    filtering can be tuned in isolation later."""

    _OBS = [
        {
            "target": "eval-web-vuln",
            "port": 22,
            "protocol": "tcp",
            "reachable": True,
            "banner": "OpenSSH 8.5p1 Ubuntu-1ubuntu1",
            "service_guess": {"vendor": "OpenSSH", "product": "OpenSSH", "version": "8.5p1"},
        },
    ]

    def test_analyze_omits_external_section_by_default(self):
        seen: dict = {}

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            seen["prompt"] = user_prompt
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "..."})

        agent = ExposureAgent(verdict_fn=fake_llm, config=AgentConfig(run_probes=False))
        _run(agent.analyze(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE))
        self.assertNotIn("External-attacker view", seen["prompt"])

    def test_analyze_includes_external_section_when_provided(self):
        seen: dict = {}

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            seen["prompt"] = user_prompt
            return json.dumps({"verdict": "CONFIRMED", "reason": "reachable"})

        agent = ExposureAgent(verdict_fn=fake_llm, config=AgentConfig(run_probes=False))
        _run(agent.analyze(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE, network_state=self._OBS))
        self.assertIn("External-attacker view", seen["prompt"])
        self.assertIn("OpenSSH 8.5p1", seen["prompt"])

    def test_analyze_batch_forwards_network_state_to_each_call(self):
        prompts_seen: list[str] = []

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            prompts_seen.append(user_prompt)
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "..."})

        agent = ExposureAgent(verdict_fn=fake_llm, config=AgentConfig(run_probes=False))
        candidates = [
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-A"),
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-B"),
        ]
        _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE, network_state=self._OBS))
        self.assertEqual(len(prompts_seen), 2)
        for p in prompts_seen:
            self.assertIn("External-attacker view", p)


# --- v2-7: dynamic probe proposal --------------------------------------------


class TestExposureAgentDynamicProposal(unittest.TestCase):
    def test_proposer_called_when_no_known_probe(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-9999-9999")
        proposer_calls: list[tuple[dict, dict]] = []

        async def fake_proposer(cand: dict, host: dict) -> str:
            proposer_calls.append((cand, host))
            return json.dumps({
                "binary": "dpkg",
                "args": ["-l", "libssl1.1"],
                "rationale": "check libssl version",
                "expected_signals": ["1.1.1"],
            })

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "no probe executed"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=True),
            probe_proposer=fake_proposer,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertEqual(len(proposer_calls), 1)
        self.assertEqual(proposer_calls[0][0]["cve_id"], "CVE-9999-9999")
        self.assertEqual(verdict.proposed_probe, {
            "binary": "dpkg",
            "args": ["-l", "libssl1.1"],
            "rationale": "check libssl version",
            "expected_signals": ["1.1.1"],
        })
        self.assertEqual(verdict.probe_proposal_error, "")
        # Confirm proposal is not executed
        self.assertEqual(verdict.probe_command, "")

    def test_proposer_not_called_when_known_probe_exists(self):
        # CVE-2023-38408 is in KNOWN_PROBES
        proposer_calls: list[dict] = []

        async def fake_proposer(cand: dict, host: dict) -> str:
            proposer_calls.append(cand)
            return json.dumps({"binary": "should_not_run", "args": []})

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "CONFIRMED", "reason": "ssh banner matches"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=True),
            probe_runner=_fake_probe_runner,
            probe_proposer=fake_proposer,
        )
        verdict = _run(agent.analyze(_SAMPLE_CANDIDATE, _SAMPLE_HOST_STATE))

        self.assertEqual(len(proposer_calls), 0)
        self.assertIsNone(verdict.proposed_probe)
        self.assertEqual(verdict.probe_command, "ssh -V")

    def test_proposer_not_called_when_run_probes_false(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-9999-9999")
        proposer_calls: list[dict] = []

        async def fake_proposer(cand: dict, host: dict) -> str:
            proposer_calls.append(cand)
            return json.dumps({"binary": "echo", "args": ["1"]})

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "no probes"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=False),
            probe_proposer=fake_proposer,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertEqual(len(proposer_calls), 0)
        self.assertIsNone(verdict.proposed_probe)
        self.assertEqual(verdict.probe_proposal_error, "")

    def test_proposer_failure_sets_error_and_does_not_abort_batch(self):
        candidates = [
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-FAIL"),
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-OK"),
        ]

        async def fake_proposer(cand: dict, host: dict) -> str:
            if cand.get("cve_id") == "CVE-FAIL":
                raise RuntimeError("proposer connection reset")
            return json.dumps({
                "binary": "httpd",
                "args": ["-v"],
                "rationale": "check apache",
                "expected_signals": [],
            })

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "test"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=True),
            probe_proposer=fake_proposer,
        )
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual(len(verdicts), 2)
        v_fail = verdicts[0]
        self.assertIsNone(v_fail.proposed_probe)
        self.assertIn("proposer connection reset", v_fail.probe_proposal_error)

        v_ok = verdicts[1]
        self.assertIsNotNone(v_ok.proposed_probe)
        self.assertEqual(v_ok.probe_proposal_error, "")

    def test_proposer_invalid_output_sets_error(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-9999-9999")

        async def fake_proposer(cand: dict, host: dict) -> str:
            # Returns an invalid proposal (shell wrapper)
            return json.dumps({"binary": "bash", "args": ["-c", "whoami"]})

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "test"})

        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(run_probes=True),
            probe_proposer=fake_proposer,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertIsNone(verdict.proposed_probe)
        self.assertIn("is a shell wrapper", verdict.probe_proposal_error)


class TestVerdictProposalRoundTrip(unittest.TestCase):
    def test_verdict_roundtrip_with_proposal(self):
        v = Verdict(
            cve_id="CVE-9999-0001",
            verdict=VerdictType.NO_EVIDENCE,
            reason="pending human review of proposed probe",
            evidence={"note": "evidence"},
            proposed_probe={
                "binary": "redis-cli",
                "args": ["INFO"],
                "rationale": "check version",
                "expected_signals": ["redis_version"],
            },
            probe_proposal_error="",
        )
        d = v.to_dict()
        restored = Verdict.from_dict(d)
        self.assertEqual(restored.proposed_probe, v.proposed_probe)
        self.assertEqual(restored.probe_proposal_error, "")
        self.assertEqual(restored.cve_id, v.cve_id)
        self.assertEqual(restored.verdict, v.verdict)

    def test_verdict_roundtrip_with_proposal_error(self):
        v = Verdict(
            cve_id="CVE-9999-0002",
            verdict=VerdictType.NO_EVIDENCE,
            reason="proposal failed",
            proposed_probe=None,
            probe_proposal_error="binary 'bash' is a shell wrapper; refused",
        )
        d = v.to_dict()
        restored = Verdict.from_dict(d)
        self.assertIsNone(restored.proposed_probe)
        self.assertEqual(restored.probe_proposal_error, "binary 'bash' is a shell wrapper; refused")

    def test_verdict_roundtrip_backward_compat_missing_fields(self):
        # Simulates loading older JSON that didn't have proposed_probe or probe_proposal_error
        old_dict = {
            "cve_id": "CVE-2023-38408",
            "verdict": "CONFIRMED",
            "reason": "older verdict",
            "evidence": {},
            "probe_command": "ssh -V",
            "probe_output": "banner",
            "timestamp": "2026-08-01T00:00:00+00:00",
        }
        restored = Verdict.from_dict(old_dict)
        self.assertIsNone(restored.proposed_probe)
        self.assertEqual(restored.probe_proposal_error, "")


if __name__ == "__main__":
    unittest.main()
