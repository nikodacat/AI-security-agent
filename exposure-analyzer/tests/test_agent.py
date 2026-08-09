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
from exposure_analyzer.verdicts import VerdictType


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
            config=AgentConfig(interactive=False),
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
            config=AgentConfig(interactive=False),
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
            config=AgentConfig(interactive=False, run_probes=False),
        )
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual([v.cve_id for v in verdicts], ["CVE-A", "CVE-B", "CVE-C"])
        self.assertEqual(calls, ["Candidate: CVE-A", "Candidate: CVE-B", "Candidate: CVE-C"])


if __name__ == "__main__":
    unittest.main()
