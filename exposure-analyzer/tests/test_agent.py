"""Tests for exposure_analyzer.agent."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposure_analyzer.agent import (
    AgentConfig,
    ExposureAgent,
    _parse_verdict_response,
    build_openai_compatible_verdict_fn,
)
from exposure_analyzer.hitl import ApprovalGate, Decision, load_learned_probes
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

    def test_batch_retries_unparseable_reply_once(self):
        attempts: dict[str, int] = {}

        async def flaky_llm(system_prompt: str, user_prompt: str) -> str:
            cve = user_prompt.splitlines()[0].split()[-1]
            attempts[cve] = attempts.get(cve, 0) + 1
            if cve == "CVE-B" and attempts[cve] == 1:
                return '{"verdict": ...}'  # small local models do this
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "ok"})

        candidates = [dict(_SAMPLE_CANDIDATE, cve_id=c) for c in ("CVE-A", "CVE-B", "CVE-C")]
        agent = ExposureAgent(verdict_fn=flaky_llm, config=AgentConfig(run_probes=False))
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual([v.cve_id for v in verdicts], ["CVE-A", "CVE-B", "CVE-C"])
        self.assertEqual(attempts["CVE-B"], 2)
        self.assertEqual(agent.last_batch_errors, [])

    def test_batch_isolates_a_candidate_that_keeps_failing(self):
        async def llm(system_prompt: str, user_prompt: str) -> str:
            if "CVE-B" in user_prompt.splitlines()[0]:
                return "not json at all"
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "ok"})

        candidates = [dict(_SAMPLE_CANDIDATE, cve_id=c) for c in ("CVE-A", "CVE-B", "CVE-C")]
        agent = ExposureAgent(verdict_fn=llm, config=AgentConfig(run_probes=False))
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        # The failure is reported, not papered over with an invented verdict.
        self.assertEqual([v.cve_id for v in verdicts], ["CVE-A", "CVE-C"])
        self.assertEqual([c for c, _ in agent.last_batch_errors], ["CVE-B"])
        self.assertIn("ValueError", agent.last_batch_errors[0][1])

    def test_batch_isolates_transport_errors_without_retrying(self):
        calls: list[str] = []

        async def llm(system_prompt: str, user_prompt: str) -> str:
            cve = user_prompt.splitlines()[0].split()[-1]
            calls.append(cve)
            if cve == "CVE-B":
                raise RuntimeError("connection reset")
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "ok"})

        candidates = [dict(_SAMPLE_CANDIDATE, cve_id=c) for c in ("CVE-A", "CVE-B", "CVE-C")]
        agent = ExposureAgent(verdict_fn=llm, config=AgentConfig(run_probes=False))
        verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual([v.cve_id for v in verdicts], ["CVE-A", "CVE-C"])
        self.assertEqual(calls.count("CVE-B"), 1)


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


class TestExposureAgentHITL(unittest.TestCase):
    _SAMPLE_PROPOSAL = json.dumps(
        {
            "binary": "python",
            "args": ["--version"],
            "rationale": "check python version",
            "expected_signals": ["Python"],
        }
    )

    def test_approved_proposal_executes(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-NO-PROBE-1")

        async def fake_proposer(cand: dict, host: dict) -> str:
            return self._SAMPLE_PROPOSAL

        seen: dict[str, str] = {}

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            seen["user_prompt"] = user_prompt
            return json.dumps({"verdict": "CONFIRMED", "reason": "probe ran"})

        gate = ApprovalGate(auto_approve_all_unsafe=True, interactive=False)
        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(),
            probe_proposer=fake_proposer,
            approval_gate=gate,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertEqual(verdict.cve_id, "CVE-NO-PROBE-1")
        self.assertEqual(verdict.probe_command, "python --version")
        self.assertIn("Python", verdict.probe_output)
        self.assertIsNotNone(verdict.proposed_probe)
        self.assertEqual(verdict.proposed_probe["binary"], "python")
        self.assertEqual(verdict.proposed_probe["args"], ["--version"])
        self.assertEqual(verdict.probe_proposal_error, "")
        self.assertIn("python --version", seen["user_prompt"])

    def test_denied_proposal_leaves_probe_empty(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-NO-PROBE-2")

        async def fake_proposer(cand: dict, host: dict) -> str:
            return self._SAMPLE_PROPOSAL

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "probe denied"})

        gate = ApprovalGate(interactive=False)
        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(),
            probe_proposer=fake_proposer,
            approval_gate=gate,
        )
        verdict = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))

        self.assertEqual(verdict.cve_id, "CVE-NO-PROBE-2")
        self.assertEqual(verdict.probe_command, "")
        self.assertEqual(verdict.probe_output, "")
        self.assertIsNotNone(verdict.proposed_probe)
        self.assertEqual(verdict.probe_proposal_error, "")

    def test_jsonl_append_behavior_and_idempotency(self):
        candidate = dict(_SAMPLE_CANDIDATE, cve_id="CVE-NO-PROBE-3")

        async def fake_proposer(cand: dict, host: dict) -> str:
            return self._SAMPLE_PROPOSAL

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "CONFIRMED", "reason": "ok"})

        with tempfile.TemporaryDirectory() as td:
            jsonl_path = Path(td) / "learned_probes.jsonl"
            gate = ApprovalGate(auto_approve_all_unsafe=True, interactive=False)
            agent = ExposureAgent(
                verdict_fn=fake_llm,
                config=AgentConfig(),
                probe_proposer=fake_proposer,
                approval_gate=gate,
                learned_probes_path=jsonl_path,
            )

            # First run: appends to JSONL
            verdict1 = _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))
            self.assertEqual(verdict1.probe_command, "python --version")
            self.assertTrue(jsonl_path.exists())
            records = load_learned_probes(jsonl_path)
            self.assertEqual(len(records), 1)

            # Second run with same agent: idempotency check ensures no double append
            _run(agent.analyze(candidate, _SAMPLE_HOST_STATE))
            lines = jsonl_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

            # Run with learned_probes_path=None (--no-learn): does not append
            gate2 = ApprovalGate(auto_approve_all_unsafe=True, interactive=False)
            agent_no_learn = ExposureAgent(
                verdict_fn=fake_llm,
                config=AgentConfig(),
                probe_proposer=fake_proposer,
                approval_gate=gate2,
                learned_probes_path=None,
            )
            _run(agent_no_learn.analyze(candidate, _SAMPLE_HOST_STATE))
            self.assertEqual(len(gate2.learned), 0)
            lines_after = jsonl_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines_after), 1)

    def test_skip_all_denies_subsequent_proposals_in_batch(self):
        candidates = [
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-NO-PROBE-4"),
            dict(_SAMPLE_CANDIDATE, cve_id="CVE-NO-PROBE-5"),
        ]

        async def fake_proposer(cand: dict, host: dict) -> str:
            return self._SAMPLE_PROPOSAL

        async def fake_llm(system_prompt: str, user_prompt: str) -> str:
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "denied"})

        gate = ApprovalGate(interactive=True)
        agent = ExposureAgent(
            verdict_fn=fake_llm,
            config=AgentConfig(),
            probe_proposer=fake_proposer,
            approval_gate=gate,
        )

        with patch("builtins.input", return_value="skip-all") as mock_input:
            verdicts = _run(agent.analyze_batch(candidates, _SAMPLE_HOST_STATE))

        self.assertEqual(len(verdicts), 2)
        self.assertEqual(verdicts[0].probe_command, "")
        self.assertEqual(verdicts[1].probe_command, "")
        self.assertIsNotNone(verdicts[0].proposed_probe)
        self.assertIsNotNone(verdicts[1].proposed_probe)
        mock_input.assert_called_once()


class TestBuildOpenAICompatibleVerdictFn(unittest.TestCase):
    def test_posts_messages_and_returns_content(self):
        import httpx

        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": '{"verdict": "CONFIRMED"}'}}]},
            )

        verdict_fn = build_openai_compatible_verdict_fn(
            base_url="http://192.168.50.55:8080/v1/chat/completions",
            model="qwen",
        )

        # Swap in the mock transport the same way httpx recommends for tests:
        # monkeypatch AsyncClient to route through a MockTransport instead of
        # the network. We do this by patching httpx.AsyncClient's default
        # transport via the `transport=` kwarg path exercised in _call.
        orig_async_client = httpx.AsyncClient

        def _mock_client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return orig_async_client(*args, **kwargs)

        with patch("httpx.AsyncClient", side_effect=_mock_client):
            result = _run(verdict_fn("SYSTEM", "USER"))

        self.assertEqual(result, '{"verdict": "CONFIRMED"}')
        self.assertEqual(captured["url"], "http://192.168.50.55:8080/v1/chat/completions")
        self.assertEqual(captured["body"]["model"], "qwen")
        self.assertEqual(captured["body"]["stream"], False)
        # A runaway generation on a single-slot local server stalls every later request.
        self.assertEqual(captured["body"]["max_tokens"], 2048)
        self.assertEqual(
            captured["body"]["messages"],
            [{"role": "system", "content": "SYSTEM"}, {"role": "user", "content": "USER"}],
        )
        self.assertNotIn("authorization", captured["headers"])

    def test_sends_bearer_token_when_api_key_given(self):
        import httpx

        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        verdict_fn = build_openai_compatible_verdict_fn(
            base_url="http://localhost:8080/v1/chat/completions",
            model="qwen",
            api_key="secret-token",
        )

        orig_async_client = httpx.AsyncClient

        def _mock_client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return orig_async_client(*args, **kwargs)

        with patch("httpx.AsyncClient", side_effect=_mock_client):
            _run(verdict_fn("SYSTEM", "USER"))

        self.assertEqual(captured["headers"]["authorization"], "Bearer secret-token")

    def test_raises_runtime_error_on_http_error_status(self):
        import httpx

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        verdict_fn = build_openai_compatible_verdict_fn(
            base_url="http://localhost:8080/v1/chat/completions",
            model="qwen",
        )

        orig_async_client = httpx.AsyncClient

        def _mock_client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return orig_async_client(*args, **kwargs)

        with patch("httpx.AsyncClient", side_effect=_mock_client):
            with self.assertRaises(httpx.HTTPStatusError):
                _run(verdict_fn("SYSTEM", "USER"))


class TestCallBudget(unittest.TestCase):
    def test_call_limit_blocks_the_next_call(self):
        from exposure_analyzer.agent import BudgetExceeded, CallBudget
        b = CallBudget(max_calls=2)
        b.check(); b.record(None)
        b.check(); b.record(None)
        with self.assertRaises(BudgetExceeded):
            b.check()

    def test_cost_limit_uses_reported_cost(self):
        from exposure_analyzer.agent import BudgetExceeded, CallBudget
        b = CallBudget(max_cost_usd=0.05)
        b.check(); b.record(0.03)
        b.check(); b.record(0.03)  # now 0.06 >= 0.05
        with self.assertRaises(BudgetExceeded):
            b.check()

    def test_no_limits_never_raises(self):
        from exposure_analyzer.agent import CallBudget
        b = CallBudget()
        for _ in range(1000):
            b.check(); b.record(1.0)

    def test_batch_stops_and_keeps_verdicts_so_far(self):
        from exposure_analyzer.agent import CallBudget
        budget = CallBudget(max_calls=2)

        async def verdict_fn(system: str, user: str) -> str:
            budget.check()
            budget.record(None)
            return json.dumps({"verdict": "NO_EVIDENCE", "reason": "r", "evidence": {}})

        agent = ExposureAgent(verdict_fn=verdict_fn, config=AgentConfig(run_probes=False))
        cands = [dict(_SAMPLE_CANDIDATE, cve_id=f"CVE-2020-000{i}") for i in range(5)]
        out = _run(agent.analyze_batch(cands, _SAMPLE_HOST_STATE))
        self.assertEqual([v.cve_id for v in out], ["CVE-2020-0000", "CVE-2020-0001"])
        self.assertIn("call limit 2", agent.stopped_by_budget)
        self.assertEqual(agent.last_batch_errors, [])  # stopping is not a per-CVE failure

    def test_claude_fn_checks_before_and_records_cost_after(self):
        import sys
        import types
        from exposure_analyzer.agent import BudgetExceeded, CallBudget, build_claude_verdict_fn

        class _Opts:
            def __init__(self, **kw): pass

        class ResultMessage:
            total_cost_usd = 0.04

        async def _query(prompt, options):
            yield types.SimpleNamespace(text="{}")
            yield ResultMessage()

        fake = types.SimpleNamespace(query=_query, ClaudeAgentOptions=_Opts)
        budget = CallBudget(max_calls=1)
        with patch.dict(sys.modules, {"claude_agent_sdk": fake}):
            fn = build_claude_verdict_fn(budget)
            _run(fn("S", "U"))
            self.assertEqual((budget.calls, round(budget.cost_usd, 2)), (1, 0.04))
            with self.assertRaises(BudgetExceeded):
                _run(fn("S", "U"))
            self.assertEqual(budget.calls, 1)  # the blocked call was never made


class TestClaudeVerdictFnOptions(unittest.TestCase):
    """The Agent SDK ships Claude Code's tool definitions with every call unless told not to:
    measured 33,542 input tokens for a ~2,000-token prompt, 3,321 with these options."""

    def test_call_is_text_only_one_turn(self):
        import sys
        import types

        seen: dict = {}

        class _Options:
            def __init__(self, **kw):
                seen.update(kw)

        async def _query(prompt, options):
            yield types.SimpleNamespace(text="{}")

        fake = types.SimpleNamespace(query=_query, ClaudeAgentOptions=_Options)
        with patch.dict(sys.modules, {"claude_agent_sdk": fake}):
            from exposure_analyzer.agent import build_claude_verdict_fn
            _run(build_claude_verdict_fn()("SYSTEM", "USER"))

        self.assertEqual(seen["system_prompt"], "SYSTEM")
        self.assertEqual(seen["tools"], [])
        self.assertEqual(seen["setting_sources"], [])
        self.assertEqual(seen["max_turns"], 1)


if __name__ == "__main__":
    unittest.main()
