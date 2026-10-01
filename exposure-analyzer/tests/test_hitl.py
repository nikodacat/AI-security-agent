"""Tests for exposure_analyzer.hitl."""

from __future__ import annotations

import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposure_analyzer.hitl import (
    ApprovalGate,
    Decision,
    LearnedProbeRecord,
    append_learned_probe,
    argv_hash,
    build_probe_argv,
    load_learned_probes,
    make_learned_record,
    stdin_is_tty,
)
from exposure_analyzer.proposal import ProposedProbe


class TestArgvHash(unittest.TestCase):
    def test_argv_hash_collision_resistance(self):
        h1 = argv_hash("find", ("foo", "bar"))
        h2 = argv_hash("find", ("foobar",))
        self.assertNotEqual(h1, h2)

    def test_argv_hash_deterministic(self):
        h1 = argv_hash("httpd", ("-v",))
        h2 = argv_hash("httpd", ("-v",))
        self.assertEqual(h1, h2)

    def test_argv_hash_output_shape(self):
        h = argv_hash("redis-cli", ["INFO"])
        self.assertTrue(h.startswith("sha256:"))
        hex_part = h.split(":", 1)[1]
        self.assertEqual(len(hex_part), 64)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", hex_part) is not None)


class TestLearnedProbeRecord(unittest.TestCase):
    def test_record_to_json_line_and_from_json_roundtrip(self):
        rec = LearnedProbeRecord(
            argv_hash="sha256:1234567890abcdef",
            binary="httpd",
            args=("-v",),
            rationale="check apache version",
            expected_signals=(r"Apache/2\.4",),
            first_seen_cve="CVE-2021-41773",
            approved_at="2026-09-24T00:00:00+00:00",
            approved_by="operator",
        )
        line = rec.to_json_line()
        self.assertNotIn("\n", line)
        import json
        d = json.loads(line)
        restored = LearnedProbeRecord.from_json(d)
        self.assertEqual(restored, rec)

    def test_make_learned_record(self):
        prop = ProposedProbe(
            binary="python",
            args=("--version",),
            rationale="test rationale",
            expected_signals=("Python 3",),
        )
        rec = make_learned_record(prop, cve_id="CVE-2023-0001", approved_by="operator")
        self.assertEqual(rec.binary, "python")
        self.assertEqual(rec.args, ("--version",))
        self.assertEqual(rec.first_seen_cve, "CVE-2023-0001")
        self.assertEqual(rec.approved_by, "operator")
        self.assertEqual(rec.argv_hash, argv_hash("python", ("--version",)))
        self.assertTrue(rec.approved_at)


class TestLearnedProbesPersistence(unittest.TestCase):
    def test_load_missing_file_returns_empty_dict(self):
        p = Path("/path/that/does/not/exist/learned_probes.jsonl")
        res = load_learned_probes(p)
        self.assertEqual(res, {})

    def test_load_malformed_line_warns_and_skips(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "learned_probes.jsonl"
            rec1 = LearnedProbeRecord(
                argv_hash="sha256:aaa",
                binary="b1",
                args=("a1",),
                rationale="r1",
                expected_signals=(),
                first_seen_cve="CVE-1",
                approved_at="2026-09-24T00:00:00+00:00",
                approved_by="operator",
            )
            rec2 = LearnedProbeRecord(
                argv_hash="sha256:bbb",
                binary="b2",
                args=("a2",),
                rationale="r2",
                expected_signals=(),
                first_seen_cve="CVE-2",
                approved_at="2026-09-24T00:00:00+00:00",
                approved_by="operator",
            )
            content = f"{rec1.to_json_line()}\n{{broken json\n{rec2.to_json_line()}\n"
            path.write_text(content, encoding="utf-8")

            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                loaded = load_learned_probes(path)

            self.assertEqual(len(loaded), 2)
            self.assertIn("sha256:aaa", loaded)
            self.assertIn("sha256:bbb", loaded)
            stderr_val = err_buf.getvalue()
            self.assertIn("skipping malformed JSON", stderr_val)
            self.assertIn("line 2", stderr_val)

    def test_load_line_missing_argv_hash_warns_and_skips(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "learned_probes.jsonl"
            content = '{"binary": "b1", "args": []}\n'
            path.write_text(content, encoding="utf-8")

            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                loaded = load_learned_probes(path)

            self.assertEqual(loaded, {})
            self.assertIn("skipping row without argv_hash", err_buf.getvalue())

    def test_append_learned_probe_creates_file_and_appends(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sub" / "learned_probes.jsonl"
            rec1 = LearnedProbeRecord(
                argv_hash="sha256:111",
                binary="b1",
                args=(),
                rationale="r1",
                expected_signals=(),
                first_seen_cve="CVE-1",
                approved_at="2026-09-24T00:00:00+00:00",
                approved_by="operator",
            )
            append_learned_probe(path, rec1)
            self.assertTrue(path.exists())
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

            rec2 = LearnedProbeRecord(
                argv_hash="sha256:222",
                binary="b2",
                args=(),
                rationale="r2",
                expected_signals=(),
                first_seen_cve="CVE-2",
                approved_at="2026-09-24T00:00:00+00:00",
                approved_by="operator",
            )
            append_learned_probe(path, rec2)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)


class TestApprovalGate(unittest.TestCase):
    def setUp(self):
        self.sample_proposal = ProposedProbe(
            binary="httpd",
            args=("-v",),
            rationale="check version",
            expected_signals=(r"Apache/2\.4",),
        )

    def test_empty_binary_proposal_denied_without_prompt(self):
        gate = ApprovalGate()
        empty_prop = ProposedProbe(
            binary="",
            args=(),
            rationale="no useful probe",
            expected_signals=(),
        )
        decision, approver = gate.decide(empty_prop, "CVE-2023-0001")
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(approver, "")

    def test_auto_approve_all_unsafe(self):
        gate = ApprovalGate(auto_approve_all_unsafe=True, interactive=False)
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.APPROVE)
        self.assertEqual(approver, "auto-approve-all-unsafe")

    def test_auto_approve_known_matching_hash(self):
        h = argv_hash(self.sample_proposal.binary, self.sample_proposal.args)
        rec = LearnedProbeRecord(
            argv_hash=h,
            binary=self.sample_proposal.binary,
            args=self.sample_proposal.args,
            rationale="cached",
            expected_signals=(),
            first_seen_cve="CVE-OLD",
            approved_at="2026-09-24T00:00:00+00:00",
            approved_by="operator",
        )
        gate = ApprovalGate(
            learned={h: rec},
            auto_approve_known=True,
            interactive=False,
        )
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.APPROVE)
        self.assertEqual(approver, "auto-approve-known")

    def test_auto_approve_known_no_matching_hash_non_interactive(self):
        gate = ApprovalGate(
            learned={},
            auto_approve_known=True,
            interactive=False,
        )
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(approver, "")

    @patch("builtins.input", return_value="y")
    def test_interactive_prompt_approves_on_y(self, mock_input):
        gate = ApprovalGate(interactive=True)
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.APPROVE)
        self.assertEqual(approver, "operator")
        mock_input.assert_called_once()

    @patch("builtins.input", return_value="")
    def test_interactive_prompt_denies_on_empty(self, mock_input):
        gate = ApprovalGate(interactive=True)
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(approver, "")

    @patch("builtins.input", return_value="n")
    def test_interactive_prompt_denies_on_n(self, mock_input):
        gate = ApprovalGate(interactive=True)
        decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(approver, "")

    @patch("builtins.input", return_value="skip-all")
    def test_interactive_prompt_skip_all_latches(self, mock_input):
        gate = ApprovalGate(interactive=True)
        decision1, approver1 = gate.decide(self.sample_proposal, "CVE-2023-0001")
        self.assertEqual(decision1, Decision.DENY)
        self.assertEqual(approver1, "")

        # Second proposal should be denied immediately without prompting
        decision2, approver2 = gate.decide(self.sample_proposal, "CVE-2023-0002")
        self.assertEqual(decision2, Decision.DENY)
        self.assertEqual(approver2, "")
        mock_input.assert_called_once()

    def test_interactive_prompt_garbage_then_y_reprompts(self):
        responses = ["what?", "y"]
        call_count = 0

        def fake_input(prompt: str = "") -> str:
            nonlocal call_count
            ans = responses[call_count]
            call_count += 1
            return ans

        gate = ApprovalGate(interactive=True)
        with patch("builtins.input", side_effect=fake_input):
            decision, approver = gate.decide(self.sample_proposal, "CVE-2023-0001")

        self.assertEqual(call_count, 2)
        self.assertEqual(decision, Decision.APPROVE)
        self.assertEqual(approver, "operator")

    def test_interactive_prompt_eof_denies_and_latches(self):
        gate = ApprovalGate(interactive=True)
        with patch("builtins.input", side_effect=EOFError):
            decision1, approver1 = gate.decide(self.sample_proposal, "CVE-2023-0001")

        self.assertEqual(decision1, Decision.DENY)
        self.assertEqual(approver1, "")

        # Subsequent call should return DENY without prompting
        with patch("builtins.input", side_effect=AssertionError("should not be called")):
            decision2, approver2 = gate.decide(self.sample_proposal, "CVE-2023-0002")
        self.assertEqual(decision2, Decision.DENY)
        self.assertEqual(approver2, "")


class TestBuildProbeArgv(unittest.TestCase):
    def test_without_target_container(self):
        prop = ProposedProbe("httpd", ("-v",), "rationale", ())
        argv = build_probe_argv(prop, target_container=None)
        self.assertEqual(argv, ["httpd", "-v"])

    def test_with_target_container(self):
        prop = ProposedProbe("httpd", ("-v",), "rationale", ())
        argv = build_probe_argv(prop, target_container="eval-web-vuln")
        self.assertEqual(argv, ["docker", "exec", "eval-web-vuln", "httpd", "-v"])


class TestStdinIsTty(unittest.TestCase):
    def test_stdin_is_tty_returns_bool(self):
        res = stdin_is_tty()
        self.assertIsInstance(res, bool)


if __name__ == "__main__":
    unittest.main()
