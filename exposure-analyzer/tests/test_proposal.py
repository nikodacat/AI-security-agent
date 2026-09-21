"""Tests for exposure_analyzer.proposal."""

from __future__ import annotations

import json
import unittest

from exposure_analyzer.proposal import (
    ProposedProbe,
    ProposalValidationError,
    build_proposer_user_prompt,
    parse_proposal,
)


class TestParseProposalHappyPath(unittest.TestCase):
    def test_happy_path(self):
        raw = json.dumps(
            {
                "binary": "httpd",
                "args": ["-v"],
                "rationale": "banner reveals version",
                "expected_signals": [r"Apache/2\.4\.(49|50)"],
            }
        )
        probe = parse_proposal(raw)
        self.assertEqual(probe.binary, "httpd")
        self.assertEqual(probe.args, ("-v",))
        self.assertEqual(probe.rationale, "banner reveals version")
        self.assertEqual(probe.expected_signals, (r"Apache/2\.4\.(49|50)",))

    def test_empty_binary_sentinel(self):
        raw = json.dumps(
            {
                "binary": "",
                "args": [],
                "rationale": "no useful probe available",
                "expected_signals": [],
            }
        )
        probe = parse_proposal(raw)
        self.assertEqual(probe.binary, "")
        self.assertEqual(probe.args, ())
        self.assertEqual(probe.rationale, "no useful probe available")
        self.assertEqual(probe.expected_signals, ())

    def test_code_fence_wrapping(self):
        raw = (
            "```json\n"
            '{"binary": "find", "args": ["/var/log"], "rationale": "check logs", "expected_signals": ["error"]}\n'
            "```"
        )
        probe = parse_proposal(raw)
        self.assertEqual(probe.binary, "find")
        self.assertEqual(probe.args, ("/var/log",))

    def test_prose_wrapping(self):
        raw = (
            "Here's my proposal:\n"
            '{"binary": "dpkg", "args": ["-l", "nginx"], "rationale": "query pkg", "expected_signals": ["nginx"]}\n'
            "Hope that helps."
        )
        probe = parse_proposal(raw)
        self.assertEqual(probe.binary, "dpkg")
        self.assertEqual(probe.args, ("-l", "nginx"))


class TestParseProposalValidationErrors(unittest.TestCase):
    def test_empty_binary_with_nonempty_args(self):
        raw = json.dumps({"binary": "", "args": ["-v"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("empty binary requires empty args", str(cm.exception))

    def test_binary_with_slash(self):
        raw = json.dumps({"binary": "/bin/sh", "args": []})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("illegal characters", str(cm.exception))

    def test_binary_in_shell_wrappers(self):
        raw = json.dumps({"binary": "bash", "args": ["-c", "id"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("is a shell wrapper", str(cm.exception))

    def test_binary_containing_semicolon(self):
        raw = json.dumps({"binary": "echo;rm", "args": []})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("illegal characters", str(cm.exception))

    def test_binary_containing_dollar(self):
        raw = json.dumps({"binary": "$HOME", "args": []})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("illegal characters", str(cm.exception))

    def test_arg_semicolon_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo;bar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_pipe_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo|bar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_redirect_out_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo>bar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_redirect_in_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo<bar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_background_ampersand_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo&bar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_backtick_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo`bar`"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_arg_newline_rejected(self):
        raw = json.dumps({"binary": "find", "args": ["foo\nbar"]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("shell metacharacter", str(cm.exception))

    def test_non_list_args(self):
        raw = json.dumps({"binary": "httpd", "args": "-v"})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("'args' must be a list", str(cm.exception))

    def test_non_string_arg_element(self):
        raw = json.dumps({"binary": "httpd", "args": [123]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("must be a string", str(cm.exception))

    def test_arg_longer_than_max(self):
        raw = json.dumps({"binary": "httpd", "args": ["a" * 201]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("longer than 200 chars", str(cm.exception))

    def test_too_many_args(self):
        raw = json.dumps({"binary": "httpd", "args": ["a"] * 11})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("too many args", str(cm.exception))

    def test_non_list_expected_signals(self):
        raw = json.dumps({"binary": "httpd", "args": [], "expected_signals": "sig"})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("'expected_signals' must be a list", str(cm.exception))

    def test_too_many_expected_signals(self):
        raw = json.dumps({"binary": "httpd", "args": [], "expected_signals": ["s"] * 11})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("too many expected_signals", str(cm.exception))

    def test_signal_longer_than_max(self):
        raw = json.dumps({"binary": "httpd", "args": [], "expected_signals": ["s" * 201]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("longer than 200 chars", str(cm.exception))

    def test_non_string_signal_element(self):
        raw = json.dumps({"binary": "httpd", "args": [], "expected_signals": [42]})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("must be a string", str(cm.exception))

    def test_rationale_longer_than_max(self):
        raw = json.dumps({"binary": "httpd", "args": [], "rationale": "r" * 501})
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(raw)
        self.assertIn("rationale longer than 500 chars", str(cm.exception))

    def test_bare_non_json_string(self):
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal("not valid json at all")
        self.assertIn("no JSON object with 'binary' key found", str(cm.exception))

    def test_no_binary_key_present(self):
        with self.assertRaises(ProposalValidationError) as cm:
            parse_proposal(json.dumps({"command": "httpd -v"}))
        self.assertIn("no JSON object with 'binary' key found", str(cm.exception))


class TestProposedProbeDataClass(unittest.TestCase):
    def test_roundtrip_to_dict_from_dict(self):
        probe = ProposedProbe(
            binary="redis-cli",
            args=("-h", "127.0.0.1", "INFO", "server"),
            rationale="exposes redis_version",
            expected_signals=(r"redis_version:6\.2\.[0-6]",),
        )
        d = probe.to_dict()
        self.assertEqual(d["binary"], "redis-cli")
        self.assertEqual(d["args"], ["-h", "127.0.0.1", "INFO", "server"])
        self.assertEqual(d["rationale"], "exposes redis_version")
        self.assertEqual(d["expected_signals"], [r"redis_version:6\.2\.[0-6]"])

        roundtripped = ProposedProbe.from_dict(d)
        self.assertEqual(roundtripped, probe)

    def test_build_proposer_user_prompt(self):
        candidate = {"cve_id": "CVE-2024-1234", "package_name": "foo"}
        host_state = {"os": "Linux"}
        prompt = build_proposer_user_prompt(candidate, host_state)
        self.assertIn("Candidate: CVE-2024-1234", prompt)
        self.assertIn("CVE metadata:", prompt)
        self.assertIn("Host inventory (from host-scanner):", prompt)
        self.assertIn("Linux", prompt)


if __name__ == "__main__":
    unittest.main()
