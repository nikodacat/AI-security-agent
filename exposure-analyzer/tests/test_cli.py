"""Smoke tests for exposure_analyzer.cli — cover the fake-engine path.

The Claude engine path can't be unit-tested (needs a live claude CLI),
but the fake engine, arg parsing, and file I/O all can. This lifts cli.py
off 0% coverage and catches "did I break the CLI shape" regressions.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from exposure_analyzer.cli import build_parser, main
from exposure_analyzer.hitl import DEFAULT_LEARNED_PROBES_PATH


_SAMPLE_CANDIDATES = {
    "schema_version": 1,
    "source": "test",
    "kev_findings": [
        {
            "cve_id": "CVE-2023-38408",
            "kev_name": "OpenSSH PKCS#11 Vulnerability",
            "kev_vendor": "OpenSSH",
            "kev_product": "OpenSSH",
            "kev_description": "test",
            "package_name": "openssh-server",
            "package_version": "8.5p1",
            "verdict": "vulnerable",
            "verdict_detail": "8.5p1 in affected range",
        }
    ],
}


class TestParser(unittest.TestCase):
    def test_analyze_requires_candidates(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["analyze"])  # no --candidates

    def test_engine_choices(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "--candidates", "x.json",
                                  "--engine", "fake"])
        self.assertEqual(args.engine, "fake")
        with self.assertRaises(SystemExit):
            parser.parse_args(["analyze", "--candidates", "x.json",
                               "--engine", "invalid"])

    def test_propose_probes_flag(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "--candidates", "x.json"])
        self.assertFalse(args.propose_probes)

        args_with = parser.parse_args(["analyze", "--candidates", "x.json", "--propose-probes"])
        self.assertTrue(args_with.propose_probes)

    def test_hitl_flags_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["analyze", "--candidates", "x.json"])
        self.assertFalse(args.auto_approve_known)
        self.assertFalse(args.auto_approve_all_unsafe)
        self.assertEqual(args.learned_probes_path, DEFAULT_LEARNED_PROBES_PATH)
        self.assertFalse(args.no_learn)

    def test_hitl_flags_parsing(self):
        parser = build_parser()
        custom_path = Path("custom/path/learned_probes.jsonl")
        args = parser.parse_args([
            "analyze",
            "--candidates", "x.json",
            "--auto-approve-known",
            "--auto-approve-all-unsafe",
            "--learned-probes-path", str(custom_path),
            "--no-learn",
        ])
        self.assertTrue(args.auto_approve_known)
        self.assertTrue(args.auto_approve_all_unsafe)
        self.assertEqual(args.learned_probes_path, custom_path)
        self.assertTrue(args.no_learn)


class TestFakeEngineEndToEnd(unittest.TestCase):
    def test_fake_engine_writes_verdicts(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            out = td / "verdicts.json"

            rc = main(["analyze",
                       "--candidates", str(cands),
                       "--output", str(out),
                       "--engine", "fake"])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(len(payload["verdicts"]), 1)
            self.assertEqual(payload["verdicts"][0]["cve_id"], "CVE-2023-38408")
            self.assertEqual(payload["verdicts"][0]["verdict"], "CONFIRMED")

    def test_fake_engine_with_propose_probes_flag(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            out = td / "verdicts.json"

            rc = main(["analyze",
                       "--candidates", str(cands),
                       "--output", str(out),
                       "--engine", "fake",
                       "--propose-probes"])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_fake_engine_with_hitl_flags(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            out = td / "verdicts.json"
            learned_path = td / "learned.jsonl"

            rc = main([
                "analyze",
                "--candidates", str(cands),
                "--output", str(out),
                "--engine", "fake",
                "--propose-probes",
                "--auto-approve-known",
                "--auto-approve-all-unsafe",
                "--learned-probes-path", str(learned_path),
                "--no-learn",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_missing_candidates_file_exits_nonzero(self):
        rc = main(["analyze",
                   "--candidates", "/no/such/path/cands.json",
                   "--output", "/tmp/out.json",
                   "--engine", "fake"])
        self.assertEqual(rc, 1)

    def test_missing_host_state_file_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            rc = main(["analyze",
                       "--candidates", str(cands),
                       "--host-state", "/no/such/path/state.json",
                       "--output", str(td / "out.json"),
                       "--engine", "fake"])
            self.assertEqual(rc, 1)


# --- v2: --network-state flag -------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[2]
_NETWORK_STATE_SCHEMA = _REPO_ROOT / "docs" / "schemas" / "network_state.schema.json"
_VALID_OBSERVATIONS: list[dict] = [
    {
        "target": "eval-db-exposed",
        "port": 6379,
        "protocol": "tcp",
        "reachable": True,
        "banner": "Redis key-value store 6.2.6",
        "service_guess": {"vendor": "Redis", "product": "Redis", "version": "6.2.6"},
    },
]


class TestNetworkStateFlag(unittest.TestCase):
    """v2-5: --network-state loads + schema-validates before hand-off to agent.

    All these tests run under the fake engine so we don't need a live Claude
    CLI. The fake engine ignores network_state, but the LOAD path is still
    exercised — that's what we're pinning down here.
    """

    def _run_with_ns(self, td: Path, ns_content: str, extra_args: list[str] | None = None) -> int:
        cands = td / "cands.json"
        cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
        ns = td / "network_state.json"
        ns.write_text(ns_content, encoding="utf-8")
        argv = [
            "analyze",
            "--candidates", str(cands),
            "--output", str(td / "out.json"),
            "--engine", "fake",
            "--network-state", str(ns),
            "--network-state-schema", str(_NETWORK_STATE_SCHEMA),
        ]
        if extra_args:
            argv.extend(extra_args)
        return main(argv)

    def test_missing_network_state_file_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            rc = main([
                "analyze",
                "--candidates", str(cands),
                "--output", str(td / "out.json"),
                "--engine", "fake",
                "--network-state", str(td / "does-not-exist.json"),
            ])
            self.assertEqual(rc, 1)

    def test_invalid_json_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            rc = self._run_with_ns(Path(td), ns_content="{not json")
            self.assertEqual(rc, 1)

    def test_non_list_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            rc = self._run_with_ns(Path(td), ns_content=json.dumps({"observations": []}))
            self.assertEqual(rc, 1)

    def test_schema_violation_exits_1(self):
        """A record missing a required field must fail validation."""
        bad = [{"target": "x", "port": 22, "protocol": "tcp"}]  # missing reachable
        with tempfile.TemporaryDirectory() as td:
            rc = self._run_with_ns(Path(td), ns_content=json.dumps(bad))
            self.assertEqual(rc, 1)

    def test_valid_input_produces_normal_run(self):
        with tempfile.TemporaryDirectory() as td:
            rc = self._run_with_ns(Path(td), ns_content=json.dumps(_VALID_OBSERVATIONS))
            self.assertEqual(rc, 0)
            out = json.loads((Path(td) / "out.json").read_text(encoding="utf-8"))
            # fake engine ignores network_state but still produces verdicts
            self.assertEqual(len(out["verdicts"]), 1)

    def test_missing_schema_file_still_loads_with_warning(self):
        """Operator's schema path may not resolve from cwd; we warn but continue."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cands = td / "cands.json"
            cands.write_text(json.dumps(_SAMPLE_CANDIDATES), encoding="utf-8")
            ns = td / "network_state.json"
            ns.write_text(json.dumps(_VALID_OBSERVATIONS), encoding="utf-8")
            rc = main([
                "analyze",
                "--candidates", str(cands),
                "--output", str(td / "out.json"),
                "--engine", "fake",
                "--network-state", str(ns),
                "--network-state-schema", str(td / "no-such-schema.json"),
            ])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
