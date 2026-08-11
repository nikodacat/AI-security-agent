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


if __name__ == "__main__":
    unittest.main()
