"""Tests for the attack-simulator CLI end-to-end (fake engine only)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from attack_simulator.cli import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    build_parser,
    main,
)


CONFIRMED = {
    "cve_id": "CVE-2022-0543",
    "verdict": "CONFIRMED",
    "reason": "Redis 6.2.6 unpatched, reachable, no auth.",
    "evidence": {
        "network_state": "port 6379 reachable:true, banner Redis 6.2.6",
        "package_version": "redis 6.2.6",
    },
}
MITIGATED = {"cve_id": "CVE-X", "verdict": "MITIGATED_BY_CONFIG", "reason": "patched."}


def _write_verdicts(dir_path: Path, verdicts: list[dict]) -> Path:
    p = dir_path / "verdicts.json"
    p.write_text(json.dumps({"schema_version": "v1", "generated_at": "t", "verdicts": verdicts}),
                 encoding="utf-8")
    return p


class ParserTests(unittest.TestCase):
    def test_parser_has_narrate_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["narrate", "--verdicts", "a", "--output", "b"])
        self.assertEqual(args.command, "narrate")
        self.assertEqual(args.engine, "fake")

    def test_parser_accepts_all_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "narrate", "--verdicts", "in.json", "--output", "out.json",
            "--markdown", "out.md", "--target", "eval-db-exposed",
            "--engine", "claude", "--model", "sonnet",
        ])
        self.assertEqual(args.target, "eval-db-exposed")
        self.assertEqual(args.markdown, "out.md")
        self.assertEqual(args.engine, "claude")

    def test_no_command_exits_usage(self) -> None:
        self.assertEqual(main([]), EXIT_USAGE)


class NarrateEndToEndTests(unittest.TestCase):
    def test_narrate_fake_engine_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [CONFIRMED, MITIGATED])
            out_json = td_path / "out.json"
            out_md = td_path / "out.md"

            rc = main([
                "narrate",
                "--verdicts", str(in_path),
                "--output", str(out_json),
                "--markdown", str(out_md),
                "--target", "eval-db-exposed",
                "--engine", "fake",
            ])
            self.assertEqual(rc, EXIT_OK)

            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(len(data["narratives"]), 1)
            self.assertEqual(data["narratives"][0]["cve_id"], "CVE-2022-0543")
            self.assertEqual(data["narratives"][0]["target"], "eval-db-exposed")
            self.assertEqual(data["narratives"][0]["model"], "fake")

            md = out_md.read_text(encoding="utf-8")
            self.assertIn("# Attack narratives", md)
            self.assertIn("CVE-2022-0543", md)
            self.assertIn("eval-db-exposed", md)

    def test_narrate_skips_non_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [MITIGATED])
            out_json = td_path / "out.json"

            rc = main(["narrate", "--verdicts", str(in_path), "--output", str(out_json)])
            self.assertEqual(rc, EXIT_OK)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["narratives"], [])

    def test_narrate_missing_verdicts_file(self) -> None:
        rc = main(["narrate", "--verdicts", "/nonexistent/nope.json", "--output", "/tmp/x.json"])
        self.assertEqual(rc, EXIT_INPUT_ERROR)

    def test_narrate_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("not json{", encoding="utf-8")
            rc = main(["narrate", "--verdicts", str(bad), "--output", str(Path(td) / "o.json")])
            self.assertEqual(rc, EXIT_INPUT_ERROR)

    def test_narrate_accepts_bare_list_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = td_path / "bare.json"
            in_path.write_text(json.dumps([CONFIRMED]), encoding="utf-8")
            out_json = td_path / "out.json"

            rc = main(["narrate", "--verdicts", str(in_path), "--output", str(out_json)])
            self.assertEqual(rc, EXIT_OK)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(len(data["narratives"]), 1)

    def test_narrate_creates_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [CONFIRMED])
            out_json = td_path / "sub" / "dir" / "out.json"
            out_md = td_path / "another" / "dir" / "out.md"

            rc = main([
                "narrate", "--verdicts", str(in_path),
                "--output", str(out_json), "--markdown", str(out_md),
            ])
            self.assertEqual(rc, EXIT_OK)
            self.assertTrue(out_json.exists())
            self.assertTrue(out_md.exists())


if __name__ == "__main__":
    unittest.main()
