"""Tests for the fix-publisher CLI end-to-end (fake engine only)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fix_publisher.cli import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    build_parser,
    main,
)


CONFIRMED = {
    "cve_id": "CVE-2022-0778",
    "verdict": "CONFIRMED",
    "reason": "Pre-fix libssl1.1 1.1.1d.",
    "package_name": "libssl1.1",
    "evidence": {"package_version": "libssl1.1 1.1.1d-0+deb10u6"},
}
MITIGATED = {"cve_id": "CVE-X", "verdict": "MITIGATED_BY_CONFIG", "reason": "patched."}


def _write_verdicts(dir_path: Path, verdicts: list[dict]) -> Path:
    p = dir_path / "verdicts.json"
    p.write_text(
        json.dumps({"schema_version": "v1", "generated_at": "t", "verdicts": verdicts}),
        encoding="utf-8",
    )
    return p


class ParserTests(unittest.TestCase):
    def test_publish_subcommand(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["publish", "--verdicts", "a", "--output", "b"])
        self.assertEqual(args.command, "publish")
        self.assertEqual(args.engine, "fake")

    def test_all_flags(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "publish", "--verdicts", "in.json", "--output", "out.json",
            "--markdown", "out.md", "--target", "eval-cms-plugin",
            "--engine", "claude", "--model", "sonnet",
        ])
        self.assertEqual(args.target, "eval-cms-plugin")
        self.assertEqual(args.engine, "claude")

    def test_no_command(self) -> None:
        self.assertEqual(main([]), EXIT_USAGE)


class PublishEndToEndTests(unittest.TestCase):
    def test_publish_fake_writes_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [CONFIRMED, MITIGATED])
            out_json = td_path / "out.json"
            out_md = td_path / "out.md"
            rc = main([
                "publish",
                "--verdicts", str(in_path),
                "--output", str(out_json),
                "--markdown", str(out_md),
                "--target", "eval-cms-plugin",
            ])
            self.assertEqual(rc, EXIT_OK)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(len(data["remediations"]), 1)
            self.assertEqual(data["remediations"][0]["cve_id"], "CVE-2022-0778")
            self.assertEqual(data["remediations"][0]["target"], "eval-cms-plugin")
            self.assertEqual(data["remediations"][0]["model"], "fake")

            md = out_md.read_text(encoding="utf-8")
            self.assertIn("# Remediation drafts", md)
            self.assertIn("CVE-2022-0778", md)
            self.assertIn("eval-cms-plugin", md)
            self.assertIn("### Package update", md)

    def test_publish_skips_non_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [MITIGATED])
            out_json = td_path / "out.json"
            rc = main(["publish", "--verdicts", str(in_path), "--output", str(out_json)])
            self.assertEqual(rc, EXIT_OK)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["remediations"], [])

    def test_missing_verdicts_file(self) -> None:
        rc = main([
            "publish", "--verdicts", "/nonexistent/nope.json", "--output", "/tmp/x.json",
        ])
        self.assertEqual(rc, EXIT_INPUT_ERROR)

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.json"
            bad.write_text("not json{", encoding="utf-8")
            rc = main([
                "publish", "--verdicts", str(bad), "--output", str(Path(td) / "o.json"),
            ])
            self.assertEqual(rc, EXIT_INPUT_ERROR)

    def test_accepts_bare_list_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = td_path / "bare.json"
            in_path.write_text(json.dumps([CONFIRMED]), encoding="utf-8")
            out_json = td_path / "out.json"
            rc = main(["publish", "--verdicts", str(in_path), "--output", str(out_json)])
            self.assertEqual(rc, EXIT_OK)

    def test_creates_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_path = _write_verdicts(td_path, [CONFIRMED])
            out_json = td_path / "sub" / "dir" / "out.json"
            out_md = td_path / "another" / "dir" / "out.md"
            rc = main([
                "publish", "--verdicts", str(in_path),
                "--output", str(out_json), "--markdown", str(out_md),
            ])
            self.assertEqual(rc, EXIT_OK)
            self.assertTrue(out_json.exists())
            self.assertTrue(out_md.exists())


if __name__ == "__main__":
    unittest.main()
