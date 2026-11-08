"""Security checks: every scanner finding id gets a hint, and the report block is safe + idempotent."""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

from fix_publisher import hardening
from fix_publisher.hardening import HINTS, collect_findings, hint_for, render_html_section

_REPO = Path(__file__).resolve().parents[2]


def _scan(posture=(), leaks=()):
    return {"scanners": {"posture": {"findings": list(posture)}, "leaks": {"findings": list(leaks)}}}


def _f(fid, sev="low", title="t", ev="e"):
    return {"id": fid, "severity": sev, "title": title, "evidence": ev}


class HintTests(unittest.TestCase):
    def test_every_id_the_scanners_can_emit_has_a_hint(self) -> None:
        """Ids are read from the scanner sources, so a new finding without a hint fails here."""
        ids: set[str] = set()
        for name in ("posture.py", "leaks.py"):
            src = (_REPO / "host-scanner" / "scanners" / name).read_text(encoding="utf-8")
            ids |= set(re.findall(r'Finding\(\s*"([a-z0-9-]+)"', src))
            ids |= set(re.findall(r'"(leak-[a-z0-9-]+)"', src))
        ids -= {"leak"}  # a dict key, not a finding id
        self.assertGreater(len(ids), 20)
        missing = sorted(i for i in ids if i not in HINTS)
        self.assertEqual(missing, [])

    def test_known_id(self) -> None:
        self.assertIn("PermitRootLogin", hint_for("ssh-root-login"))

    def test_sysctl_prefix_names_the_key(self) -> None:
        h = hint_for("sysctl-kernel-dmesg_restrict")
        self.assertIn("kernel.dmesg_restrict", h)
        self.assertIn("kernel.yama.ptrace_scope", hint_for("sysctl-kernel-yama-ptrace_scope"))

    def test_truncated_and_unknown_ids_still_get_text(self) -> None:
        self.assertIn("More findings", hint_for("leak-backup-truncated"))
        self.assertEqual(hint_for("brand-new-check"), hardening._GENERIC_HINT)

    def test_hints_are_single_lines(self) -> None:
        for fid, h in HINTS.items():
            self.assertNotIn("\n", h, fid)
            self.assertTrue(h.strip(), fid)


class CollectTests(unittest.TestCase):
    def test_sorted_by_severity_and_labelled_by_source(self) -> None:
        out = collect_findings(_scan([_f("os-eol", "low"), _f("ssh-root-login", "high")], [_f("leak-dotenv", "medium")]))
        self.assertEqual([f["id"] for f in out], ["ssh-root-login", "leak-dotenv", "os-eol"])
        self.assertEqual({f["id"]: f["source"] for f in out}["leak-dotenv"], "leaks")
        self.assertTrue(all(f["hint"] for f in out))

    def test_missing_or_broken_scanner_data_is_tolerated(self) -> None:
        self.assertEqual(collect_findings({}), [])
        self.assertEqual(collect_findings({"scanners": {"posture": None, "leaks": {"status": "error"}}}), [])
        self.assertEqual(collect_findings(_scan([{"severity": "low"}, "junk"])), [])


class RenderTests(unittest.TestCase):
    def test_escapes_fields(self) -> None:
        out = render_html_section(collect_findings(_scan([_f("x", "high", "<script>alert(1)</script>", "a&b")])))
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("a&amp;b", out)

    def test_empty_and_markers(self) -> None:
        out = render_html_section([])
        self.assertIn("(no findings)", out)
        self.assertTrue(out.startswith(hardening.SECTION_MARKER))
        self.assertTrue(out.endswith(hardening.SECTION_MARKER.replace("-->", "end -->")))

    def test_marker_matches_the_one_report_py_strips(self) -> None:
        sys.path.insert(0, str(_REPO / "exposure-analyzer"))
        from exposure_analyzer import report
        self.assertEqual(hardening.SECTION_MARKER, report._SECURITY_CHECKS_MARKER)


if __name__ == "__main__":
    unittest.main()
