"""Tests for exposure_analyzer.report — HTML injection is idempotent + safe."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from exposure_analyzer.report import (
    append_verdicts_to_report,
    render_verdicts_summary,
)
from exposure_analyzer.verdicts import Verdict, VerdictType


_MINIMAL_REPORT_HTML = """<!DOCTYPE html>
<html><head><title>test</title></head>
<body>
<div class="card"><h2>Existing</h2></div>
</body></html>
"""


def _sample_verdicts() -> list[Verdict]:
    return [
        Verdict(
            cve_id="CVE-2021-42013",
            verdict=VerdictType.CONFIRMED,
            reason="Apache 2.4.49 in range",
            evidence={"banner": "Apache/2.4.49"},
        ),
        Verdict(
            cve_id="CVE-2014-0160",
            verdict=VerdictType.MITIGATED_BY_CONFIG,
            reason="OpenSSL 1.1.1n is post-fix",
            evidence={"pkg": "libssl1.1"},
        ),
    ]


class TestAppendToReport(unittest.TestCase):
    def _write_report(self, td: Path) -> Path:
        p = td / "report.html"
        p.write_text(_MINIMAL_REPORT_HTML, encoding="utf-8")
        return p

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            append_verdicts_to_report([], Path("/no/such/report.html"))

    def test_appends_before_body_close(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            report = self._write_report(td)
            append_verdicts_to_report(_sample_verdicts(), report)

            html = report.read_text(encoding="utf-8")
            self.assertIn("Exposure Verdicts", html)
            self.assertIn("CVE-2021-42013", html)
            self.assertIn("CVE-2014-0160", html)
            # Injected before </body>, not after
            self.assertLess(html.find("Exposure Verdicts"), html.find("</body>"))
            # Original content preserved
            self.assertIn("Existing", html)

    def test_reinjection_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            report = self._write_report(td)
            append_verdicts_to_report(_sample_verdicts(), report)
            append_verdicts_to_report(_sample_verdicts(), report)

            html = report.read_text(encoding="utf-8")
            # Exactly one Exposure Verdicts section, not two stacked
            self.assertEqual(html.count("Exposure Verdicts"), 1)
            # Existing content untouched
            self.assertIn("Existing", html)

    def test_reinjection_replaces_with_fresh_content(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            report = self._write_report(td)

            first_run = [Verdict(cve_id="CVE-OLD-0001", verdict=VerdictType.CONFIRMED,
                                 reason="first", evidence={})]
            append_verdicts_to_report(first_run, report)
            self.assertIn("CVE-OLD-0001", report.read_text(encoding="utf-8"))

            second_run = [Verdict(cve_id="CVE-NEW-0002", verdict=VerdictType.NO_EVIDENCE,
                                  reason="second", evidence={})]
            append_verdicts_to_report(second_run, report)

            html = report.read_text(encoding="utf-8")
            self.assertIn("CVE-NEW-0002", html)
            self.assertNotIn("CVE-OLD-0001", html)  # stale content stripped

    def test_html_special_chars_escaped(self):
        # A verdict reason containing HTML must not break out of the cell.
        verdicts = [Verdict(
            cve_id="CVE-XSS-TEST",
            verdict=VerdictType.NO_EVIDENCE,
            reason="<script>alert('xss')</script>",
            evidence={"raw": "<img src=x onerror=alert(1)>"},
        )]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            report = self._write_report(td)
            append_verdicts_to_report(verdicts, report)

            html = report.read_text(encoding="utf-8")
            # Raw <script> must NOT appear -- it'd execute in a browser
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)

    def test_report_without_body_tag_still_gets_section_appended(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            report = td / "report.html"
            report.write_text("<html><h1>bare</h1></html>", encoding="utf-8")
            append_verdicts_to_report(_sample_verdicts(), report)

            html = report.read_text(encoding="utf-8")
            self.assertIn("Exposure Verdicts", html)


class TestRenderVerdictsSummary(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(render_verdicts_summary([]), "(no verdicts)")

    def test_multiple(self):
        text = render_verdicts_summary(_sample_verdicts())
        self.assertIn("CVE-2021-42013", text)
        self.assertIn("CVE-2014-0160", text)
        self.assertIn("CONFIRMED", text)
        self.assertIn("MITIGATED_BY_CONFIG", text)


if __name__ == "__main__":
    unittest.main()
