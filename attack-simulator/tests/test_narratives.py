"""Tests for the Narrative data model + JSON round-trip + Markdown render."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from attack_simulator.narratives import (
    Narrative,
    SCHEMA_VERSION,
    SECTION_MARKER,
    dump_narratives,
    load_narratives,
    render_html_section,
    render_markdown,
)


class NarrativeDataclassTests(unittest.TestCase):
    def test_narrative_to_dict_round_trip(self) -> None:
        n = Narrative(
            cve_id="CVE-2022-0543",
            target="eval-db-exposed",
            narrative="body",
            source_verdict_reason="reason",
            generated_at="2026-09-30T15:00:00+00:00",
            model="sonnet",
        )
        self.assertEqual(Narrative.from_dict(n.to_dict()), n)

    def test_narrative_from_dict_tolerates_missing_optional_fields(self) -> None:
        # Only cve_id, target, narrative required semantically. Empty defaults elsewhere.
        n = Narrative.from_dict({"cve_id": "CVE-X", "target": "t", "narrative": "b"})
        self.assertEqual(n.cve_id, "CVE-X")
        self.assertEqual(n.target, "t")
        self.assertEqual(n.narrative, "b")
        self.assertEqual(n.source_verdict_reason, "")
        self.assertEqual(n.generated_at, "")
        self.assertEqual(n.model, "")

    def test_narrative_is_frozen(self) -> None:
        n = Narrative(cve_id="X", target="t", narrative="b")
        with self.assertRaises(Exception):
            n.cve_id = "Y"  # type: ignore[misc]


class DumpLoadRoundTripTests(unittest.TestCase):
    def test_dump_load_round_trip(self) -> None:
        entries = [
            Narrative(cve_id="CVE-A", target="host1", narrative="A body", model="sonnet"),
            Narrative(cve_id="CVE-B", target="host1", narrative="B body", model="sonnet"),
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.json"
            dump_narratives(entries, p, generated_at="2026-09-30T15:00:00+00:00")
            reloaded = load_narratives(p)
        self.assertEqual(reloaded, entries)

    def test_dump_writes_schema_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.json"
            dump_narratives([], p, generated_at="2026-09-30T15:00:00+00:00")
            data = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["generated_at"], "2026-09-30T15:00:00+00:00")
        self.assertEqual(data["narratives"], [])

    def test_load_tolerates_bare_list_format(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bare.json"
            p.write_text(
                json.dumps([{"cve_id": "CVE-X", "target": "t", "narrative": "b"}]),
                encoding="utf-8",
            )
            result = load_narratives(p)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cve_id, "CVE-X")

    def test_load_rejects_unrecognized_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text('"just a string"', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_narratives(p)

    def test_dump_creates_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nested" / "dir" / "out.json"
            dump_narratives([], p)
            self.assertTrue(p.exists())


class MarkdownRenderTests(unittest.TestCase):
    def test_render_markdown_includes_scope_line(self) -> None:
        md = render_markdown([], generated_at="2026-09-30T15:00:00+00:00")
        self.assertIn("# Attack narratives", md)
        self.assertIn("Advisory scope: 0 narrative(s)", md)
        self.assertIn("No exploit code", md)
        self.assertIn("2026-09-30T15:00:00+00:00", md)

    def test_render_markdown_empty_says_nothing_to_narrate(self) -> None:
        md = render_markdown([])
        self.assertIn("no CONFIRMED verdicts", md)

    def test_render_markdown_per_narrative_structure(self) -> None:
        n = Narrative(
            cve_id="CVE-2022-0543",
            target="eval-db-exposed",
            narrative="### Recon\nfoo\n### Discovery\nbar\n### Exploitation\nbaz",
            source_verdict_reason="Redis 6.2.6 running unpatched",
            generated_at="2026-09-30T15:00:00+00:00",
            model="sonnet",
        )
        md = render_markdown([n])
        # heading contains both cve_id and target
        self.assertIn("## CVE-2022-0543", md)
        self.assertIn("eval-db-exposed", md)
        # metadata line
        self.assertIn("2026-09-30T15:00:00+00:00", md)
        self.assertIn("model: sonnet", md)
        # verdict reason rendered as blockquote
        self.assertIn("> Redis 6.2.6 running unpatched", md)
        # narrative body preserved
        self.assertIn("### Recon", md)
        self.assertIn("### Exploitation", md)

    def test_render_markdown_scopes_narrative_count_correctly(self) -> None:
        entries = [
            Narrative(cve_id="A", target="t", narrative="x"),
            Narrative(cve_id="B", target="t", narrative="y"),
            Narrative(cve_id="C", target="t", narrative="z"),
        ]
        md = render_markdown(entries)
        self.assertIn("3 narrative(s)", md)

    def test_render_markdown_omits_metadata_line_when_empty(self) -> None:
        # No generated_at, no model set — the metadata italic line should be absent.
        n = Narrative(cve_id="X", target="t", narrative="body")
        md = render_markdown([n])
        # No "_·_" bits present
        self.assertNotIn("model:", md)


class HtmlSectionTests(unittest.TestCase):
    def _sample(self) -> Narrative:
        return Narrative(
            cve_id="CVE-2022-0543",
            target="eval-db-exposed",
            narrative=(
                "### Recon\nAttacker scans and finds port 6379 open.\n\n"
                "### Discovery\nBanner confirms Redis 6.2.6.\n\n"
                "### Exploitation\nLua sandbox escape leads to code exec."
            ),
            source_verdict_reason="Redis 6.2.6 unpatched.",
            generated_at="2026-10-01T10:00:00+00:00",
            model="sonnet",
        )

    def test_section_wrapped_in_markers(self) -> None:
        html = render_html_section([self._sample()])
        self.assertTrue(html.startswith(SECTION_MARKER))
        self.assertIn(SECTION_MARKER + " end", html)

    def test_uses_host_scanner_card_class(self) -> None:
        html = render_html_section([self._sample()])
        self.assertIn('class="card"', html)
        self.assertIn("<h2>Attack Narratives</h2>", html)

    def test_scope_line_reflects_count(self) -> None:
        html = render_html_section([self._sample(), self._sample()])
        self.assertIn("2 narrative(s)", html)

    def test_empty_narratives_shows_placeholder(self) -> None:
        html = render_html_section([])
        self.assertIn("no CONFIRMED verdicts", html)

    def test_three_section_headings_rendered_as_h4(self) -> None:
        html = render_html_section([self._sample()])
        self.assertIn("<h4", html)
        self.assertIn("Recon", html)
        self.assertIn("Discovery", html)
        self.assertIn("Exploitation", html)

    def test_verdict_reason_rendered_as_blockquote(self) -> None:
        html = render_html_section([self._sample()])
        self.assertIn("<blockquote", html)
        self.assertIn("Analyzer verdict", html)
        self.assertIn("Redis 6.2.6 unpatched", html)

    def test_generated_at_shown_in_scope_line(self) -> None:
        html = render_html_section([self._sample()], generated_at="2026-10-01T10:00:00+00:00")
        self.assertIn("2026-10-01T10:00:00+00:00", html)

    def test_xss_escape_in_cve_id(self) -> None:
        n = Narrative(cve_id="<script>alert(1)</script>", target="t", narrative="body")
        html = render_html_section([n])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_xss_escape_in_narrative_body(self) -> None:
        n = Narrative(
            cve_id="CVE-X", target="t",
            narrative="### Recon\n<img src=x onerror=alert(1)>",
        )
        html = render_html_section([n])
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)

    def test_xss_escape_in_verdict_reason(self) -> None:
        n = Narrative(
            cve_id="X", target="t", narrative="body",
            source_verdict_reason='"><script>bad</script>',
        )
        html = render_html_section([n])
        self.assertNotIn("<script>bad</script>", html)


if __name__ == "__main__":
    unittest.main()
