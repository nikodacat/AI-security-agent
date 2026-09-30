"""Tests for the Remediation data model + JSON round-trip + Markdown render."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fix_publisher.remediations import (
    Remediation,
    SCHEMA_VERSION,
    SECTION_MARKER,
    dump_remediations,
    load_remediations,
    render_html_section,
    render_markdown,
)


class RemediationDataclassTests(unittest.TestCase):
    def test_to_dict_round_trip(self) -> None:
        r = Remediation(
            cve_id="CVE-2022-0778",
            target="eval-cms-plugin",
            apt_command="apt install libssl1.1=1.1.1n-0+deb10u6",
            config_diff="no config change needed",
            service_restart="systemctl restart apache2",
            explanation="Upgrades OpenSSL past the BN_mod_sqrt fix.",
            source_verdict_reason="Pre-fix openssl 1.1.1d.",
            generated_at="2026-10-01T10:00:00+00:00",
            model="sonnet",
        )
        self.assertEqual(Remediation.from_dict(r.to_dict()), r)

    def test_from_dict_tolerates_missing_optionals(self) -> None:
        r = Remediation.from_dict({
            "cve_id": "CVE-X", "target": "t",
            "apt_command": "apt install foo=1.0",
            "config_diff": "no config change needed",
            "service_restart": "no restart needed",
            "explanation": "reason",
        })
        self.assertEqual(r.cve_id, "CVE-X")
        self.assertEqual(r.source_verdict_reason, "")
        self.assertEqual(r.generated_at, "")

    def test_frozen(self) -> None:
        r = Remediation(cve_id="X", target="t", apt_command="a", config_diff="c",
                        service_restart="s", explanation="e")
        with self.assertRaises(Exception):
            r.cve_id = "Y"  # type: ignore[misc]


class DumpLoadRoundTripTests(unittest.TestCase):
    def test_dump_load(self) -> None:
        entries = [
            Remediation(cve_id="A", target="h", apt_command="apt install a=1.0",
                        config_diff="no config change needed", service_restart="no restart needed",
                        explanation="fix A"),
            Remediation(cve_id="B", target="h", apt_command="apt install b=2.0",
                        config_diff="no config change needed", service_restart="no restart needed",
                        explanation="fix B"),
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.json"
            dump_remediations(entries, p, generated_at="2026-10-01T10:00:00+00:00")
            reloaded = load_remediations(p)
        self.assertEqual(reloaded, entries)

    def test_dump_writes_schema_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.json"
            dump_remediations([], p, generated_at="t")
            data = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["generated_at"], "t")
        self.assertEqual(data["remediations"], [])

    def test_load_tolerates_bare_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bare.json"
            p.write_text(json.dumps([{
                "cve_id": "X", "target": "t",
                "apt_command": "apt install foo=1.0",
                "config_diff": "no config change needed",
                "service_restart": "no restart needed",
                "explanation": "e",
            }]), encoding="utf-8")
            result = load_remediations(p)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cve_id, "X")

    def test_load_rejects_bad_shape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text('"not a list or dict"', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_remediations(p)

    def test_dump_creates_parent_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nested" / "dir" / "out.json"
            dump_remediations([], p)
            self.assertTrue(p.exists())


class MarkdownRenderTests(unittest.TestCase):
    def _sample(self) -> Remediation:
        return Remediation(
            cve_id="CVE-2022-0778",
            target="eval-cms-plugin",
            apt_command="apt install libssl1.1=1.1.1n-0+deb10u6",
            config_diff="",
            service_restart="systemctl restart apache2",
            explanation="Upgrade OpenSSL past the BN_mod_sqrt fix.",
            source_verdict_reason="Pre-fix libssl1.1 1.1.1d, TLS reachable.",
            generated_at="2026-10-01T10:00:00+00:00",
            model="sonnet",
        )

    def test_scope_line(self) -> None:
        md = render_markdown([self._sample()], generated_at="2026-10-01T10:00:00+00:00")
        self.assertIn("# Remediation drafts", md)
        self.assertIn("Advisory scope: 1 remediation(s)", md)
        self.assertIn("2026-10-01T10:00:00+00:00", md)

    def test_empty_says_nothing_to_remediate(self) -> None:
        md = render_markdown([])
        self.assertIn("no CONFIRMED verdicts", md)

    def test_per_remediation_structure(self) -> None:
        md = render_markdown([self._sample()])
        self.assertIn("## CVE-2022-0778", md)
        self.assertIn("eval-cms-plugin", md)
        self.assertIn("model: sonnet", md)
        # blockquote of verdict reason
        self.assertIn("> Pre-fix libssl1.1 1.1.1d", md)
        # four subsections
        self.assertIn("### Package update", md)
        self.assertIn("### Config change", md)
        self.assertIn("### Service restart", md)
        self.assertIn("### Why this works", md)
        # apt command in bash fence
        self.assertIn("```bash", md)
        self.assertIn("apt install libssl1.1=1.1.1n-0+deb10u6", md)
        # restart command in bash fence
        self.assertIn("systemctl restart apache2", md)
        # empty config renders as italic no-change line
        self.assertIn("no config change needed", md)

    def test_config_diff_rendered_when_present(self) -> None:
        r = self._sample()
        # Cast via replace to get a dataclass-safe copy
        from dataclasses import replace
        r = replace(r, config_diff="- ProtocolVersion 3\n+ ProtocolVersion 4")
        md = render_markdown([r])
        self.assertIn("```diff", md)
        self.assertIn("ProtocolVersion 4", md)

    def test_missing_restart_collapses_to_italic(self) -> None:
        from dataclasses import replace
        r = replace(self._sample(), service_restart="no restart needed")
        md = render_markdown([r])
        self.assertIn("_no restart needed._", md)

    def test_scope_count_reflects_input(self) -> None:
        rems = [self._sample(), self._sample(), self._sample()]
        md = render_markdown(rems)
        self.assertIn("3 remediation(s)", md)


class HtmlSectionTests(unittest.TestCase):
    def _sample(self) -> Remediation:
        return Remediation(
            cve_id="CVE-2022-0778",
            target="eval-cms-plugin",
            apt_command="apt install libssl1.1=1.1.1n-0+deb10u3",
            config_diff="",
            service_restart="systemctl restart apache2",
            explanation="Upgrade OpenSSL past the BN_mod_sqrt fix.",
            source_verdict_reason="Pre-fix libssl1.1 1.1.1d.",
            generated_at="2026-10-01T10:00:00+00:00",
            model="sonnet",
        )

    def test_section_wrapped_in_markers(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertTrue(html_out.startswith(SECTION_MARKER))
        self.assertIn(SECTION_MARKER + " end", html_out)

    def test_uses_host_scanner_card_class(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertIn('class="card"', html_out)
        self.assertIn("<h2>Remediation Drafts</h2>", html_out)

    def test_all_four_subsections_rendered(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertIn("Package update", html_out)
        self.assertIn("Config change", html_out)
        self.assertIn("Service restart", html_out)
        self.assertIn("Why this works", html_out)

    def test_apt_command_rendered_in_code_block(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertIn("apt install libssl1.1=1.1.1n-0+deb10u3", html_out)
        self.assertIn("language-bash", html_out)

    def test_empty_apt_command_shows_muted_line(self) -> None:
        from dataclasses import replace
        r = replace(self._sample(), apt_command="")
        html_out = render_html_section([r])
        self.assertIn("no apt command", html_out)

    def test_empty_config_diff_collapses_to_muted_line(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertIn("no config change needed", html_out)

    def test_config_diff_present_uses_diff_block(self) -> None:
        from dataclasses import replace
        r = replace(self._sample(), config_diff="- old\n+ new")
        html_out = render_html_section([r])
        self.assertIn("language-diff", html_out)
        self.assertIn("+ new", html_out)

    def test_verdict_reason_as_blockquote(self) -> None:
        html_out = render_html_section([self._sample()])
        self.assertIn("<blockquote", html_out)
        self.assertIn("Analyzer verdict", html_out)

    def test_scope_count_matches_input(self) -> None:
        html_out = render_html_section([self._sample(), self._sample()])
        self.assertIn("2 remediation(s)", html_out)

    def test_empty_remediations_shows_placeholder(self) -> None:
        html_out = render_html_section([])
        self.assertIn("no CONFIRMED verdicts", html_out)

    def test_xss_escape_in_apt_command(self) -> None:
        from dataclasses import replace
        r = replace(self._sample(), apt_command='apt install <script>alert(1)</script>')
        html_out = render_html_section([r])
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_xss_escape_in_explanation(self) -> None:
        from dataclasses import replace
        r = replace(self._sample(), explanation='"><img src=x onerror=1>')
        html_out = render_html_section([r])
        self.assertNotIn("<img src=x onerror=1>", html_out)


if __name__ == "__main__":
    unittest.main()
