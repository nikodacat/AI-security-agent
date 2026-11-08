"""Settings (one place for every tunable) and the budget ordering of candidates."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from exposure_analyzer import settings
from exposure_analyzer.ordering import order_for_budget


class SettingsValues(unittest.TestCase):
    def test_defaults_when_nothing_is_given(self):
        s = settings.build()
        self.assertEqual((s.min_cvss, s.per_product, s.max_per_source, s.max_calls), (7.0, 15, 60, 60))
        self.assertTrue(s.prioritize)
        self.assertFalse(s.use_osv or s.use_nvd or s.use_banner)  # opt-in, as the CLI flags are

    def test_file_then_overrides_and_none_overrides_are_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "scan.json"
            p.write_text(json.dumps({"max_calls": 20, "min_cvss": 9}), encoding="utf-8")
            s = settings.load(p, overrides={"max_calls": 5, "per_product": None})
        self.assertEqual((s.max_calls, s.min_cvss, s.per_product), (5, 9.0, 15))

    def test_unknown_name_is_an_error_not_ignored(self):
        with self.assertRaisesRegex(settings.SettingsError, "unknown setting.*min_cvs\\b"):
            settings.build({"min_cvs": 5})

    def test_out_of_range_wrong_type_and_bad_choice_are_rejected(self):
        for bad in ({"min_cvss": 11}, {"per_product": 0}, {"per_product": 2.5}, {"use_osv": "yes"},
                    {"max_calls": True}, {"engine": "gpt"}, {"engine": 3}):
            with self.assertRaises(settings.SettingsError, msg=str(bad)):
                settings.build(bad)

    def test_zero_means_no_cap_and_is_allowed(self):
        s = settings.build({"max_calls": 0, "max_cost_usd": 0})
        self.assertEqual((s.max_calls, s.max_cost_usd), (0, 0.0))

    def test_unreadable_or_non_object_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text("[1]", encoding="utf-8")
            with self.assertRaises(settings.SettingsError):
                settings.load(p)
            with self.assertRaises(settings.SettingsError):
                settings.load(Path(d) / "missing.json")

    def test_dump_round_trips(self):
        s = settings.build({"max_calls": 7, "model": "qwen"})
        with tempfile.TemporaryDirectory() as d:
            settings.dump(s, Path(d) / "s.json")
            self.assertEqual(settings.load(Path(d) / "s.json"), s)


class SettingsDescription(unittest.TestCase):
    def test_every_field_is_described_with_a_group_and_its_default_is_valid(self):
        rows = settings.describe()
        self.assertEqual({r["name"] for r in rows}, set(settings.to_dict(settings.build())))
        for r in rows:
            self.assertIn(r["group"], {"discovery", "model", "probes"})
            self.assertTrue(r["help"])
            settings.build({r["name"]: r["default"]})  # the default passes its own validation

    def test_description_is_json_serialisable(self):
        json.dumps(settings.describe())


def _c(cve, source, cvss=None):
    c = {"cve_id": cve, "source": source}
    if cvss is not None:
        c["cvss"] = cvss
    return c


class BudgetOrder(unittest.TestCase):
    def test_kev_first_then_sources_in_rotation_by_cvss(self):
        cands = [_c("K1", "inventory"), _c("K2", "banner"),
                 _c("N1", "nvd-cpe", 7.5), _c("N2", "nvd-cpe", 9.8), _c("N3", "nvd-cpe", 8.0),
                 _c("O1", "osv", 7.1), _c("O2", "osv", 9.0)]
        got = [c["cve_id"] for c in order_for_budget(cands)]
        self.assertEqual(got, ["K1", "K2", "N2", "O2", "N3", "O1", "N1"])

    def test_a_budget_cut_still_reaches_every_source(self):
        cands = [_c(f"N{i}", "nvd-cpe", 8.0) for i in range(30)] + [_c(f"O{i}", "osv", 8.0) for i in range(5)]
        head = {c["source"] for c in order_for_budget(cands)[:4]}
        self.assertEqual(head, {"nvd-cpe", "osv"})

    def test_nothing_is_added_or_dropped_and_missing_cvss_sorts_last(self):
        cands = [_c("A", "osv"), _c("B", "osv", 8.0), _c("K", "inventory")]
        out = order_for_budget(cands)
        self.assertEqual(sorted(c["cve_id"] for c in out), ["A", "B", "K"])
        self.assertEqual([c["cve_id"] for c in out], ["K", "B", "A"])

    def test_empty_input(self):
        self.assertEqual(order_for_budget([]), [])


if __name__ == "__main__":
    unittest.main()
