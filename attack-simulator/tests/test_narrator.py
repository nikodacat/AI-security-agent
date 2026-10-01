"""Tests for AttackSimulator orchestration + fake narrator."""

from __future__ import annotations

import unittest

from attack_simulator.narrator import (
    AttackSimulator,
    fake_narrator_fn,
    narratives_from_verdicts,
)


CONFIRMED_VERDICT = {
    "cve_id": "CVE-2022-0543",
    "verdict": "CONFIRMED",
    "reason": "Redis 6.2.6 unpatched Debian variant, reachable, no auth.",
    "evidence": {
        "network_state": "port 6379 reachable:true, banner Redis 6.2.6",
        "package_version": "redis 6.2.6 upstream image",
    },
}

MITIGATED_VERDICT = {
    "cve_id": "CVE-2014-0160",
    "verdict": "MITIGATED_BY_CONFIG",
    "reason": "OpenSSL 1.1.1n is post-fix.",
}

NOT_RUNNING_VERDICT = {
    "cve_id": "CVE-9999-0000",
    "verdict": "NOT_RUNNING",
    "reason": "Service stopped.",
}


class FakeNarratorTests(unittest.TestCase):
    def test_fake_narrator_produces_three_sections(self) -> None:
        text = fake_narrator_fn(CONFIRMED_VERDICT)
        self.assertIn("### Recon", text)
        self.assertIn("### Discovery", text)
        self.assertIn("### Exploitation", text)

    def test_fake_narrator_references_verdict_evidence(self) -> None:
        text = fake_narrator_fn(CONFIRMED_VERDICT)
        self.assertIn("6379", text)
        self.assertIn("redis 6.2.6", text.lower())
        # Reason echoed too
        self.assertIn("Redis 6.2.6 unpatched", text)

    def test_fake_narrator_tolerates_missing_evidence(self) -> None:
        text = fake_narrator_fn({"cve_id": "CVE-X", "verdict": "CONFIRMED"})
        self.assertIn("### Recon", text)
        # Absence hints present rather than KeyErrors
        self.assertIn("(no network_state evidence recorded)", text)


class AttackSimulatorFilterTests(unittest.TestCase):
    def test_narrate_all_filters_to_confirmed_only(self) -> None:
        sim = AttackSimulator(fake_narrator_fn, target="eval-db-exposed", model="fake")
        results = sim.narrate_all([CONFIRMED_VERDICT, MITIGATED_VERDICT, NOT_RUNNING_VERDICT])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2022-0543")
        self.assertEqual(results[0].target, "eval-db-exposed")
        self.assertEqual(results[0].model, "fake")

    def test_narrate_all_preserves_verdict_order(self) -> None:
        # Two CONFIRMED with a MITIGATED between: the two CONFIRMED should
        # come out in input order.
        v2 = dict(CONFIRMED_VERDICT); v2["cve_id"] = "CVE-2022-24735"
        sim = AttackSimulator(fake_narrator_fn)
        results = sim.narrate_all([CONFIRMED_VERDICT, MITIGATED_VERDICT, v2])
        self.assertEqual([r.cve_id for r in results], ["CVE-2022-0543", "CVE-2022-24735"])

    def test_narrate_all_carries_source_verdict_reason(self) -> None:
        sim = AttackSimulator(fake_narrator_fn)
        results = sim.narrate_all([CONFIRMED_VERDICT])
        self.assertEqual(results[0].source_verdict_reason, CONFIRMED_VERDICT["reason"])

    def test_narrate_all_sets_generated_at(self) -> None:
        sim = AttackSimulator(fake_narrator_fn)
        results = sim.narrate_all([CONFIRMED_VERDICT])
        # ISO 8601 UTC with +00:00 offset
        self.assertTrue(results[0].generated_at.endswith("+00:00"))
        self.assertRegex(results[0].generated_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_narrate_all_empty_input(self) -> None:
        sim = AttackSimulator(fake_narrator_fn)
        self.assertEqual(sim.narrate_all([]), [])

    def test_narrate_all_no_confirmed(self) -> None:
        sim = AttackSimulator(fake_narrator_fn)
        self.assertEqual(sim.narrate_all([MITIGATED_VERDICT, NOT_RUNNING_VERDICT]), [])

    def test_narrator_exception_captured_not_raised(self) -> None:
        def boom(verdict):  # noqa: ANN001, ANN202
            raise RuntimeError("no can do")
        sim = AttackSimulator(boom)
        results = sim.narrate_all([CONFIRMED_VERDICT])
        self.assertEqual(len(results), 1)
        self.assertIn("narrator error", results[0].narrative)
        self.assertIn("RuntimeError", results[0].narrative)


class ConvenienceWrapperTests(unittest.TestCase):
    def test_narratives_from_verdicts_wraps_simulator(self) -> None:
        results = narratives_from_verdicts(
            [CONFIRMED_VERDICT, MITIGATED_VERDICT],
            fake_narrator_fn,
            target="host-x",
            model="fake",
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].target, "host-x")
        self.assertEqual(results[0].model, "fake")


if __name__ == "__main__":
    unittest.main()
