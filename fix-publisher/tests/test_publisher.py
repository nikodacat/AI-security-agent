"""Tests for FixPublisher orchestration + fake publisher."""

from __future__ import annotations

import unittest

from fix_publisher.publisher import (
    FixPublisher,
    fake_publisher_fn,
    remediations_from_verdicts,
)


CONFIRMED = {
    "cve_id": "CVE-2022-0778",
    "verdict": "CONFIRMED",
    "reason": "Pre-fix libssl1.1 1.1.1d, TLS reachable.",
    "package_name": "libssl1.1",
    "evidence": {"package_version": "libssl1.1 1.1.1d-0+deb10u6"},
}
MITIGATED = {"cve_id": "CVE-X", "verdict": "MITIGATED_BY_CONFIG", "reason": "patched"}
NO_EVIDENCE = {"cve_id": "CVE-Y", "verdict": "NO_EVIDENCE", "reason": "unknown"}


class FakePublisherTests(unittest.TestCase):
    def test_fake_returns_expected_keys(self) -> None:
        data = fake_publisher_fn(CONFIRMED)
        self.assertIn("apt_command", data)
        self.assertIn("config_diff", data)
        self.assertIn("service_restart", data)
        self.assertIn("explanation", data)

    def test_fake_uses_package_name_hint(self) -> None:
        data = fake_publisher_fn(CONFIRMED)
        self.assertIn("libssl1.1", data["apt_command"])

    def test_fake_references_verdict_reason(self) -> None:
        data = fake_publisher_fn(CONFIRMED)
        self.assertIn("Pre-fix libssl1.1 1.1.1d", data["explanation"])

    def test_fake_tolerates_missing_evidence(self) -> None:
        data = fake_publisher_fn({"cve_id": "CVE-X", "verdict": "CONFIRMED"})
        # still returns all 4 keys, doesn't KeyError
        for key in ("apt_command", "config_diff", "service_restart", "explanation"):
            self.assertIn(key, data)


class FixPublisherFilterTests(unittest.TestCase):
    def test_publish_all_filters_to_confirmed_only(self) -> None:
        p = FixPublisher(fake_publisher_fn, target="eval-cms-plugin", model="fake")
        results = p.publish_all([CONFIRMED, MITIGATED, NO_EVIDENCE])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2022-0778")
        self.assertEqual(results[0].target, "eval-cms-plugin")
        self.assertEqual(results[0].model, "fake")

    def test_publish_all_preserves_verdict_order(self) -> None:
        v2 = dict(CONFIRMED); v2["cve_id"] = "CVE-Z"
        p = FixPublisher(fake_publisher_fn)
        results = p.publish_all([CONFIRMED, MITIGATED, v2])
        self.assertEqual([r.cve_id for r in results], ["CVE-2022-0778", "CVE-Z"])

    def test_publish_all_carries_source_verdict_reason(self) -> None:
        p = FixPublisher(fake_publisher_fn)
        results = p.publish_all([CONFIRMED])
        self.assertEqual(results[0].source_verdict_reason, CONFIRMED["reason"])

    def test_publish_all_sets_generated_at(self) -> None:
        p = FixPublisher(fake_publisher_fn)
        results = p.publish_all([CONFIRMED])
        self.assertTrue(results[0].generated_at.endswith("+00:00"))
        self.assertRegex(results[0].generated_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_publish_all_empty_input(self) -> None:
        p = FixPublisher(fake_publisher_fn)
        self.assertEqual(p.publish_all([]), [])

    def test_publish_all_no_confirmed(self) -> None:
        p = FixPublisher(fake_publisher_fn)
        self.assertEqual(p.publish_all([MITIGATED, NO_EVIDENCE]), [])

    def test_publisher_exception_captured_not_raised(self) -> None:
        def boom(verdict):  # noqa: ANN001, ANN202
            raise RuntimeError("no can do")
        p = FixPublisher(boom)
        results = p.publish_all([CONFIRMED])
        self.assertEqual(len(results), 1)
        self.assertIn("publisher error", results[0].explanation)
        self.assertIn("RuntimeError", results[0].explanation)

    def test_empty_optional_fields_default_to_no_change(self) -> None:
        # Publisher_fn returns only apt_command + explanation — the others
        # must default to the "no change" sentinels so the report renders cleanly.
        def minimal(verdict):  # noqa: ANN001, ANN202
            return {"apt_command": "apt install foo=1.0", "explanation": "e"}
        p = FixPublisher(minimal)
        results = p.publish_all([CONFIRMED])
        self.assertEqual(results[0].config_diff, "no config change needed")
        self.assertEqual(results[0].service_restart, "no restart needed")


class ConvenienceWrapperTests(unittest.TestCase):
    def test_wraps_publisher(self) -> None:
        results = remediations_from_verdicts(
            [CONFIRMED, MITIGATED], fake_publisher_fn,
            target="host-x", model="fake",
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].target, "host-x")


if __name__ == "__main__":
    unittest.main()
