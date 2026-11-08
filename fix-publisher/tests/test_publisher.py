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


class NonAptOriginTests(unittest.TestCase):
    """v3-5: no apt command for software that apt did not install."""

    def _v(self, **kw):
        return {**CONFIRMED, **kw}

    def test_dpkg_package_is_apt_managed(self) -> None:
        from fix_publisher.publisher import non_apt_origin
        self.assertEqual(non_apt_origin(self._v(package_source="dpkg (via host-scanner)")), "")
        self.assertEqual(non_apt_origin(self._v(package_source="dpkg")), "")

    def test_unmanaged_binary_is_not_apt(self) -> None:
        from fix_publisher.publisher import non_apt_origin
        self.assertIn("unmanaged-binary", non_apt_origin(self._v(package_source="unmanaged-binary")))

    def test_osv_library_is_not_apt(self) -> None:
        from fix_publisher.publisher import non_apt_origin
        r = non_apt_origin(self._v(candidate_source="osv", package_source="/app/lib/log4j-core.jar"))
        self.assertIn("log4j-core.jar", r)

    def test_unknown_origin_is_left_to_the_model(self) -> None:
        from fix_publisher.publisher import non_apt_origin
        self.assertEqual(non_apt_origin(self._v()), "")
        self.assertEqual(non_apt_origin(self._v(candidate_source="banner")), "")
        self.assertEqual(non_apt_origin(self._v(candidate_source="banner", package_source="dpkg")), "")

    def test_banner_version_no_apt_package_has_is_not_apt(self) -> None:
        from fix_publisher.publisher import non_apt_origin
        v = self._v(candidate_source="banner", package_source="banner (version not in the apt package list)")
        self.assertIn("no apt package has that version", non_apt_origin(v))

    def test_publish_all_forces_empty_apt_and_flags_it(self) -> None:
        # Even a publisher that wrongly returns an apt command is overridden.
        def wrong(verdict):
            return {"apt_command": "apt install httpd=2.4.51", "config_diff": "no config change needed",
                    "service_restart": "no restart needed", "explanation": "upgrade"}
        rems = FixPublisher(wrong).publish_all([self._v(package_source="unmanaged-binary")])
        self.assertEqual(rems[0].apt_command, "")
        self.assertIn("Not apt-managed", rems[0].explanation)
        self.assertIn("Manual patch required", rems[0].explanation)

    def test_hint_reaches_the_publisher_and_prompt(self) -> None:
        from fix_publisher.prompts import build_remediation_prompt
        seen = {}
        def spy(verdict):
            seen.update(verdict)
            return fake_publisher_fn(verdict)
        FixPublisher(spy).publish_all([self._v(package_source="unmanaged-binary")])
        self.assertTrue(seen.get("not_apt_managed"))
        self.assertIn("NOT APT-MANAGED", build_remediation_prompt(seen))

    def test_apt_managed_verdict_unchanged(self) -> None:
        rems = FixPublisher(fake_publisher_fn).publish_all([self._v(package_source="dpkg")])
        self.assertIn("libssl1.1", rems[0].apt_command)
        self.assertNotIn("Not apt-managed", rems[0].explanation)


class PinVersionTests(unittest.TestCase):
    """An apt pin must be newer than what is installed."""

    def test_debian_version_ordering(self) -> None:
        from fix_publisher.debver import compare
        older_than = [
            ("2.4.38-3+deb10u1", "2.4.38-3+deb10u4"),
            ("1.1.1d-0+deb10u6", "1.1.1n-0+deb10u3"),
            ("1.1.1d-0+deb10u7", "1.1.1d-0+deb10u8"),
            ("6.2.7-1", "5:6.0.16-1+deb11u2"),        # epoch outranks everything
            ("1.0~rc1-1", "1.0-1"),                    # tilde sorts before the end
            ("2.4.9-1", "2.4.10-1"),                   # numeric, not text, comparison
            ("1.0-1", "1.0-1+b1"),
        ]
        for a, b in older_than:
            self.assertEqual(compare(a, b), -1, (a, b))
            self.assertEqual(compare(b, a), 1, (b, a))
        self.assertEqual(compare("1:2.0-1", "1:2.0-1"), 0)
        self.assertEqual(compare("2.0", "0:2.0"), 0)

    def test_pin_not_newer(self) -> None:
        from fix_publisher.publisher import pin_not_newer
        self.assertEqual(pin_not_newer("apt install apache2=2.4.38-3+deb10u1", "2.4.38-3+deb10u4"),
                         "2.4.38-3+deb10u1")
        self.assertEqual(pin_not_newer("apt install apache2=2.4.38-3+deb10u4", "2.4.38-3+deb10u4"),
                         "2.4.38-3+deb10u4")          # equal is not an upgrade
        self.assertEqual(pin_not_newer("apt install libssl1.1=1.1.1n-0+deb10u3", "1.1.1d-0+deb10u6"), "")
        self.assertEqual(pin_not_newer("apt install a=2 b=1", "1.5"), "1")   # any stale pin counts
        self.assertEqual(pin_not_newer("apt install a=1", ""), "")           # installed version unknown
        self.assertEqual(pin_not_newer("", "1.0"), "")

    def test_publish_all_drops_a_pin_that_is_not_newer(self) -> None:
        def stale(verdict):
            return {"apt_command": "apt install apache2=2.4.38-3+deb10u1", "config_diff": "no config change needed",
                    "service_restart": "systemctl restart apache2", "explanation": "fixed per DSA"}
        v = {**CONFIRMED, "package_source": "dpkg", "package_version": "2.4.38-3+deb10u4"}
        r = FixPublisher(stale).publish_all([v])[0]
        self.assertEqual(r.apt_command, "")
        self.assertIn("Version check failed", r.explanation)
        self.assertIn("2.4.38-3+deb10u1", r.explanation)

    def test_newer_pin_is_kept(self) -> None:
        def good(verdict):
            return {"apt_command": "apt install libssl1.1=1.1.1n-0+deb10u3", "config_diff": "no config change needed",
                    "service_restart": "no restart needed", "explanation": "ok"}
        v = {**CONFIRMED, "package_source": "dpkg", "package_version": "1.1.1d-0+deb10u6"}
        r = FixPublisher(good).publish_all([v])[0]
        self.assertEqual(r.apt_command, "apt install libssl1.1=1.1.1n-0+deb10u3")
        self.assertNotIn("Version check failed", r.explanation)

    def test_installed_version_wins_over_the_banner_version(self) -> None:
        # banner says "2.4.38"; the apt package is 2.4.38-3+deb10u4, and the pin is older than that.
        def stale(verdict):
            return {"apt_command": "apt install apache2=2.4.38-3+deb10u1", "config_diff": "no config change needed",
                    "service_restart": "no restart needed", "explanation": "x"}
        v = {**CONFIRMED, "package_source": "dpkg", "package_version": "2.4.38",
             "installed_version": "2.4.38-3+deb10u4"}
        r = FixPublisher(stale).publish_all([v])[0]
        self.assertEqual(r.apt_command, "")
        self.assertIn("installed 2.4.38-3+deb10u4", r.explanation)
