"""check_evidence: reasons are checked against what the model was given, and made-up facts are caught."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_evidence import Evidence, check_reason, installed_versions_in, is_loopback, ports_in  # noqa: E402

HOST = {"scanners": {
    "software": {"installed_apps": [{"name": "Apache Druid", "version": "0.20.0"}]},
    "services": {"listening": [
        {"port": 8081, "bind": "::", "pids": [1]},
        {"port": 8888, "bind": "0.0.0.0", "pids": [1]},
        {"port": 1527, "bind": "::ffff:127.0.0.1", "pids": [1]},
    ]},
}}
NET = [
    {"target": "t", "port": 8081, "reachable": True},
    {"target": "t", "port": 8888, "reachable": True},
    {"target": "t", "port": 9999, "reachable": False},
]


def verdicts_of(reason: str):
    return check_reason(reason, Evidence(HOST, NET, "druid 0.20.0"))


def bad(claims):
    return [(c["type"], c["value"]) for c in claims if not c["ok"]]


class ExtractionTests(unittest.TestCase):
    def test_ports(self) -> None:
        self.assertEqual(ports_in("listening on ports 8081, 8082 and 8888"), [8081, 8082, 8888])
        self.assertEqual(ports_in("bound to 0.0.0.0:9000 and 443/tcp"), [443, 9000])
        self.assertEqual(ports_in("CVE-2021-25646 in 0.20.0"), [])

    def test_versions_skip_advisory_data(self) -> None:
        self.assertEqual(installed_versions_in("Installed curl 7.81.0 is affected"), ["7.81.0"])
        self.assertEqual(installed_versions_in("affected range 7.33.0 through 7.82.0"), [])
        self.assertEqual(installed_versions_in("fixed in 2.4.50"), [])
        self.assertEqual(installed_versions_in("(CVSS 9.8) flaw"), [])
        self.assertEqual(installed_versions_in("bound to 0.0.0.0"), [])

    def test_loopback(self) -> None:
        self.assertTrue(is_loopback("::ffff:127.0.0.1"))
        self.assertFalse(is_loopback("::"))


class CheckTests(unittest.TestCase):
    def test_true_claims_pass(self) -> None:
        claims = verdicts_of("Druid 0.20.0 listens on 0.0.0.0 port 8888 and is externally reachable on port 8888.")
        self.assertTrue(claims)
        self.assertEqual(bad(claims), [])

    def test_made_up_port_is_caught(self) -> None:
        self.assertIn(("port", 7777), bad(verdicts_of("Druid listens on port 7777.")))

    def test_unreachable_port_called_reachable_is_caught(self) -> None:
        self.assertIn(("external", 9999), bad(verdicts_of("Port 9999 is externally reachable.")))

    def test_loopback_listener_called_wildcard_is_caught(self) -> None:
        self.assertIn(("bind", 1527), bad(verdicts_of("The service is bound to 0.0.0.0 on port 1527.")))

    def test_made_up_installed_version_is_caught(self) -> None:
        self.assertIn(("version", "9.9.9"), bad(verdicts_of("Installed Druid 9.9.9 is vulnerable.")))

    def test_real_installed_version_passes(self) -> None:
        self.assertEqual(bad(verdicts_of("Installed Druid 0.20.0 is vulnerable.")), [])

    def test_no_network_data_means_no_external_claims(self) -> None:
        claims = check_reason("Port 8081 is externally reachable.", Evidence(HOST, None))
        self.assertEqual([c["type"] for c in claims], ["port"])


if __name__ == "__main__":
    unittest.main()
