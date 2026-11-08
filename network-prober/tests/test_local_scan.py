"""Scanning this computer itself needs a connect scan (nmap's SYN scan cannot do it on Windows)."""

from __future__ import annotations

import socket
import unittest
from unittest import mock

from network_prober.prober import _build_arguments, is_this_machine, scan_targets


class _FakeScanner:
    seen: list[tuple[str, str]] = []

    def scan(self, hosts, arguments):
        _FakeScanner.seen.append((hosts, arguments))

    def all_hosts(self):
        return []


class IsThisMachineTests(unittest.TestCase):
    def test_loopback_and_localhost(self) -> None:
        for t in ("localhost", "LOCALHOST", "127.0.0.1", "127.5.6.7", "::1", " 127.0.0.1 "):
            self.assertTrue(is_this_machine(t), t)

    def test_own_address_is_this_machine(self) -> None:
        with mock.patch.object(socket, "gethostbyname_ex", return_value=("h", [], ["192.168.50.69"])):
            self.assertTrue(is_this_machine("192.168.50.69"))

    def test_other_hosts_are_not(self) -> None:
        with mock.patch.object(socket, "gethostbyname_ex", return_value=("h", [], ["192.168.50.69"])), \
             mock.patch.object(socket, "gethostbyname", side_effect=lambda h: h):
            for t in ("192.168.50.70", "203.0.113.5", "10.0.0.1"):
                self.assertFalse(is_this_machine(t), t)

    def test_unresolvable_name_is_not(self) -> None:
        with mock.patch.object(socket, "gethostbyname_ex", side_effect=OSError):
            self.assertFalse(is_this_machine("no-such-host.invalid"))


class ArgumentTests(unittest.TestCase):
    def test_connect_scan_is_added_only_when_asked(self) -> None:
        self.assertNotIn("-sT", _build_arguments(100, 60))
        self.assertTrue(_build_arguments(100, 60, connect_scan=True).startswith("-sT -sV"))
        self.assertIn("-p 8791", _build_arguments(100, 60, ports="8791", connect_scan=True))

    def test_each_target_gets_its_own_scan_type(self) -> None:
        _FakeScanner.seen = []
        with mock.patch.object(socket, "gethostbyname_ex", return_value=("h", [], ["192.168.50.69"])), \
             mock.patch.object(socket, "gethostbyname", side_effect=lambda h: h):
            scan_targets(["127.0.0.1", "203.0.113.5"], ports="80", _scanner_factory=_FakeScanner)
        by_host = dict(_FakeScanner.seen)
        self.assertTrue(by_host["127.0.0.1"].startswith("-sT"))
        self.assertFalse(by_host["203.0.113.5"].startswith("-sT"))


if __name__ == "__main__":
    unittest.main()
