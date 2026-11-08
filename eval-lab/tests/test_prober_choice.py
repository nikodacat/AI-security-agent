"""Where the network check runs (run_full_scan.choose_prober)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_full_scan import choose_prober  # noqa: E402


def pick(requested="auto", container=False, nmap=False, docker=False):
    return choose_prober(requested, container_mode=container, have_nmap=nmap, docker_up=docker)


class ChooseProberTests(unittest.TestCase):
    def test_lab_containers_use_the_attacker_container(self) -> None:
        # their names resolve only inside the compose network, even if nmap is installed here
        self.assertEqual(pick(container=True, nmap=True), "docker")
        self.assertEqual(pick(container=True), "docker")

    def test_a_server_is_probed_from_this_computer_when_nmap_is_installed(self) -> None:
        self.assertEqual(pick(nmap=True, docker=True), "local")

    def test_a_server_falls_back_to_the_attacker_container(self) -> None:
        self.assertEqual(pick(nmap=False, docker=True), "docker")

    def test_nothing_available_gives_no_prober(self) -> None:
        self.assertEqual(pick(), "")

    def test_explicit_choices(self) -> None:
        self.assertEqual(pick("docker"), "docker")
        self.assertEqual(pick("local", nmap=True), "local")
        with self.assertRaises(ValueError):
            pick("local", nmap=False)


if __name__ == "__main__":
    unittest.main()
