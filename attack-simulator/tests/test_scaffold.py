"""9a scaffold smoke tests.

These verify the package skeleton is importable and the CLI --help works
without any real dependencies (claude-agent-sdk in particular). Real
behavior tests land in 9b-9e.
"""

from __future__ import annotations

import subprocess
import sys
import unittest


class ScaffoldSmokeTests(unittest.TestCase):
    def test_package_imports(self) -> None:
        import attack_simulator  # noqa: F401
        self.assertTrue(hasattr(attack_simulator, "__version__"))
        self.assertTrue(hasattr(attack_simulator, "Narrative"))
        self.assertTrue(hasattr(attack_simulator, "AttackSimulator"))

    def test_cli_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "attack_simulator", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("attack_simulator", result.stdout.lower() + result.stderr.lower())
        self.assertIn("narrate", result.stdout.lower() + result.stderr.lower())

    def test_cli_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "attack_simulator", "--version"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("attack-simulator", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
