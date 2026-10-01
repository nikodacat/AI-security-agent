"""10a scaffold smoke tests."""

from __future__ import annotations

import subprocess
import sys
import unittest


class ScaffoldSmokeTests(unittest.TestCase):
    def test_package_imports(self) -> None:
        import fix_publisher  # noqa: F401
        self.assertTrue(hasattr(fix_publisher, "__version__"))
        self.assertTrue(hasattr(fix_publisher, "Remediation"))
        self.assertTrue(hasattr(fix_publisher, "FixPublisher"))

    def test_cli_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "fix_publisher", "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("fix_publisher", result.stdout.lower() + result.stderr.lower())
        self.assertIn("publish", result.stdout.lower() + result.stderr.lower())

    def test_cli_version(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "fix_publisher", "--version"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("fix-publisher", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
