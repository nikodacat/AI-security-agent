"""Tests for probe runners (local + docker exec)."""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch, MagicMock

from exposure_analyzer.agent import (
    AgentConfig,
    _default_probe_runner,
    docker_exec_probe_runner,
)
from exposure_analyzer.probes import ProbeTemplate


class TestDockerExecRunner(unittest.TestCase):
    def test_wraps_command_with_docker_exec(self):
        template = ProbeTemplate(command="ssh -V")
        runner = docker_exec_probe_runner("eval-web-vuln")

        with patch("exposure_analyzer.agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="OpenSSH_8.5p1\n", stderr="")
            cmd, out = runner(template)

        # The argv passed to subprocess.run should be:
        # ["docker", "exec", "eval-web-vuln", "ssh", "-V"]
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[:3], ["docker", "exec", "eval-web-vuln"])
        self.assertEqual(argv[3:], ["ssh", "-V"])

    def test_display_command_is_the_template_not_the_wrapped_argv(self):
        # Verdicts should show `ssh -V`, not `docker exec ... ssh -V`.
        template = ProbeTemplate(command="ssh -V")
        runner = docker_exec_probe_runner("eval-web-vuln")

        with patch("exposure_analyzer.agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="OpenSSH_8.5p1\n")
            cmd, out = runner(template)

        self.assertEqual(cmd, "ssh -V")
        self.assertIn("OpenSSH_8.5p1", out)

    def test_command_not_found_message(self):
        template = ProbeTemplate(command="nonexistent-binary")
        runner = docker_exec_probe_runner("eval-web-vuln")

        with patch("exposure_analyzer.agent.subprocess.run", side_effect=FileNotFoundError()):
            cmd, out = runner(template)

        # The "not found" report should point at docker, not the probe binary,
        # since docker itself is what could not be exec'd. (Distinct from a
        # probe binary missing inside the container, which succeeds at the
        # docker layer but returns a nonzero exit + a shell error.)
        self.assertIn("not found", out.lower())
        self.assertIn("docker", out.lower())

    def test_timeout_reported_cleanly(self):
        template = ProbeTemplate(command="sleep 100")
        cfg = AgentConfig(probe_timeout_sec=0.1)
        runner = docker_exec_probe_runner("eval-web-vuln", cfg)

        with patch(
            "exposure_analyzer.agent.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=0.1),
        ):
            cmd, out = runner(template)

        self.assertIn("timed out", out.lower())

    def test_output_truncated_to_max_chars(self):
        template = ProbeTemplate(command="cat huge")
        cfg = AgentConfig(max_output_chars=50)
        runner = docker_exec_probe_runner("eval-web-vuln", cfg)

        with patch("exposure_analyzer.agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="A" * 500, stderr="")
            cmd, out = runner(template)

        self.assertLess(len(out), 500)
        self.assertIn("truncated", out)


class TestDefaultRunnerStillWorks(unittest.TestCase):
    """Regression: refactoring didn't break the local runner."""

    def test_default_runner_does_not_prefix_docker_exec(self):
        template = ProbeTemplate(command="echo hello")
        runner = _default_probe_runner(AgentConfig())

        with patch("exposure_analyzer.agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="hello\n", stderr="")
            cmd, out = runner(template)

        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[0], "echo")  # not "docker"
        self.assertEqual(cmd, "echo hello")


if __name__ == "__main__":
    unittest.main()
