"""Probe library — per-CVE non-destructive verification commands.

Each `ProbeTemplate` describes a single probe: what command to run against
the target, what output pattern indicates the vulnerability, and a hint
Claude uses when interpreting the output.

`KNOWN_PROBES` is a dict keyed by CVE ID. In v1 it's populated by hand
(chunk D adds the first entry; chunk E adds 4-5 more for the demo lab).
v2 will add a Claude-generated fallback for CVEs not in the dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProbeTemplate:
    """A single non-destructive verification command for a specific CVE.

    Fields:
      command             : shell command; `{target}` is substituted with the
                            host / container identifier at run time.
      expected_signals    : list of regex fragments; if any match the probe
                            output, the vulnerable code path is likely present.
      interpretation_hint : one-sentence guidance the prompt injects to help
                            Claude reason about the output.
      safe                : True if the probe is guaranteed non-destructive
                            (read-only, no state change). All v1 probes MUST
                            be safe=True. Attempting to add safe=False raises.
    """

    command: str
    expected_signals: list[str] = field(default_factory=list)
    interpretation_hint: str = ""
    safe: bool = True

    def __post_init__(self) -> None:
        if not self.safe:
            raise ValueError(
                "v1 exposure-analyzer only accepts non-destructive probes "
                "(safe=True). Refusing to register a mutating probe."
            )


# CVE-ID -> ProbeTemplate. Populated per-CVE by chunks D-E.
#
# Design note: 1 CVE = 1 ProbeTemplate. When two CVEs affect the same
# software (e.g. Apache CVE-2021-41773 and CVE-2021-42013 both need `httpd
# -v`), each entry declares the command independently. That's mild
# duplication but keeps the schema flat and lets each entry carry its own
# interpretation_hint tuned to that specific CVE.
KNOWN_PROBES: dict[str, ProbeTemplate] = {
    # OpenSSH PKCS#11 forwarded-agent RCE. Non-destructive probe: read the
    # installed OpenSSH banner. The vulnerable range is 5.5..<9.3p2; the
    # banner alone doesn't prove exploitability (that also requires
    # ssh-agent + forwarding + a specific PKCS#11 provider path), so the
    # analyzer combines this output with host_state config to decide.
    "CVE-2023-38408": ProbeTemplate(
        command="ssh -V",
        expected_signals=[r"OpenSSH_[5-8]\.", r"OpenSSH_9\.[0-2]"],
        interpretation_hint=(
            "The command prints OpenSSH's version to stderr. Versions "
            "5.5 through 9.3p1 inclusive are within the affected range; "
            "9.3p2 and later are patched. Absence of ssh/sshd binary means "
            "NOT_RUNNING."
        ),
    ),

    # Apache HTTP Server path-traversal to RCE. Affected: 2.4.49 and 2.4.50
    # exactly; patched in 2.4.51. Full RCE also needs mod_cgi/mod_cgid loaded
    # AND a permissive <Directory> for the traversal target; without those,
    # the file-read primitive still works but RCE does not.
    "CVE-2021-42013": ProbeTemplate(
        command="httpd -v",
        expected_signals=[r"Apache/2\.4\.(49|50)"],
        interpretation_hint=(
            "Apache 2.4.49 and 2.4.50 are the only vulnerable versions; "
            "2.4.51+ is patched. Full RCE requires mod_cgi/mod_cgid loaded "
            "and a <Directory> without 'Require all denied' -- check "
            "host_state for those two conditions before returning CONFIRMED."
        ),
    ),

    # Apache HTTP Server path-traversal (predecessor of CVE-2021-42013).
    # Affected: 2.4.49 only. Fixed in 2.4.50 but the fix was incomplete,
    # which is what CVE-2021-42013 exploits.
    "CVE-2021-41773": ProbeTemplate(
        command="httpd -v",
        expected_signals=[r"Apache/2\.4\.49"],
        interpretation_hint=(
            "Only Apache 2.4.49 is vulnerable to CVE-2021-41773. If the "
            "banner shows 2.4.50, this specific CVE is patched (but "
            "CVE-2021-42013 still applies -- treat as a separate finding)."
        ),
    ),

    # Redis Lua sandbox escape. Affected: Debian-packaged redis <=6.2.6 "
    # linked against system Lua. Exploitation requires the attacker to be
    # able to issue EVAL, which usually means either no requirepass OR
    # authenticated attacker. The probe checks both version AND accessibility.
    "CVE-2022-0543": ProbeTemplate(
        command="redis-cli -h 127.0.0.1 INFO server",
        expected_signals=[
            r"redis_version:(4|5|6\.[01])\.",       # 4.x, 5.x, 6.0.x, 6.1.x all vulnerable
            r"redis_version:6\.2\.[0-6](?![0-9])",  # 6.2.0-6.2.6 vulnerable; 6.2.7+ patched
        ],
        interpretation_hint=(
            "If the command returns a redis_version line, redis is running "
            "and reachable on loopback. Vulnerable range is <=6.2.6 "
            "Debian-packaged redis using system Lua (fixed in 5:6.0.16-1+deb11u1 "
            "for bullseye). If redis-cli is 'not found' or the command times "
            "out, redis is likely not running -> NOT_RUNNING. Combine with "
            "host_state to check bind address + requirepass for exposure."
        ),
    ),

    # Log4Shell. Java-only vulnerability; this probe is a *negative* check
    # for the analyzer to confidently rule it out on non-Java hosts.
    "CVE-2021-44228": ProbeTemplate(
        command="sh -c \"find / -maxdepth 8 -name 'log4j-core-*.jar' 2>/dev/null | head -5\"",
        expected_signals=[
            # Vulnerable: log4j-core 2.0 through 2.14.x (2-part or 3-part version).
            r"log4j-core-2\.(0|[1-9]|1[0-4])(\.[0-9]+)?\.jar",
        ],
        interpretation_hint=(
            "Empty output means log4j-core is not present anywhere on disk "
            "-> NOT_RUNNING (confident rule-out). Presence of log4j-core "
            "2.0 through 2.14.x = CONFIRMED. 2.15+ has partial mitigations; "
            "2.17.1+ is fully patched. Java-only vulnerability -- if the "
            "target has no JVM, this CVE cannot apply."
        ),
    ),
}


def lookup_probe(cve_id: str) -> ProbeTemplate | None:
    """Return the probe template for a CVE, or None if we have no known probe.

    Callers should treat `None` as "no hardcoded probe; either skip with
    NO_EVIDENCE or fall back to Claude-generated probe (v2)."
    """
    return KNOWN_PROBES.get(cve_id)
