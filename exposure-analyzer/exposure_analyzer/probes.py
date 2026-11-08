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


@dataclass(frozen=True)
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

    Threat model for the safe=True invariant:
      This blocks *accidental* registration of destructive probes and
      *accidental* mutation post-construction (via `frozen=True`). It does
      NOT prevent a determined attacker with Python access from bypassing
      via subclassing that overrides `__post_init__` or by directly
      inserting into `KNOWN_PROBES`. Those attacks are out of scope --
      anyone with arbitrary Python execution already owns the process.
      The invariant exists to catch developer mistakes, not to be a
      security boundary.
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
        # `httpd` on upstream/Vulhub images, `apache2` on Debian/Ubuntu packages.
        command="sh -c \"httpd -v 2>/dev/null || apache2 -v\"",
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
        command="sh -c \"httpd -v 2>/dev/null || apache2 -v\"",
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

    # Heartbleed. Upstream OpenSSL 1.0.1 through 1.0.1f (and 1.0.2-beta) only;
    # 1.0.0, 0.9.8 and everything from 1.0.1g / 1.0.2 / 1.1.x onward are
    # unaffected. Output includes the distro package version because
    # distros backport fixes without changing the upstream version string.
    "CVE-2014-0160": ProbeTemplate(
        command="sh -c \"openssl version; dpkg-query -W openssl libssl1.0.0 libssl1.1 2>/dev/null\"",
        expected_signals=[r"OpenSSL 1\.0\.1[a-f]?\s"],
        interpretation_hint=(
            "Only OpenSSL 1.0.1 through 1.0.1f is affected (1.0.1g fixed it). "
            "OpenSSL 1.0.0, 1.0.2 and any 1.1.x are not affected regardless "
            "of patch level. On Debian/Ubuntu, a vulnerable upstream version "
            "may carry a backported fix -- compare the dpkg package version "
            "against the distro's fixed version before concluding."
        ),
    ),

    # Shellshock family. Direct behavioural test: export a function-definition
    # env var carrying a trailing command and see whether bash executes it.
    # Only prints a marker string; touches nothing on disk.
    "CVE-2014-6278": ProbeTemplate(
        command="env x='() { :;}; echo SHELLSHOCK_VULNERABLE' bash -c 'echo probe_done'",
        expected_signals=[r"SHELLSHOCK_VULNERABLE"],
        interpretation_hint=(
            "If SHELLSHOCK_VULNERABLE appears in the output, this bash "
            "executes code after a function definition in an env var "
            "(unpatched). Output of only 'probe_done' means this bash build "
            "is patched. Even when the bash build is vulnerable, exploitation "
            "also needs a network-facing component (CGI, DHCP client, "
            "ForceCommand ssh, ...) that passes attacker-controlled data into "
            "bash's environment -- check host_state / network_state for one "
            "before returning CONFIRMED."
        ),
    ),

    # Ghostscript -dSAFER bypass via type confusion (CVE-2017-8291, "Rubber
    # Ducky"). Upstream fix is in 9.21; distros backport. Exploitation needs
    # an attacker-supplied PostScript/EPS file to reach ghostscript, typically
    # through ImageMagick, a PHP upload handler, or a document converter.
    "CVE-2017-8291": ProbeTemplate(
        command="sh -c \"gs --version; dpkg-query -W ghostscript 2>/dev/null\"",
        expected_signals=[r"^(8\.|9\.([0-9]|1[0-9]|20)(\.|\s|$))"],
        interpretation_hint=(
            "Upstream versions before 9.21 are affected; 9.21+ is fixed. On "
            "Debian/Ubuntu compare the package version against the distro "
            "security fix. Presence of the binary alone is not exploitable: "
            "something must hand untrusted PostScript/EPS to it -- check "
            "host_state for ImageMagick, PHP upload handling, or other "
            "converters. Binary absent (not found) means NOT_RUNNING."
        ),
    ),

    # Apache mod_proxy SSRF via crafted request line (CVE-2021-40438).
    # Affected httpd <= 2.4.48, and only when mod_proxy is actually loaded
    # (and a ProxyPass / reverse-proxy rule uses a unix-socket-style target).
    "CVE-2021-40438": ProbeTemplate(
        command="sh -c \"(apache2ctl -M 2>&1 || httpd -M 2>&1) | grep -i proxy; apache2 -v 2>/dev/null || httpd -v\"",
        expected_signals=[r"proxy_module"],
        interpretation_hint=(
            "The vulnerable range is httpd <= 2.4.48 (fixed in 2.4.49). "
            "Look for 'proxy_module' in the loaded-module list: if no proxy "
            "module line appears, mod_proxy is not loaded and the SSRF "
            "primitive does not exist -> MITIGATED_BY_CONFIG regardless of "
            "version. Version banner is printed on the last lines."
        ),
    ),

    # OpenSSL BN_mod_sqrt() infinite loop (CVE-2022-0778). Affected upstream:
    # 1.0.2-1.0.2zc, 1.1.1-1.1.1m, 3.0.0-3.0.1. Fixed 1.1.1n / 3.0.2.
    # DoS only (parsing a crafted certificate with explicit EC parameters).
    "CVE-2022-0778": ProbeTemplate(
        command="sh -c \"openssl version; dpkg-query -W openssl libssl1.1 libssl3 2>/dev/null\"",
        expected_signals=[
            r"OpenSSL 1\.0\.2[a-z]{0,2}\s",
            r"OpenSSL 1\.1\.1[a-m]?\s",
            r"OpenSSL 3\.0\.[01]\s",
        ],
        interpretation_hint=(
            "Upstream-affected: 1.0.2 through 1.0.2zc, 1.1.1 through 1.1.1m, "
            "3.0.0-3.0.1; fixed in 1.1.1n and 3.0.2. A bare '1.1.1' with no "
            "letter or a letter <= m is in range. Debian/Ubuntu backport the "
            "fix without bumping the upstream string -- compare the dpkg "
            "package version to the distro's fixed version. Impact is denial "
            "of service only (infinite loop while parsing a crafted cert)."
        ),
    ),

    # OpenSSL SM2 decryption buffer overflow (CVE-2021-3711). Affected
    # 1.1.1 through 1.1.1k; fixed in 1.1.1l. Only reachable if the
    # application decrypts attacker-supplied SM2 ciphertext.
    "CVE-2021-3711": ProbeTemplate(
        command="sh -c \"openssl version; dpkg-query -W openssl libssl1.1 libssl3 2>/dev/null\"",
        expected_signals=[r"OpenSSL 1\.1\.1[a-k]?\s"],
        interpretation_hint=(
            "Upstream-affected: 1.1.1 through 1.1.1k (1.1.1l fixed it); "
            "1.0.2 and 3.x are not affected. Debian/Ubuntu backport the fix "
            "without bumping the upstream string -- compare the dpkg package "
            "version to the distro's fixed version. Practical exposure also "
            "requires an application that performs SM2 decryption on "
            "untrusted input, which is rare."
        ),
    ),

    # PHP (2026-10 KEV additions). Both are fixed in 8.2.35 / 8.3.36 / 8.4.27 /
    # 8.5.12, so any PHP older than those on its branch is affected. 7.x and
    # 8.0/8.1 are end-of-life and will never get a fix.
    "CVE-2026-109618": ProbeTemplate(
        command="php -v",
        expected_signals=[
            r"PHP (7\.[3-9]|8\.[01]\.)",
            r"PHP 8\.2\.([0-9]|[12][0-9]|3[0-4])(?![0-9])",
            r"PHP 8\.3\.([0-9]|[12][0-9]|3[0-5])(?![0-9])",
            r"PHP 8\.4\.([0-9]|1[0-9]|2[0-6])(?![0-9])",
            r"PHP 8\.5\.([0-9]|1[01])(?![0-9])",
        ],
        interpretation_hint=(
            "Affected: PHP 7.3.0 up to (not including) 8.2.35, 8.3.x < 8.3.36, "
            "8.4.x < 8.4.27, 8.5.x < 8.5.12. A match means the PHP CLI on this "
            "host is in range. The web server may load a different PHP build "
            "(mod_php / php-fpm): check host_state.services for which one serves "
            "requests. PHP 7.x/8.0/8.1 are end-of-life: no fixed version exists "
            "on those branches, only an upgrade to a fixed 8.x release."
        ),
    ),
    "CVE-2026-109619": ProbeTemplate(
        command="php -v",
        expected_signals=[
            r"PHP (5\.[4-9]|7\.|8\.[01]\.)",
            r"PHP 8\.2\.([0-9]|[12][0-9]|3[0-4])(?![0-9])",
            r"PHP 8\.3\.([0-9]|[12][0-9]|3[0-5])(?![0-9])",
            r"PHP 8\.4\.([0-9]|1[0-9]|2[0-6])(?![0-9])",
            r"PHP 8\.5\.([0-9]|1[01])(?![0-9])",
        ],
        interpretation_hint=(
            "Affected: PHP 5.4.0 up to (not including) 8.2.35, 8.3.x < 8.3.36, "
            "8.4.x < 8.4.27, 8.5.x < 8.5.12. Same caveats as CVE-2026-109618: "
            "the CLI version is evidence for the web-serving PHP only if "
            "host_state.services shows the same build is what Apache/php-fpm uses."
        ),
    ),
}


def lookup_probe(cve_id: str) -> ProbeTemplate | None:
    """Return the probe template for a CVE, or None if we have no known probe.

    Callers should treat `None` as "no hardcoded probe; either skip with
    NO_EVIDENCE or fall back to Claude-generated probe (v2)."
    """
    return KNOWN_PROBES.get(cve_id)
