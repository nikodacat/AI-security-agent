# Attack narratives

Advisory scope: 2 narrative(s) from CONFIRMED verdicts. No exploit code, no attacker-tool invocations.

_Generated: 2026-10-01T02:59:37+00:00_

---

## CVE-2022-0778 — target: `eval-cms-plugin`

_2026-10-01T02:59:23+00:00 · model: claude-sonnet_

**Analyzer verdict:**

> Installed libssl1.1 1.1.1d-0+deb10u6 predates the 1.1.1n patched line, so the BN_mod_sqrt infinite-loop flaw is present. OpenSSL is a library invoked via PHP openssl_* functions behind Apache httpd 2.4.38, which network_state confirms is externally reachable on port 80. Vulnerable version + reachable code path + no mitigating config.

### Recon

An external attacker sweeping the host finds port 80 open and reachable, with Apache httpd 2.4.38 advertised in the banner. This single low-noise probe gives the attacker a web server fingerprint and tells them the host is a live, internet-facing target worth deeper enumeration. Nothing about the banner itself reveals the underlying crypto library — that requires a further step.

### Discovery

The attacker enumerates the application layer behind Apache and identifies PHP in use, inferring (via error pages, response timing, or framework fingerprints) that server-side code invokes PHP's `openssl_*` function family — any feature touching certificate parsing, key generation, signature verification, or encrypted data handling is a candidate. Correlating the host's OS/package fingerprint with the installed `libssl1.1 1.1.1d-0+deb10u6` confirms the library predates the 1.1.1n fix line. The exposure path is layered: Apache terminates the request, PHP's OpenSSL bindings process attacker-influenced input, and that input reaches `BN_mod_sqrt` logic inside libssl — no additional access control sits in front of it.

### Exploitation

The vulnerability class is a denial-of-service condition: certain malformed elliptic-curve parameters drive `BN_mod_sqrt` into an infinite loop, pinning the worker thread/process handling the request. The attacker's objective is service disruption rather than code execution or data theft — by repeatedly triggering the flawed computation through any reachable PHP code path that parses attacker-supplied EC key material, they exhaust Apache/PHP worker capacity and degrade or deny availability for legitimate users. The precise trigger depends on which `openssl_*` call sites accept external input, which the evidence here does not fully enumerate.

---

## CVE-2021-3711 — target: `eval-cms-plugin`

_2026-10-01T02:59:37+00:00 · model: claude-sonnet_

**Analyzer verdict:**

> Installed libssl1.1 is 1.1.1d, which predates the 1.1.1l fix boundary for CVE-2021-3711 (SM2 decryption buffer overflow) — version is within the affected range, not post-fix. The package metadata itself notes the overflow is reachable via PHP openssl_* calls, and network-prober confirms port 80 is externally reachable with an Apache httpd 2.4.38 banner, indicating a live web/PHP stack that links against this OpenSSL build. No config-level mitigation (e.g. disabling SM2 code paths) is evidenced in host_state, so the vulnerable code path is both present and exposed.

### Recon

An external attacker scanning the host sees port 80 open with an `Apache httpd 2.4.38` banner — a low-noise, unauthenticated observation available to anyone sweeping the network segment. The banner alone signals a Linux-based web stack of a certain vintage and invites follow-up probing to identify the application layer running behind Apache (commonly PHP on this version pairing), along with any endpoints that accept user-supplied data for cryptographic or certificate-related operations.

### Discovery

Dpkg ground truth pins the installed `libssl1.1` at 1.1.1d, which sits before the 1.1.1l boundary where the SM2 decryption fix landed — so the vulnerable code path is physically present on disk. The package metadata itself calls out that this path is reachable through PHP's `openssl_*` function family, meaning the attacker's real target is any web-facing feature that passes attacker-controlled input into those bindings (e.g., certificate/key parsing, decryption, or signature-verification forms). No compensating control — such as disabling SM2 handling — is reflected in host state, so discovery reduces to finding which PHP endpoint on the Apache service touches OpenSSL's SM2 decryption routine.

### Exploitation

The vulnerability class is a buffer overflow triggered during SM2 decryption when an undersized buffer is supplied relative to attacker-controlled ciphertext length. An attacker's objective is memory corruption within the web server's process context, pursued by crafting malformed input to the identified OpenSSL-backed endpoint in hopes of forcing a miscalculated buffer size. Depending on the calling application's exact usage of the library, the outcome ranges from denial-of-service (worker crash) to potential remote code execution inside the Apache/PHP process — the precise ceiling depends on how the hosting application invokes the affected OpenSSL calls, which evidence here does not fully specify.

---
