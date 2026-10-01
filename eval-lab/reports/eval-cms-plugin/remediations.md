# Remediation drafts

Advisory scope: 2 remediation(s) from CONFIRMED verdicts. Draft commands — review against your fleet's pins before applying.

_Generated: 2026-09-30T16:49:24+00:00_

---

## CVE-2022-0778 — target: `eval-cms-plugin`

_2026-09-30T16:49:11+00:00 · model: claude-sonnet_

**Analyzer verdict:**

> Installed libssl1.1 1.1.1d-0+deb10u6 predates the 1.1.1n patched line, so the BN_mod_sqrt infinite-loop flaw is present. OpenSSL is a library invoked via PHP openssl_* functions behind Apache httpd 2.4.38, which network_state confirms is externally reachable on port 80. Vulnerable version + reachable code path + no mitigating config.

### Package update

```bash
apt install libssl1.1=1.1.1n-0+deb10u3
```

### Config change

_no config change needed._

### Service restart

```bash
systemctl restart apache2
```

### Why this works

CVE-2022-0778 (BN_mod_sqrt infinite-loop DoS) is fixed upstream in OpenSSL 1.1.1n per the OpenSSL security advisory of 2022-03-15; Debian's buster backport landing this fix is libssl1.1 1.1.1n-0+deb10u3, which supersedes the installed 1.1.1d-0+deb10u6. Apache httpd loads libssl1.1 into its worker processes via PHP's openssl_* functions, so it must be restarted after the upgrade to load the patched library.

---

## CVE-2021-3711 — target: `eval-cms-plugin`

_2026-09-30T16:49:24+00:00 · model: claude-sonnet_

**Analyzer verdict:**

> Installed libssl1.1 is 1.1.1d, which predates the 1.1.1l fix boundary for CVE-2021-3711 (SM2 decryption buffer overflow) — version is within the affected range, not post-fix. The package metadata itself notes the overflow is reachable via PHP openssl_* calls, and network-prober confirms port 80 is externally reachable with an Apache httpd 2.4.38 banner, indicating a live web/PHP stack that links against this OpenSSL build. No config-level mitigation (e.g. disabling SM2 code paths) is evidenced in host_state, so the vulnerable code path is both present and exposed.

### Package update

```bash
apt install libssl1.1=1.1.1d-0+deb10u7
```

### Config change

_no config change needed._

### Service restart

```bash
systemctl restart apache2
```

### Why this works

CVE-2021-3711 (SM2 decryption buffer overflow) is fixed upstream in OpenSSL 1.1.1l and backported by Debian into libssl1.1 1.1.1d-0+deb10u7 (DSA-4963-1); the installed 1.1.1d predates this and must be upgraded to the patched Debian revision. Apache's PHP/openssl-linked workers hold the old library in memory, so apache2 must be restarted to load the fixed libssl1.1.

---
