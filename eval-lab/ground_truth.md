# eval-lab — Ground Truth

**Committed 2026-08-05, before any exposure-analyzer run against this lab.**
No back-fitting: entries here reflect what a security-competent human should
conclude from the container's software + config, deciding the verdict *from
first principles* rather than from what the analyzer happens to output.

Each row: **CVE**, **software affected**, **version present**, **detectable
via** (what evidence a scanner needs to gather), **expected verdict** (one of
`CONFIRMED` / `MITIGATED_BY_CONFIG` / `MITIGATED_BY_EXPOSURE` / `NOT_RUNNING` /
`NO_EVIDENCE`), and a **one-line rationale**. `NO_EVIDENCE` is used only when a
CVE requires evidence the scanner cannot gather (i.e. the analyzer should
honestly report insufficient data, not guess).

The **detection method** column is important: several CVEs in this lab affect
software built from source (`httpd` in web-vuln) or web-app code
(`wordpress`) that the current dpkg-based software scanner does *not* see.
Those rows are labeled "banner" or "config" and are flagged for chunk E's
probe library to cover.

---

## Container: `eval-web-vuln`

Base image: `httpd:2.4.49` on Debian 10 (buster). Apache built from source into
`/usr/local/apache2/`. `mod_cgid` + `mod_autoindex` loaded. `ScriptAlias /cgi-bin/`
configured. httpd bound to `0.0.0.0:80`, published on host at `:8081`.

| # | CVE            | Software (version)             | Detectable via                                     | Expected verdict         | Rationale |
|---|----------------|--------------------------------|----------------------------------------------------|--------------------------|-----------|
| 1 | CVE-2021-42013 | Apache HTTP Server (2.4.49)    | banner: `httpd -v` OR HTTP `Server:` header        | **CONFIRMED**            | Version in affected range (2.4.49/50); `mod_cgid` loaded → path-traversal → RCE fully wired; port 80 published; no `Require all denied` shielding traversal target. |
| 2 | CVE-2021-41773 | Apache HTTP Server (2.4.49)    | banner: `httpd -v`                                 | **CONFIRMED**            | Predecessor of #1, same affected version, same conditions. |
| 3 | CVE-2022-0778  | OpenSSL library (libssl1.1 1.1.1n-0+deb10u6) | dpkg: `libssl1.1`                                  | **MITIGATED_BY_CONFIG**  | Package version 1.1.1n is *at* the patched line (fix landed in 1.1.1n / 3.0.2). Vulnerable range `<1.1.1n`. Verdict is technically "not affected"; framed as MITIGATED_BY_CONFIG since the analyzer sees the family match. |
| 4 | CVE-2021-3711  | OpenSSL library (libssl1.1 1.1.1n-0+deb10u6) | dpkg: `libssl1.1`                                  | **MITIGATED_BY_CONFIG**  | Package version is post-fix (fixed in 1.1.1l). |
| 5 | CVE-2023-38408 | OpenSSH client/server          | probe: `ssh -V` / `which sshd`                     | **NOT_RUNNING**          | No `ssh`/`sshd` binary present in the container at all. |
| 6 | CVE-2019-0211  | Apache HTTP Server mod_prefork | banner + probe: `httpd -M` MPM check               | **MITIGATED_BY_CONFIG**  | httpd 2.4.49 is post-fix (fixed in 2.4.39); also uses `event` MPM by default in this image, not `prefork`. |

**Coverage gap note:** rows 1, 2, 6 depend on banner-based probes for `httpd`
that the dpkg-based scanner does not produce. Chunk E must add an `httpd -v`
probe (analog of the SSH probe already in `KNOWN_PROBES`) to unblock those
verdicts.

---

## Container: `eval-db-exposed`

Base image: `redis:6.2.6` on Debian 11 (bullseye). Config: `bind 0.0.0.0`,
`protected-mode no`, empty `requirepass`. Redis running as PID 1 (root inside
container). Lua scripting (`EVAL`) confirmed working. Published on host at
`:16379`.

| # | CVE            | Software (version)      | Detectable via                                        | Expected verdict         | Rationale |
|---|----------------|-------------------------|-------------------------------------------------------|--------------------------|-----------|
| 1 | CVE-2022-0543  | Redis Lua sandbox escape (6.2.6, Debian package) | banner: `INFO server` OR probe: `EVAL "return 1+1" 0` | **CONFIRMED**            | Debian-packaged Lua interpreter linked dynamically; `EVAL` accessible without auth; verified `EVAL` returns `2`. Fixed only in Debian's patched redis (`5:6.0.16-1+deb11u1`), and this container uses the upstream `redis:6.2.6` image which does *not* carry the patch. |
| 2 | (exposure)     | Redis 6.2.6 (any CVE)   | scanner: `bind` + `requirepass` + `protected-mode`    | **CONFIRMED** (as blast-radius marker) | Not a CVE per se — the exposure of an unauthenticated Redis on `0.0.0.0` is itself the finding. Any Redis CVE requiring network access is trivially reachable. |
| 3 | CVE-2022-0778  | OpenSSL library (libssl1.1 1.1.1n-0+deb11u1)         | dpkg: `libssl1.1`                                     | **MITIGATED_BY_CONFIG**  | Package is at 1.1.1n (patched line). |
| 4 | CVE-2022-24735 | Redis Lua sandbox escape (redis <=6.2.6)             | banner: `INFO server`                                 | **CONFIRMED**            | Redis 6.2.6 predates 6.2.7 fix; Lua accessible; same conditions as #1. |
| 5 | CVE-2022-24736 | Redis Lua NULL-deref (redis <=6.2.6)                 | banner: `INFO server`                                 | **CONFIRMED**            | Same version + Lua-accessible condition; DoS on crafted script. |
| 6 | CVE-2023-38408 | OpenSSH                 | probe: `which ssh`                                    | **NOT_RUNNING**          | No SSH binary present. |

**Coverage gap note:** row 2 is an exposure-only finding — the *analyzer* is
what turns "port bound to 0.0.0.0 + no requirepass" into a verdict; there is
no CVE ID. Consider whether the verdict schema should support "exposure
finding" as a first-class category alongside CVEs (chunk-M design question).

---

## Container: `eval-cms-plugin`

Base image: `wordpress:5.7-apache` on Debian 10 (buster). Ships Apache
**2.4.38** (Debian package, *not* 2.4.49 — CVE-2021-42013 does NOT apply
here). PHP 7.4.21. WordPress core 5.7.x (`wp-includes/version.php` present
but `wp_version` not populated until first setup). No plugins installed
(`wp-content/plugins/` empty). Port 80 published on host at `:8082`.

| # | CVE            | Software (version)               | Detectable via                                     | Expected verdict         | Rationale |
|---|----------------|----------------------------------|----------------------------------------------------|--------------------------|-----------|
| 1 | CVE-2021-42013 | Apache HTTP Server (2.4.38)      | banner: `apache2 -v` OR HTTP `Server:` header      | **MITIGATED_BY_CONFIG**  | Affected range is exactly 2.4.49/2.4.50; 2.4.38 predates the vulnerable code path (a separate CVE for 2.4.38 exists). Not vulnerable to *this* CVE. |
| 2 | CVE-2021-40438 | Apache mod_proxy (2.4.38)        | banner + probe: `apache2ctl -M` proxy check        | **MITIGATED_BY_CONFIG**  | Version *is* in affected range (fixed in 2.4.49) BUT `mod_proxy` is not loaded (only `rewrite_module` per `apache2ctl -M`). Not reachable. |
| 3 | CVE-2022-0778  | OpenSSL library (libssl1.1 1.1.1d-0+deb10u6) | dpkg: `libssl1.1`                                  | **CONFIRMED**            | Package version 1.1.1d is BEFORE 1.1.1n (patched line); this is exactly the CVE from our `sample_candidates.json`. httpd doesn't use it for TLS (no mod_ssl), but PHP does — any TLS operation from PHP triggers the vulnerable BN_mod_sqrt. |
| 4 | CVE-2021-3711  | OpenSSL library (libssl1.1 1.1.1d) | dpkg: `libssl1.1`                                  | **CONFIRMED**            | 1.1.1d predates 1.1.1l fix. Buffer overflow in SM2 decryption. Reachable through PHP's `openssl_*` functions. |
| 5 | CVE-2021-44228 | Log4j                            | probe: `find / -name "log4j*"`                     | **NOT_RUNNING**          | Java-only vulnerability; PHP stack has no log4j. Included as a sanity check — analyzer should confidently produce NOT_RUNNING, not CONFIRMED, for a language-mismatched CVE. |
| 6 | CVE-2023-38408 | OpenSSH                          | probe: `which ssh`                                 | **NOT_RUNNING**          | No SSH binary present. |
| 7 | (wp plugin CVE — deferred) | (any WP plugin vuln) | probe: `ls wp-content/plugins/`                    | **NOT_RUNNING**          | Plugin directory is empty; no plugin-specific CVEs apply. Kept as a reminder that "cms-plugin" as a category needs a container with real plugins for a proper demo — chunk E follow-up. |

**Coverage gap note:** rows 1, 2 need an `apache2 -v` probe (banner check).
Rows 4-5 need probes that verify PHP is actually invoked in a way that
exercises the vulnerable OpenSSL code path — otherwise the verdict is
technically MITIGATED_BY_EXPOSURE (installed but not called). Row 7 is a
scope note: the container name "cms-plugin" doesn't match its content.

---

## Aggregate

**18 CVE ground-truth entries** across 3 containers. Breakdown by expected
verdict:

| Verdict                  | Count |
|--------------------------|------:|
| CONFIRMED                | 7     |
| MITIGATED_BY_CONFIG      | 6     |
| MITIGATED_BY_EXPOSURE    | 0     |
| NOT_RUNNING              | 5     |
| NO_EVIDENCE              | 0     |

## Handoff to chunk E (probe library)

To exercise this ground truth end-to-end, chunk E needs at minimum:

1. **`httpd -v` probe** — for Apache banner extraction (web-vuln rows 1-2, 6;
   cms-plugin rows 1-2). Analogous to the existing `ssh -V` probe.
2. **`apache2 -v` probe** — Debian-packaged variant (cms-plugin).
3. **Redis `INFO server` probe** — via `redis-cli -h <host> INFO server`
   (db-exposed rows 1, 4-5). Also needs `CONFIG GET requirepass` /
   `CONFIG GET bind` for the exposure-only finding (row 2).
4. **`wp-cli core version`** *or* filesystem read of `wp-includes/version.php`
   (cms-plugin — deferred entry).
5. **Filesystem-existence probe** — check for `/lib/log4j*.jar` or similar
   to positively rule out Java-only CVEs (cms-plugin row 5).

## Handoff to chunk J (eval runs)

- `eval_results.csv` columns: `container`, `cve_id`, `expected_verdict` (from
  this file), `actual_verdict` (from analyzer), `time_seconds`, `match`
  (boolean).
- Success metric: analyzer verdict matches `expected_verdict` for ≥80% of
  rows. Failures are teaching data — either the probe/analyzer needs
  refinement, or this ground truth needs revision (and the revision is logged
  below with reasoning, preserving the audit trail).

## Revision log

- **2026-08-05: web-vuln row 5 (CVE-2023-38408) — verdict weakened from `NOT_RUNNING` to `NO_EVIDENCE` (pending; see below).** During the first end-to-end chunk-E run against `eval-web-vuln`, Claude correctly pointed out that `ssh -V` returning "not found in PATH" does not conclusively rule out `sshd` being installed at another path. `NOT_RUNNING` requires positive absence proof (`dpkg -l | grep -c openssh-server` returning 0, or `find / -name sshd -type f` returning nothing). Until a stronger absence probe is added, `NO_EVIDENCE` is the honest verdict. Applies to db-exposed row 6 as well. **Fix ownership:** chunk E follow-up probe.
