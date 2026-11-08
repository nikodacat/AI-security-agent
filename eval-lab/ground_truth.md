# eval-lab — Ground Truth

**Committed 2026-08-05 (original 17 entries, aspirational).**
**Revised 2026-08-10 (added v1-scored scope, 7 entries; total 7 scored + 17 unscored).**
**Revised 2026-09-21 (v2-6 widening — all 24 entries now scored under v2 capabilities).**
No back-fitting: entries here reflect what a security-competent human should
conclude from the container's software + config, deciding the verdict *from
first principles* rather than from what the analyzer happens to output.

---

## Two-tier structure (history)

This document originally defined ground truth at two scopes:

- **§ Scoring scope (v1)** — 7 CVEs the v1 pipeline actually surfaced
  (KEV catalog ∩ dpkg-installed packages ∩ these three containers).
  Every entry is a patched-package CVE, so the correct verdict is
  `MITIGATED_BY_CONFIG` — this measures whether the analyzer reliably
  recognizes patched software as such.
- **§ Aspirational ground truth (v2 coverage targets)** — the original 17
  entries covering banner-detected Apache, source-built httpd, non-dpkg
  log4j, absent SSH, and unauthenticated Redis. Not scoreable by v1
  because cve-matcher's KEV+dpkg substrate could not see them.

**As of v2-6 (2026-09-21) both tiers are scored by `run_eval.py`.** v2's
external network-prober, banner-based probe library, and host-scanner
substrate collectively surface the 17 previously-aspirational entries.
The section split below is preserved for history (it shows *why* v1
couldn't score them); scoring now reads the full 24 entries from
`ground_truth.yaml` (version 3, scoring_scope `v2-with-external-prober`).

The two tiers together give the report an honest coverage picture: "here
is what v1 scored, here is what v2 added, here's why the gap existed."

---

## Scoring scope (v1) — pipeline-surfaceable CVEs

The 7 CVEs below are exactly what `cve-matcher` surfaces against these
containers today (all KEV-listed and all detected via dpkg package lists).
Every installed version is post-fix, so the schema-correct verdict is
`MITIGATED_BY_CONFIG`. The analyzer's job is to consistently recognize this.

### `eval-web-vuln`

| # | CVE            | Package (version)                              | Expected verdict        | Rationale |
|---|----------------|------------------------------------------------|-------------------------|-----------|
| 1 | CVE-2014-0160  | libssl1.1 (1.1.1n-0+deb10u6)                   | **MITIGATED_BY_CONFIG** | Heartbleed fixed in 1.0.1g; installed 1.1.1n is far post-fix. |
| 2 | CVE-2014-6278  | bash (5.0-4)                                   | **MITIGATED_BY_CONFIG** | Shellshock family (`env x='() { :;}; command'` variants) fixed in bash 4.3 patchlevels; installed 5.0 is post-fix. |

### `eval-db-exposed`

| # | CVE            | Package (version)                              | Expected verdict        | Rationale |
|---|----------------|------------------------------------------------|-------------------------|-----------|
| 1 | CVE-2014-0160  | libssl1.1 (1.1.1w-0+deb11u8)                   | **MITIGATED_BY_CONFIG** | Heartbleed fixed in 1.0.1g; installed 1.1.1w is far post-fix. |
| 2 | CVE-2014-6278  | bash (5.1-2+b3)                                | **MITIGATED_BY_CONFIG** | Shellshock family fixed in bash 4.3; installed 5.1 is post-fix. |

### `eval-cms-plugin`

| # | CVE            | Package (version)                              | Expected verdict        | Rationale |
|---|----------------|------------------------------------------------|-------------------------|-----------|
| 1 | CVE-2014-0160  | libssl1.1 (1.1.1d-0+deb10u6)                   | **MITIGATED_BY_CONFIG** | Heartbleed fixed in 1.0.1g; installed 1.1.1d is post-fix. |
| 2 | CVE-2014-6278  | bash (5.0-4)                                   | **MITIGATED_BY_CONFIG** | Shellshock family fixed in bash 4.3; installed 5.0 is post-fix. |
| 3 | CVE-2017-8291  | ghostscript (9.27~dfsg-2+deb10u4)              | **MITIGATED_BY_CONFIG** | Ghostscript `-dSAFER` bypass fixed in 9.21; installed 9.27 is post-fix. |

**v1-scored aggregate:** 7 entries, all `MITIGATED_BY_CONFIG`.

---

## Aspirational ground truth (now v2-scored as of 2026-09-21)

Everything below is the *original* 17-entry ground truth committed 2026-08-05.
These CVEs are what a security-competent human should flag when looking at the
containers, but they fell outside the v1 pipeline's KEV+dpkg substrate:
Apache 2.4.49 is built from source (not dpkg), log4j is a jar file (not dpkg),
`CVE-2022-0778` isn't in KEV (DoS-only), and OpenSSH isn't installed at all.

**As of v2-6 (2026-09-21) these 17 entries ARE scored by `run_eval.py`** —
v2 supplies the substrate that v1 lacked (banner-based analyzer probes for
Apache/Redis, filesystem-existence probes for log4j and SSH absence, and
external reachability data from `network-prober`). SSH-absence rows use
`NO_EVIDENCE` per the 2026-08-05 revision-log decision (a `ssh -V`
not-found is not positive absence proof; a stronger dpkg + filesystem
negative probe would justify `NOT_RUNNING`).

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
| 1 | CVE-2022-0543  | Redis Lua sandbox escape (6.2.6, Debian package) | banner: `INFO server` OR probe: `EVAL "return 1+1" 0` | **MITIGATED_BY_CONFIG**  | **Revised 2026-10-30 (was CONFIRMED).** The bug is Debian-specific: Debian links Lua dynamically and leaves the `package` global exposed. This container is the upstream `redis:6.2.6` image: Lua is bundled, and `EVAL "return type(package)" 0` fails with `nonexistent global variable 'package'`. `EVAL` being reachable without auth is true but is not this CVE. The original row mistook "no Debian patch" for "vulnerable". |
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

**24 scored CVE ground-truth entries** across 3 containers (7 v1-scored +
17 v2-6-added; two aspirational-doc rows without CVE IDs — the Redis
exposure marker and the empty wp-plugins entry — are intentionally not
scored). Breakdown by expected verdict:

| Verdict                  | Count |
|--------------------------|------:|
| CONFIRMED                | 6     |
| MITIGATED_BY_CONFIG      | 14    |
| MITIGATED_BY_EXPOSURE    | 0     |
| NOT_RUNNING              | 1     |
| NO_EVIDENCE              | 3     |

Per-container: eval-web-vuln 8, eval-db-exposed 7, eval-cms-plugin 9.
Distinct CVE IDs: 14 (several appear across containers with different
installed versions → different verdicts, which is the point).

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
  (boolean), `row_type` (`both`/`gt_only`/`pipeline_only`).
- Success metric (v1 scoring scope): analyzer verdict matches
  `expected_verdict` for ≥80% of `both` rows. Failures are teaching data —
  either the analyzer prompt needs refinement, or this ground truth needs
  revision (logged below with reasoning, preserving the audit trail).
- Aspirational entries (17 v2 targets) will appear as `gt_only` rows in
  eval_results.csv only after the v2 scanner-widening chunks land; today
  they are excluded from the scored YAML.

## Revision log

- **2026-10-30: CVE-2022-0543 on `eval-db-exposed` changed CONFIRMED -> MITIGATED_BY_CONFIG.**
  Found while re-checking why the week-9-vs-current comparison never surfaced
  this CVE. Measured on the running container: `redis-cli EVAL "return
  type(package)" 0` -> error `nonexistent global variable 'package'`;
  `ldd redis-server` shows no liblua. The CVE exists only in Debian's
  packaging (dynamically linked Lua), so the upstream image is not exploitable.
  **Consequence for earlier numbers:** the v2-13 result (23/24) counted a
  CONFIRMED verdict on this CVE as correct; under the corrected key that
  verdict was a false positive, so v2-13 over-stated accuracy by one entry and
  the attack narrative / remediation generated for it described an exploit
  that does not apply here. The week-9-vs-current comparison (7 -> 11 of 24)
  is unaffected in direction: that CVE was never surfaced by either version,
  so it was wrong before and is still wrong. Revised after seeing results, so
  it is disclosed here rather than folded in silently. Counts: CONFIRMED 7 -> 6,
  MITIGATED_BY_CONFIG 13 -> 14.

- **2026-09-21: v2-6 widening (all 24 entries scored).** `ground_truth.yaml`
  bumped to version 3 with `scoring_scope: v2-with-external-prober`. The 17
  previously-aspirational entries are now mechanically extracted into the
  YAML (see the tables above for the source rationale). Two aspirational-doc
  rows that carry no CVE ID stay out of scoring: the Redis unauth-exposure
  marker on `eval-db-exposed` (an exposure-only finding, not a CVE) and the
  empty `wp-content/plugins/` entry on `eval-cms-plugin` (a scope note, not
  a CVE). Detection-basis is captured per row as `dpkg` / `banner` /
  `probe-fs` (analyzer probe library) — a new column, forward-compatible
  with `run_eval.py` which only reads `cve_id` + `expected`. SSH-absence
  entries (3 rows) use `NO_EVIDENCE` per the 2026-08-05 pending decision.
  Aggregate flip: was 7 scored / 17 unscored, now 24 scored. **Motivation:**
  v2-5 landed the analyzer-side network_state.json consumption, so the
  scoring substrate can finally see reachability + banners; keeping the
  aspirational tier unscored would understate what v2-13's full eval run
  actually measures. This is the promised widening from § v2 Spec success
  criterion #1 (7 → 24 entries).
- **2026-08-10: v2 rescope (Path A).** Split ground truth into "v1 scored"
  and "aspirational v2 targets" tiers. The v1 scored tier contains the 7
  KEV+dpkg CVEs cve-matcher actually surfaces against these containers
  (Heartbleed and Shellshock-family on patched OpenSSL/bash across all
  three, plus a Ghostscript CVE on cms-plugin). All 7 have expected verdict
  `MITIGATED_BY_CONFIG` because every installed package version is
  post-fix. The original 17 entries (banner-detected Apache 2.4.49,
  non-dpkg log4j, absent SSH, non-KEV CVE-2022-0778) move to the
  aspirational tier and are excluded from `run_eval.py` scoring until the
  scanner substrate widens. `ground_truth.yaml` bumped to version 2 with
  `scoring_scope: v1-pipeline-surfaceable`. **Motivation:** the first full
  eval run (2026-08-10) surfaced 0/17 coverage under the original scope,
  which conflated analyzer accuracy with scanner coverage. Splitting the
  two tiers gives an honest, individually-actionable number for each. 
- **2026-08-05: web-vuln row 5 (CVE-2023-38408) — verdict weakened from `NOT_RUNNING` to `NO_EVIDENCE` (pending; see below).** During the first end-to-end chunk-E run against `eval-web-vuln`, Claude correctly pointed out that `ssh -V` returning "not found in PATH" does not conclusively rule out `sshd` being installed at another path. `NOT_RUNNING` requires positive absence proof (`dpkg -l | grep -c openssh-server` returning 0, or `find / -name sshd -type f` returning nothing). Until a stronger absence probe is added, `NO_EVIDENCE` is the honest verdict. Applies to db-exposed row 6 as well. **Fix ownership:** chunk E follow-up probe.
