# Poster numbers

Status of this file: consolidated 2026-11-03 from README.md (Results), PROJECT_STATE.md (v3-6b to v3-11) and the raw
result files under `eval-lab/`; held-out set 4 and Django/Airflow added 2026-11-05 (v3-13). `results.png` was redrawn 2026-11-05 by
`make_results.py` (section 3 on the left, section 1 blind sets with Wilson intervals on the right); the numbers are
typed into that script, so rerun it if section 1 changes. Django/Airflow are not on the chart.

Two kinds of number appear below. Do not mix them on the poster.

- **Recall (section 1, 2):** "the expected CVE appears in our candidate list / in Trivy's or Grype's report".
  This is NOT a verdict. For us it means "the tool would have looked at it"; for Trivy and Grype it means "they
  listed it". Our side is the more generous reading, so the comparison flatters us slightly.
- **Verdict (section 3, 4):** "the model stage called the expected CVE `CONFIRMED`".

## 1. Candidate recall against Trivy 0.58.1 and Grype v0.86.1 (same images, Vulhub, answer key = the CVE the directory exists to demonstrate)

| Set | Size | Status of the number | Ours | Trivy | Grype |
|---|---|---|---|---|---|
| Development | 15 | code was tuned on it; NOT evidence | 15 | 7 | 9 |
| Held-out 1 | 10 evaluable of 12 | seen afterwards, no longer blind | 6 | 5 | 5 |
| Held-out 2, first run | 10 | **blind**, code before v3-10 | 3 | 3 | 5 |
| Held-out 3 | 10 | **blind**, current code | 3 | 2 | 2 |
| Held-out 4 | 10 | **blind**, current code, pre-registered 26171a9 | 4 | 2 | 5 |
| **Pooled blind (set 2 first run + sets 3 and 4)** | **30** | | **10** | **7** | **12** |
| Django + Airflow | 2 | never scored before; current code; listed separately, not pooled | 1 | 2 | 2 |

- Held-out 2 after the v3-10 fixes: ours 7/10. Development data now (the gaps were fixed after seeing them). Do not print as blind.
- Regression, 25 earlier runnable scenarios rerun on the v3-10 code: 21 hit before, 21 after, 0 lost, 0 gained.
- Complementarity (expected CVE found by at least one tool):
  held-out 2: Trivy + Grype 5/10, with ours 7/10 (as recorded at the time; not recomputed from files);
  held-out 3: Trivy + Grype 2/10, with ours **3/10** (an earlier version of this file said 4/10; recomputed 2026-11-05 from
  the raw candidate and baseline files, no arm adds a fourth); held-out 4: Trivy + Grype 5/10, with ours 6/10.
  Found by us and by neither image scanner: flink, wordpress (set 2), druid (set 3), ghostscript (set 4).
- Candidate recall on the development set by stage (KEV + banner -> + NVD -> + OSV): 5 -> 9 -> 12 of 15; 15/15 after the
  v3-7b catalog and whole-filesystem pass (tuned on).
- Not scored: Django and Airflow (cannot start; CRLF in the Vulhub clone on Windows, not a tool result).

Reading the pooled blind row: 10 / 7 / 12 of 30 (Wilson 95%: [0.19,0.51], [0.12,0.41], [0.25,0.58]) overlap completely.
Grype is ahead of us by 2 on the point estimate; Trivy's hits are a subset of Grype's in all three sets. Say
"complementary", not "better". Earlier pooled figure over sets 2 (first run) and 3 only: 6 / 5 / 7 of 20.
Held-out 4 alone: ours 4/10 [0.17,0.69], Trivy 2/10 [0.06,0.51], Grype 5/10 [0.24,0.76].

## 2. Why the misses happen (checked after the runs, no code changed)

| Reason | Held-out 3 | Held-out 2 (before fixes) |
|---|---|---|
| Scanner cannot name the product (Go single binary, no catalog row, no version file) | minio, 1panel, metabase, coldfusion, elfinder | kibana, superset, joomla probe |
| Ecosystem not read | jumpserver (no PyPI libs found) | rails (RubyGems), grafana / postgres / zabbix (Alpine) |
| Network probe saw nothing | jimureport | none |
| Data gap (library found, no CVE entry under it) | none | n/a (seen earlier: OFBiz, JBoss, Confluence, Spring Cloud Gateway) |
| Lost to the per-product cap of 15 | none | joomla CVE-2015-8562 (CVSS 7.5 behind 63 higher scores) |

Held-out 4 (checked after the run, no code changed):

| Reason | Scenarios |
|---|---|
| Expected CVE is below the CVSS 7.0 floor of the OSV stage (found the library, dropped the advisory) | vite (CVE-2025-32395 is MODERATE; 16 advisories dropped) |
| Scanner cannot name the product (no catalog row, no version file, built from source) | imagemagick 7.1.0-49, adminer, erlang/OTP, chartbrew (the app itself) |
| Whole-image cap of 60 candidates | chartbrew (1457 libraries, 144 CVEs at CVSS >= 7.0, 60 kept) |
| Scan could not run in the target | ingress-nginx (a K3s image: no glibc or musl loader, so neither scanner binary executes). Image scanners work from outside and are not affected. |

Harness notes for sets 1 and 4 (not scanner code): Django and Airflow could not start only because the Vulhub clone is
`autocrlf=true`; LF copies from `git archive` fix it (clone untouched). Airflow also needs its README's `airflow-init` run
first, and the harness picked the one-shot init container; scenarios may now set `pre_run` and `service` (only Airflow does).

Known unsupported: Alpine older than 3.12 (postgres 9.6.7, zabbix 3.0.3 stay uninventoried).

## 3. Answer key written by the author (3 self-built containers, 24 entries, 6 expected CONFIRMED)

| Claim | Number | Caveat to print next to it |
|---|---|---|
| Answer-key entries correct, week 9 -> banners -> NVD | 7 -> 11 -> 13 of 24 | key written by the author, corrected once (CVE-2022-0543) |
| Real vulns found | 0 -> 2 -> 3 of 6 | week 9 and banners are the mean of 2 runs, NVD is 1 run |
| False CONFIRMED | 0 in all three | same sample |
| Unlisted CONFIRMED from NVD | 28; 9 checked (Redis), all 9 hold; 19 unreviewed | "hold" = version affected and feature reachable; nothing exploited |
| Local model | Qwen3.5-9B scored 11 of 24, same as Claude on the first two rows | not completed for the NVD row |

## 4. Vulhub, verdict level (15 scenarios, 1 run each, Claude engine)

| Claim | Number | Caveat |
|---|---|---|
| Expected CVE called CONFIRMED | 5 of 15 with KEV + banners; 6 of 15 with NVD | NVD model stage run only on nginx and bash |
| Misses of candidate sourcing, not judgment | 8 of 15 | expected CVE never became a candidate |
| Wrong verdict | 1 (bash 4.3, binary replaced behind a patched dpkg revision) | the tool trusts the package database |

Model stage on OSV candidates (3 scenarios): expected CVE CONFIRMED in nginx, ActiveMQ, Jenkins.

### 4b. Model stage on held-out set 3 (Gemini 4 Argon through agy, sampled, 1 run)

| Claim | Number | Caveat |
|---|---|---|
| Expected CVE judged CONFIRMED, when it is a candidate | 3 of 3 (gradio, geoserver, druid) | the expected CVE is a candidate in only 3 of 10 scenarios; a different model from the Claude rows |
| Random sample of other candidates: CONFIRMED | 76 of 150 (51%) | 15 per scenario, seed 20261104, drawn over all candidates |
| Same sample: MITIGATED_BY_CONFIG / NO_EVIDENCE / MITIGATED_BY_EXPOSURE / NOT_RUNNING | 45 / 15 / 8 / 6 | |
| What the 76 CONFIRMED reasons rest on | 76 cite an open port, 10 a probe, 4 that the code is loaded or used | read from the reasons, not verified against the targets |
| Same Argon run repeated (r5 vs r3, same model, same 153 calls, no errors) | same verdict 131 of 153 (86%, kappa 0.78); CONFIRMED 79 then 78, in both 72; CONFIRMED-or-not agrees 140 of 153; expected CVEs 3 of 3 CONFIRMED both times | run-to-run noise of one model, not accuracy; the biggest swings are in the two scenarios with no exposed port (jimureport 2 -> 0, minio 2 -> 0) |
| Claude re-judging the same 79 CONFIRMED (Argon: 3 expected + 76 sampled) | still CONFIRMED 54 (68%); not 25 (NO_EVIDENCE 14, MITIGATED_BY_CONFIG 9, other 2); expected CVEs 3 of 3 still CONFIRMED | $2.51, 80 calls, 1 run; agreement is not correctness (see PROJECT_STATE v3-12) |

CONFIRMED here means "affected version present on a host with a reachable service" (e.g. curl 7.81 on a host whose
Go service listens on 10086). It is not "exploitable". No human review of the 76 has been done; do not print a precision.

## 5. Cost and effort

| Item | Number | Caveat |
|---|---|---|
| Model cost per verdict call | $0.02-0.03 (earlier text-only measurement: 33.5k -> 3.3k input tokens, $0.207 -> $0.025) | one measurement each |
| Model-stage spend, v3-8 round | about $5.4 | 3 scenarios plus reruns for the budget-order change |
| Call cap in the default settings | 60 calls / $2.00 | `exposure_analyzer/settings.py`; KEV first, then sources in rotation by CVSS |
| NVD discovery time | about 1000 s per container vs about 90 s | adds 30-40 candidates per container |
| Trivy alert volume | 21-2195 HIGH+CRITICAL CVEs per image, median about 207 | counts only; we did not measure how many are false |
| Tests | 583 (host-scanner 129, exposure-analyzer 211, network-prober 41, attack-simulator 67, fix-publisher 84, cve-matcher 51) | count of passing tests, not coverage |

## 6. Not measured. Do not print any number for these.

- **Precision / false-positive rate / "noise reduction".** The only answer key is the one expected CVE per scenario.
  A CONFIRMED on any other CVE has not been checked (except the 9 Redis ones).
- The model stage on held-out set 2, and any human-checked precision of the held-out 3 verdicts.
- A comparison against pure Claude with shell access on the v3 Vulhub sets. Only the early v2 runs exist
  (`docs/VERIFICATION.md`, 3 containers plus Apache CVE-2021-41773); they are not comparable to section 1.
- Windows or non-Linux targets. Debian/Ubuntu is the tested family; Alpine >= 3.12 and RHEL-family were exercised in the Vulhub runs only.

## 7. Wording that the evidence supports

Print: "tells you which matching CVEs are affected, present and reachable *on this host*, with a reason"
(CONFIRMED is not "exploitable"; nothing is exploited); "finds hand-installed and uberjar services that
image scanners miss (flink, wordpress, druid); complementary to Trivy and Grype, not a replacement"; "two blind sets of 10
new scenarios each: 3 and 4 found vs 2 and 2 (Trivy) and 2 and 5 (Grype); pooled over three blind sets 10, 7 and 12 of 30".

Do not print: "more accurate", "fewer false positives", "complete assessment", "better than Trivy / Grype".

Known gaps to list: KEV-only default coverage, Debian backports unverified, dpkg-vs-binary mismatch (bash), posture
findings not in the report, Linux only, products the scanner cannot name (Go binaries, commercial software), Alpine < 3.12,
per-product cap of 15.
