# AI-security-agent — v1 build roadmap

Companion to `DESIGN.md`. This file breaks the v1 build into 15 ordered chunks,
each small enough to build and verify independently before moving to the next.

Update this file when a chunk is finished (check the box) OR when reality changes
the plan (add a "changed on YYYY-MM-DD because..." note next to the affected
chunk). Don't just let it go stale.

---

## Legend

- `[ ]` — not started
- `[~]` — in progress
- `[x]` — done and verified
- 🎯 — risk validator (do this earlier than pure dependency order would say)
- 🔀 — independent chunk, can run in parallel with adjacent chunks

---

## At-a-glance status (2026-08-12)

**Code chunks (A-J + F + P + V): all done and verified.** Remaining work is
report writing (K/L/M), defense prep (N), and the release tag (O).
Detailed per-chunk decision rationale + timings in `PROJECT_STATE.md`
decisions log.

```
[x] A B C D E F G H I J P V        code + eval + verification
[ ] K L M N O                       report + defense + tag
```

---

## Now (start immediately)

- [x] **A. Rename modules to `host-scanner/` + `cve-matcher/`.**
  Outcome: renames applied; all imports, launchers (`run_cli.*`, `run_web.*`),
  `.gitignore` paths, README/LINUX.md/UPSTREAM.md/SETUP-FORKS.md, and
  `scripts/init-repo.ps1` sanity guards updated. Existing scans (host-scanner
  alone; cve-matcher standalone) still run end-to-end. One commit.
  **Done: commit `ff16f9e`.**

- [x] **B. Scaffold `exposure-analyzer/` package.**
  Depends on: A.
  Outcome: `exposure-analyzer/exposure_analyzer/{agent,probes,prompts,report}.py`
  exist with empty implementations and clear docstrings. `python -c "from exposure_analyzer import agent, probes, prompts, report"`
  succeeds. `requirements.txt` and a minimal README added.
  **Done: commit `36c1ef3`.**

---

## Next (once Now is done)

- [x] 🔀 **G. `eval-lab/` Docker Compose (3 vulnerable containers).**
  Independent of A-B — can run in parallel.
  Outcome: `cd eval-lab && docker compose up -d` spawns three named
  containers (web-vuln, db-exposed, cms-plugin) each with deliberate CVEs.
  `docker exec container-name python -m host_scanner` completes without
  error. Compose file + Dockerfiles committed.
  **Done: commit `8a65edc`. Build hurdles logged in PROJECT_STATE (buster EOL, pip <23 pyproject issue, redis missing dir).**

- [x] **C. Verdict schema + report integration.**
  Depends on: B.
  Outcome: verdict dict shape defined (`CONFIRMED` / `MITIGATED_BY_CONFIG` /
  `MITIGATED_BY_EXPOSURE` / `NOT_RUNNING` / `NO_EVIDENCE` + `reason` +
  `evidence`). Given a hardcoded fake verdict, `exposure-analyzer` produces
  `verdicts.json` and appends a section to host-scanner's HTML report.
  No AI in the loop yet — this proves plumbing before adding intelligence.
  **Done: bundled into commit `2d47469` (Chunks C-E).**

- [x] 🎯 **D. First probe end-to-end (risk validator).**
  Depends on: C. Real testing needs G but a localhost mock is acceptable
  as an interim.
  Outcome: one CVE (OpenSSH `CVE-2023-38408`) — hardcoded probe (`ssh -V localhost`),
  Claude Agent SDK loop sends output + CVE context to Claude, receives a
  verdict + reasoning, appends to report. This is the architectural proof:
  if the Agent SDK loop, prompt shape, or subscription-backed CLI path has
  a fundamental problem, it surfaces here — not in week 8.
  **Done: bundled into commit `2d47469`. Live Claude smoke-test verified.**

---

## Later (once D is green — repeat the pattern + write)

- [x] **E. Probe library expansion (4-5 more probes).**
  Depends on: D.
  Outcome: `probes.py` has hardcoded probe templates for the demo-lab CVEs
  (Apache CVE-2021-42013, Redis unauth exposure, WordPress plugin CVE, etc.).
  Analyzer loops over all candidates, produces verdicts for each.
  **Done: bundled into commit `2d47469`. 4 probes added: Apache x2, Redis, Log4j. Added `docker_exec_probe_runner` + `--target-container` CLI flag.**

- [x] **F. `--batch` mode.**
  Depends on: D.
  Outcome: same code path serves interactive + batch; batch answers all
  "run this probe?" prompts automatically.
  **Resolved 2026-08-10 as chosen-not-to-implement.** Reason: v1
  `ProbeTemplate.__post_init__` refuses to register any probe with
  `safe=False`, so the entire `KNOWN_PROBES` library is non-destructive
  by construction and runtime per-probe confirmation is redundant. The
  `AgentConfig.interactive` field + CLI `--batch` flag were removed
  (they were no-ops -- the analyzer never actually consumed the flag).
  If v2 introduces higher-risk probes (state-mutating, non-loopback
  network calls), reintroduce the confirmation gate with a specific
  threat model in mind, not preemptively.

- [x] **H. `ground_truth.md` in `eval-lab/`.**
  Depends on: G.
  Outcome: per-container CVE list with expected verdict + reasoning,
  written BEFORE any analyzer run (no back-fitting). Committee-defensible.
  **Done: commit `82242df`. 18 CVE datapoints (later rescoped to 7 in ground_truth v2 — see chunk P).**

- [x] **I. `run_full_scan.sh` wrapper (top level).**
  Depends on: D, E.
  Outcome: `./run_full_scan.sh <container>` chains host-scanner → cve-matcher →
  exposure-analyzer → HTML report in one command.
  **Done: commit `60bdb2e`. Real-server counterpart `scripts/scan-local-host.sh` added in commit `1f24221`.**

- [x] **J. Full eval runs + `eval_results.csv`.**
  Depends on: E, F, G, H, I.
  Outcome: `run_eval.sh` runs the pipeline across all 3 containers, writes
  a CSV with columns `container`, `cve_id`, `expected_verdict`,
  `actual_verdict`, `time_seconds`. ~30 datapoints total.
  **Done: commits `39db4c6` (scaffolding) + `60f53ba` (execution). Baseline 14%, rose to 100% after chunk P prompt fix. CSV has 3 row types (both/gt_only/pipeline_only) for honest coverage picture, not vanity accuracy.**

---

## Added mid-build (2026-08-10)

- [x] **P. Prompt tightening (14% → 100% on scored set).**
  Not in the original roadmap. Added after chunk J revealed a systematic
  verdict-labeling inconsistency: analyzer's *reasoning* was correct on
  every case, but the *verdict label* was inconsistent (`NO_EVIDENCE` and
  `NOT_RUNNING` mistakenly used where `MITIGATED_BY_CONFIG` was correct).
  Three-line SYSTEM_PROMPT edit resolved it.
  **Done: commit `b338f05`. Report chapter 5 narrative: "measured → root-caused → patched → re-measured, 14→100% on one prompt edit."**

- [x] **V. Verification / review-stage pass.**
  Not in the original roadmap. Formal review-stage audit written into
  `docs/VERIFICATION.md` (Phase 1 Claude independent + Phase 2b
  adversarial self-review). Fixed 5 deployment gaps inline (missing
  `eval-lab/requirements.txt`, `LICENSE`, `bootstrap-linux.sh`,
  host-scanner cwd bug, cve-matcher requirements comment). Test count
  38 → 52; coverage 52 → 87%. Discovered + fixed over-claimed
  `safe=True` invariant (now `frozen=True` dataclass).
  **Done: commit `c5bc1ce`. Substitutes for the deferred formal dual-engine cross-review — see PROJECT_STATE for the `agy`-tooling issue that blocked the Gemini path.**

---

## Later (report + defense + tag)

- [ ] **K. Report chapters 1-3 draft.**
  Depends on: (design finalized — already true).
  Can overlap with J.
  Outcome: 緒論 / 相關研究 / 系統設計 drafted at target page count. Bi-weekly
  advisor review.

- [ ] **L. Report chapters 4-5 draft.**
  Depends on: J (needs the eval data for chapter 5).
  Outcome: 實作 / 評估 drafted; chapter 5 tables populated with real
  numbers from eval_results.csv.

- [ ] **M. Report chapters 6-7 + polish pass.**
  Depends on: L.
  Outcome: 討論與未來工作 / 結論 drafted; full report proofread; page count
  in the 15-25 range.

- [ ] **N. Defense prep.**
  Depends on: I (working demo).
  Outcome: 15-20 slide deck; demo rehearsed at least 3 times end-to-end;
  3-minute backup demo video recorded 3 days before defense.

- [ ] **O. `v1.0-defense` git tag.**
  Depends on: everything above.
  Outcome: `git tag v1.0-defense` at the exact commit demoed. Repo state
  frozen for the defense record.

---

## Risk notes

- **Chunk D is the single riskiest item in the whole plan.** If the Claude
  Agent SDK loop, subscription-backed CLI auth, or probe/interpretation
  cycle has a fundamental issue, discovering it after chunk M (report
  written, expecting to demo) is catastrophic. Discovering it in chunk D
  means we can adjust design cheaply. Prioritize.
- **G (Docker lab) can be done any time after B.** If you get impatient with
  code work, spend a session building containers — it unblocks D's real
  testing without touching the exposure-analyzer code path.
- **Chunks K-M are report writing.** They're not "less work" than code —
  budget accordingly, ~1 week total at Claude-paced.

---

## Changed-plan log

- **2026-08-10: chunk F — resolved as chosen-not-to-implement.** `AgentConfig.interactive` field + CLI `--batch` flag were no-ops (analyzer never consumed the flag); `ProbeTemplate.__post_init__` already enforces `safe=True` at construction, making per-probe runtime confirmation redundant. Removed both. See chunk F entry above for full rationale + v2 re-entry criteria.
- **2026-08-10: added chunk P** (prompt tightening) — surfaced by chunk J's 14% baseline. Not originally planned; added because the eval loop discovered a real, measurable issue that a targeted prompt edit could fix.
- **2026-08-10: added chunk V** (verification pass) — review-stage audit written into `docs/VERIFICATION.md`. Not originally planned but recommended by dev-pipeline SKILL for the review stage before defense.
- **2026-08-10: ground_truth rescope (Path A).** Original ground_truth (18 aspirational CVEs) split into v1-scored subset (7 KEV∩dpkg CVEs the pipeline can actually see) + aspirational v2 targets. Reason: honest scoring against what the tool can surface today rather than against what it could surface if the scanner were extended.

---

## Handoff

Code + eval + verification chunks (A/B/C/D/E/F/G/H/I/J/P/V) all done as of
2026-08-12. Next chunk is **K** (report chapters 1-3: 緒論 / 相關研究 /
系統設計). Suggested workflow for K: one chapter at a time so direction
mistakes stay contained to one chapter's worth of prose.

Each remaining chunk is still small enough for a single `/build-verify-loop`
cycle. For writing chunks (K/L/M), the loop shape is: draft → advisor
review → revise, per chapter.
