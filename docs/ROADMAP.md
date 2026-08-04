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

## Now (start immediately)

- [ ] **A. Rename modules to `host-scanner/` + `cve-matcher/`.**
  Outcome: renames applied; all imports, launchers (`run_cli.*`, `run_web.*`),
  `.gitignore` paths, README/LINUX.md/UPSTREAM.md/SETUP-FORKS.md, and
  `scripts/init-repo.ps1` sanity guards updated. Existing scans (host-scanner
  alone; cve-matcher standalone) still run end-to-end. One commit.

- [ ] **B. Scaffold `exposure-analyzer/` package.**
  Depends on: A.
  Outcome: `exposure-analyzer/exposure_analyzer/{agent,probes,prompts,report}.py`
  exist with empty implementations and clear docstrings. `python -c "from exposure_analyzer import agent, probes, prompts, report"`
  succeeds. `requirements.txt` and a minimal README added.

---

## Next (once Now is done)

- [ ] 🔀 **G. `eval-lab/` Docker Compose (3 vulnerable containers).**
  Independent of A-B — can run in parallel.
  Outcome: `cd eval-lab && docker compose up -d` spawns three named
  containers (web-vuln, db-exposed, cms-plugin) each with deliberate CVEs.
  `docker exec container-name python -m host_scanner` completes without
  error. Compose file + Dockerfiles committed.

- [ ] **C. Verdict schema + report integration.**
  Depends on: B.
  Outcome: verdict dict shape defined (`CONFIRMED` / `MITIGATED_BY_CONFIG` /
  `MITIGATED_BY_EXPOSURE` / `NOT_RUNNING` / `NO_EVIDENCE` + `reason` +
  `evidence`). Given a hardcoded fake verdict, `exposure-analyzer` produces
  `verdicts.json` and appends a section to host-scanner's HTML report.
  No AI in the loop yet — this proves plumbing before adding intelligence.

- [ ] 🎯 **D. First probe end-to-end (risk validator).**
  Depends on: C. Real testing needs G but a localhost mock is acceptable
  as an interim.
  Outcome: one CVE (OpenSSH `CVE-2023-38408`) — hardcoded probe (`ssh -V localhost`),
  Claude Agent SDK loop sends output + CVE context to Claude, receives a
  verdict + reasoning, appends to report. This is the architectural proof:
  if the Agent SDK loop, prompt shape, or subscription-backed CLI path has
  a fundamental problem, it surfaces here — not in week 8.

---

## Later (once D is green — repeat the pattern + write)

- [ ] **E. Probe library expansion (4-5 more probes).**
  Depends on: D.
  Outcome: `probes.py` has hardcoded probe templates for the demo-lab CVEs
  (Apache CVE-2021-42013, Redis unauth exposure, WordPress plugin CVE, etc.).
  Analyzer loops over all candidates, produces verdicts for each.

- [ ] **F. `--batch` mode.**
  Depends on: D.
  Outcome: same code path serves interactive + batch; batch answers all
  "run this probe?" prompts automatically.

- [ ] **H. `ground_truth.md` in `eval-lab/`.**
  Depends on: G.
  Outcome: per-container CVE list with expected verdict + reasoning,
  written BEFORE any analyzer run (no back-fitting). Committee-defensible.

- [ ] **I. `run_full_scan.sh` wrapper (top level).**
  Depends on: D, E.
  Outcome: `./run_full_scan.sh <container>` chains host-scanner → cve-matcher →
  exposure-analyzer → HTML report in one command.

- [ ] **J. Full eval runs + `eval_results.csv`.**
  Depends on: E, F, G, H, I.
  Outcome: `run_eval.sh` runs the pipeline across all 3 containers, writes
  a CSV with columns `container`, `cve_id`, `expected_verdict`,
  `actual_verdict`, `time_seconds`. ~30 datapoints total.

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

*(add entries here as the roadmap gets revised mid-build. Format: `YYYY-MM-DD: chunk X — what changed and why`)*

---

## Handoff

Next step: invoke `/build-verify-loop` and start on chunk A (rename modules).
Each chunk in this file is small enough to be a single build-verify-loop cycle.
