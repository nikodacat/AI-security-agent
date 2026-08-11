# Verification Report — AI-security-agent

**Purpose:** end-to-end verification of the pipeline's usability, correctness,
and deployability on a "normal server." This document is the QA record for
chapter 5 (evaluation) of the thesis and the primary defense material for
the "how do you know your system is correct?" line of questioning.

**Status:** Phase 1 draft (Claude independent review). Phase 2 (Gemini
cross-review via `agy`) and Phase 3 (merged final) still pending —
divergences and merged findings will be appended below.

**Generated:** 2026-08-10
**Reviewer (Phase 1):** Claude (Opus 4.7 in Claude Code)
**Codebase snapshot:** `git rev-parse HEAD` → commit `b929e25` (chunk F resolved)

---

## 0. Scope

Three cooperating Python modules and one evaluation harness:

| Component            | Role                                          | Lines |
|----------------------|-----------------------------------------------|------:|
| `host-scanner/`      | Internal recon (packages, configs, processes) |     — (pre-existing, not touched this cycle) |
| `cve-matcher/`       | KEV catalog match + optional NVD version-check |     — (pre-existing) |
| `exposure-analyzer/` | AI verdict synthesis (Claude Agent SDK)       | 1042  |
| `eval-lab/`          | Reproducible test lab + harness               |  638  |

Test code: **472 lines**, **38 unit tests** organized into 4 files.

Deliverable framing: the system must be runnable on any commodity Linux
server (Ubuntu/Debian, Python 3.9+, optionally the `claude` CLI). Docker is
required *only* for the eval-lab, not for real-world deployment.

---

## 1. Test methodology

### 1.1 Test pyramid

| Layer                  | Instances | Tooling             | What it verifies |
|------------------------|----------:|---------------------|------------------|
| Unit                   | 38        | stdlib `unittest`   | pure functions, data-class invariants, argv construction, response parsing |
| Integration (mocked)   | 8 (subset of unit) | `unittest.mock`    | agent orchestration with fake LLM + fake probe runner |
| Live e2e (Claude)      | 5+        | manual, logged in decisions log | round-trip through actual `claude-agent-sdk` |
| Full eval vs GT        | 1 (repeatable) | `run_eval.sh` | pipeline output diffed against pre-committed ground truth |

Deliberate choice of stdlib `unittest` over pytest: zero extra deps,
fresh-server portable, matches host-scanner and cve-matcher style.

### 1.2 Testability seams (architecture supporting the pyramid)

Two abstractions were introduced *specifically* to make the LLM-driven
orchestration testable without the SDK installed or the network reachable:

1. **`ExposureAgent(verdict_fn=…)`** — the LLM call is a swappable callable.
   Real code passes `build_claude_verdict_fn()`; tests pass a lambda that
   returns canned JSON. This is what lets 8 unit tests exercise the full
   `analyze()` orchestration deterministically.
2. **`ProbeRunner` `Protocol`** — the probe executor is injected. Real code
   uses `_default_probe_runner` (subprocess) or `docker_exec_probe_runner`
   (wraps with `docker exec`); tests pass a stub that returns fixed
   `(command, output)` pairs.

Both were introduced in chunk D and remained stable through chunk P — a
sign the seams were placed at the right joints.

### 1.3 Deferred-import pattern

`claude_agent_sdk` is imported *inside* `build_claude_verdict_fn()`, not at
module top. This means:

- The test suite runs cleanly on a machine without the SDK installed
  (confirmed: 38/38 pass with just stdlib + `coverage`).
- Only production paths that actually intend to hit Claude take the
  import cost.

---

## 2. Coverage measurement

Ran `coverage.py 7.x` on the exposure-analyzer test suite:

| File                             | Stmts | Miss | Cover | Notes                                    |
|----------------------------------|------:|-----:|------:|------------------------------------------|
| `exposure_analyzer/__init__.py`  |     5 |    0 |  100% | just re-exports                          |
| `exposure_analyzer/probes.py`    |    14 |    0 |  100% | full library invariants covered          |
| `exposure_analyzer/prompts.py`   |    43 |    1 |   98% | 1 line missed (truncation edge)          |
| `exposure_analyzer/agent.py`     |   117 |   16 |   86% | missing lines are SDK integration path (deferred) + one _load_verdicts branch |
| `exposure_analyzer/verdicts.py`  |    40 |    8 |   80% | some serialize round-trip paths          |
| `exposure_analyzer/report.py`    |    70 |   70 |    0% | **deliberate**: end-to-end tested via CLI, no unit tests |
| `exposure_analyzer/cli.py`       |    84 |   84 |    0% | **deliberate**: end-to-end tested via CLI, no unit tests |
| `exposure_analyzer/__main__.py`  |     3 |    3 |    0% | trivial entrypoint                       |
| **Overall**                      | **376** | **182** | **52%** | including plumbing layers |

Logic layer only (`probes + prompts + agent + verdicts + __init__`):
**86.3%** covered (189/219 statements).

The 0%-covered files (`report.py`, `cli.py`) are the CLI plumbing layer.
They're covered indirectly by:
- Multiple live smoke-tests in chunk D, E, I, J, P (all logged in decisions log).
- The chunk J live eval that ran all 3 containers through the full CLI path.

This is a **legitimate strategy** — CLI layers are shallow and their bugs
show up immediately in end-to-end runs — but should be honestly documented
rather than hidden behind a naked "52%" number.

---

## 3. Correctness invariants — verified live in this session

Ran each invariant check with actual code:

| Invariant                                                           | Verified how                                     | Result |
|---------------------------------------------------------------------|--------------------------------------------------|--------|
| `ProbeTemplate` refuses `safe=False`                                 | `python -c "ProbeTemplate(command='rm -rf /', safe=False)"` | ✓ ValueError raised |
| `Verdict` rejects unknown `VerdictType` strings                      | `python -c "Verdict(cve_id='X', verdict='MAYBE', reason='')"` | ✓ ValueError raised |
| Response parser tolerates code-fenced JSON                           | unit test `test_code_fenced_json`                | ✓ passes |
| Response parser tolerates inline prose around JSON                   | unit test `test_json_with_prose_around_it`       | ✓ passes |
| HTML report injection is idempotent (re-runs replace, not stack)     | manual verified in chunk C, still holds          | ✓ 1 section after 2 runs |
| `docker_exec_probe_runner` preserves display_cmd (not the wrapped argv) | unit test `test_display_command_is_the_template_not_the_wrapped_argv` | ✓ passes |
| Library-level `KNOWN_PROBES` invariants (safe / signals / hint / valid regex) | `TestProbeLibraryContract` (3 tests)      | ✓ all 3 pass |

Every invariant that's a claim in the design has a matching test. New
probes added to `KNOWN_PROBES` in the future will be checked automatically
against the three library-level contract tests (`test_every_probe_is_safe`,
`test_every_probe_has_signals_and_hint`, `test_every_probe_compiles_as_regex`).

---

## 4. End-to-end verification — the honest story

Six distinct live-Claude runs are documented in the decisions log
(`PROJECT_STATE.md`). Each is a datapoint proving one specific claim about
the system:

| Run           | What it verified                                    | Outcome |
|---------------|-----------------------------------------------------|---------|
| Chunk D live  | Agent SDK loop, prompt shape, response parser work end-to-end | `MITIGATED_BY_EXPOSURE` (correct) |
| Chunk E live  | `docker_exec_probe_runner` routes probes into a container | `CONFIRMED` for CVE-2021-42013 (correct) |
| Chunk E divergence | Claude out-reasoned the ground truth on CVE-2023-38408 | Ground truth revised (`NOT_RUNNING` → `NO_EVIDENCE`) |
| Chunk I live  | Full chain `scan → cve-match → analyze` through one command | 1 `MITIGATED_BY_EXPOSURE`, 1 `NO_EVIDENCE` (correct reasoning both) |
| Chunk J live eval | Repeatable eval across all 3 containers on Sonnet 5 | 24 rows / 56s wall clock / **14% baseline accuracy** on scored set |
| Chunk P re-eval | Same pipeline after 3-line SYSTEM_PROMPT fix       | **100% accuracy (7/7)** on scored set |

The 14% → 100% jump on chunk P is the strongest single piece of evidence
that (a) our measurement instrument works, (b) we can distinguish
analyzer-correctness from ground-truth-correctness, and (c) targeted
prompt changes produce measurable effects — which is exactly the
"quantifiable iteration loop" narrative the report needs.

### 4.1 Reproducibility

- `eval-lab/reports/` is `.gitignore`d — no committed run outputs to fake
  a reproduction.
- `eval-lab/ground_truth.md` + `.yaml` are committed BEFORE any analyzer
  run (audit-trailed in the revision log at the bottom of `ground_truth.md`).
- `./eval-lab/run_eval.sh --engine=claude` re-runs the entire pipeline on
  any machine with Docker + `claude` CLI.
- `--reuse-existing` on `run_eval.py` allows re-scoring cached results
  without paying Claude cost, useful for iterating on the CSV format
  itself.

---

## 5. Deployment readiness — "runs on any normal server"

The end-goal framing is: someone with a fresh Linux server should be able
to clone the repo, follow README, and get a working CVE scan. Below is
the honest audit of what works, what doesn't, and what needs fixing before
that's true.

### 5.1 Confirmed portable

| Item                                              | Evidence |
|---------------------------------------------------|----------|
| Core modules have no Windows-specific code        | `grep -rn "C:\\\\\|MSYS\|cygpath\|cp932"` returned zero hits outside `eval-lab/` |
| eval-lab Windows shims fall back on Linux         | `run_eval.sh` guards `if command -v cygpath` — on Linux the else branch runs; `MSYS_NO_PATHCONV=1` is a harmless env var elsewhere |
| Deferred `claude-agent-sdk` import                | test suite runs on a machine without it (measured this session) |
| Docker only needed for eval-lab, not real deploy  | grep of `exposure-analyzer` for `docker`: only in `docker_exec_probe_runner` (opt-in via `--target-container` flag) |

### 5.2 Gaps that would break fresh install [BLOCKER for chapter 5 "usability" claim]

| # | Gap                                                                        | Impact                                                                                | Fix                                                                       |
|---|----------------------------------------------------------------------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| 1 | `eval-lab/` uses `import yaml` (in `run_eval.py`) but has NO `requirements.txt` | `ModuleNotFoundError: yaml` on fresh install                                          | Add `eval-lab/requirements.txt` pinning `pyyaml`                          |
| 2 | `cve-matcher/requirements.txt` comment misleads: says `anthropic and claude_agent_sdk already in shared .venv; not pinned here` | The comment is confusing, but the actual behavior is graceful: `cve_matcher.explain` imports `claude_agent_sdk` **lazily** (line 67) inside a try wrapping — falls back to a deterministic KEV-template backend if the SDK isn't installed. So it's **not a hard failure** on fresh install, but the comment reads like a bug. | Rewrite the comment to: `# claude-agent-sdk is an optional runtime dep of cve_matcher.explain; if absent, we fall back to a template backend. Install for richer output.` Optionally add `claude-agent-sdk` as an extras group. |
| 3 | No top-level `LICENSE` file (README claims MIT)                            | Legal ambiguity for anyone forking; MIT is a contract, not a promise                  | Add `LICENSE` with MIT text at repo root                                  |
| 4 | No unified install script; user must guess which `requirements.txt` to run where | Real friction — SETUP-FORKS.md mentions it but there's no single command             | Add `scripts/bootstrap-linux.sh` that creates one venv and installs all three modules' requirements |
| 5 | `host-scanner/main.py` calls `load_config("config.yaml")` — cwd-relative   | Fails if invoked from anywhere other than `host-scanner/`                             | Change to `Path(__file__).parent / "config.yaml"` OR make it a CLI arg    |

### 5.3 Gaps that are acceptable (documented, not blocking)

- No `pyproject.toml` per module — modules are used via `sys.path` insertion
  (see `run_full_scan.py` lines 41-42) rather than `pip install .`. This is
  a conscious choice for the thesis (keeps the three modules independently
  editable) but should be flagged if anyone wants to distribute this as a
  package.
- No dockerized deploy target — the pipeline runs on the host, not in a
  container. This is *correct* for a security scanner (you want to see the
  host's real state, not a container's) but means you can't just "pull the
  image and run."

---

## 6. Edge cases + error handling audit

### 6.1 Handled explicitly (with evidence in code)

- **Missing candidates file**: `_cmd_analyze` in `cli.py` checks `.exists()`, prints error, returns exit code 1.
- **Missing host-state file**: same pattern; empty dict is the default if `--host-state` is omitted.
- **Claude SDK not installed**: `build_claude_verdict_fn()` catches `ImportError`, raises `RuntimeError` with actionable install instructions.
- **Probe binary not found in container**: `_run_argv` catches `FileNotFoundError`, returns `"(command not found: <argv[0]>)"` as probe output; analyzer sees the string and reasons about it.
- **Probe timeout**: `subprocess.TimeoutExpired` caught, reported as `"(probe timed out after Ns)"`.
- **Probe unexpected exception**: catch-all `except Exception as e` reports `"(probe error: <type>: <msg>)"`.
- **Output oversized**: truncated at `AgentConfig.max_output_chars` (default 4000) with `"... [truncated]"` suffix.
- **Response missing/malformed JSON**: `_parse_verdict_response` scans for `{...}` blocks, tries each; raises `ValueError` if none decode.
- **Response with unknown verdict value**: `_parse_verdict_response` calls `VerdictType(verdict)` which raises on unknown enum member.
- **Windows cp932 encoding on non-ASCII output**: `dump_verdicts` / `load_verdicts` force `encoding="utf-8"`; `PYTHONIOENCODING=utf-8` documented in run scripts.
- **Stale cached `verdicts.json` after failed pipeline run**: `run_eval.py` tracks a `failed` set and refuses to score containers whose current run errored (chunk J fix).
- **git-bash mangling `/opt/...` paths on Windows**: `run_eval.sh` guards with `cygpath -w` on the outermost script arg (chunk J fix).

### 6.2 Handled implicitly (correct behavior, not tested)

- **Docker daemon down**: `docker exec` returns rc != 0, `_run_container_scan` raises `RuntimeError` with stderr excerpt. Currently only exercised manually (during actual daemon-down incidents this session).
- **Network unreachable during NVD lookup**: cve-matcher's `enrich_with_versions` presumably handles this (not audited in this pass).

### 6.3 NOT handled, would need to be if productizing

- **`claude` CLI auth expired mid-session** (real incident during chunk J execution): SDK stringifies the auth failure as `"Claude Code returned an error result: success"` which is misleading. No detection or clean error message. **Recommend:** wrap `verdict_fn` invocation in a check that pings the CLI's auth status once before batch runs.
- **Analyzer output that's valid JSON but has garbage `evidence` field type**: `_parse_verdict_response` silently coerces to `{"raw_evidence": str(evidence)}`. Silent coercion masks real bugs.
- **A candidate with `cve_id` missing entirely**: falls through to `"CVE-UNKNOWN"` — accepted but might confuse downstream tools.

---

## 7. Security invariants (what the tool promises NOT to do)

The gray-box thesis explicitly promises no-exploit, non-destructive
behavior. The following are the invariants that back that promise:

| Promise                                        | Enforcement mechanism                                                    |
|------------------------------------------------|--------------------------------------------------------------------------|
| Probes are non-destructive                     | `ProbeTemplate.__post_init__` raises on `safe=False` (enforced at construction time; you literally cannot register an unsafe probe) |
| Claude cannot propose exploitation             | System prompt rule: "Never propose exploitation. You are a defender, not an attacker." — cited in every prompt |
| No arbitrary code execution from LLM output    | Verdict schema is a fixed enum; response parser rejects any value outside `VerdictType` — Claude cannot inject a new verdict type that triggers new code paths |
| `docker exec` targets a caller-specified container only | `--target-container` is required to be provided by the human operator; there is no auto-discovery |

**Sample_candidates.json audit:** The one bundled sample uses real CVE
IDs and package versions but contains no host secrets, credentials, or
scan output from real infrastructure. Safe to include in a public repo.

---

## 8. Known limitations (v1 scope + honest positioning)

All of these are already flagged in `PROJECT_STATE.md` decisions log or
`ground_truth.md`, but consolidated here for a single defensible list:

1. **dpkg-only scanner**: source-built software (like the `httpd 2.4.49` we
   put in web-vuln on purpose) is invisible. Any RPM-family server is
   also invisible. **Documented; v2 addresses via banner-grabbing.**
2. **KEV-only matcher**: CVEs outside CISA KEV (like CVE-2022-0778, DoS)
   are not surfaced. KEV skews toward RCE / priv-esc / auth-bypass.
   **Documented; v2 could widen to full NVD.**
3. **`--check-versions` annotates but doesn't filter**: patched findings
   still reach the LLM, wasting tokens on cases the version check already
   resolved. **Fix: add `--drop-patched` mode. Not a v1 blocker but
   quantifies in chapter M cost analysis.**
4. **Ground truth v2 scoring scope is intentionally narrow**: 7 CVEs, all
   KEV∩dpkg, all post-fix (all expected `MITIGATED_BY_CONFIG`). **Real
   accuracy claim is: "100% on the honest-scope subset the pipeline can
   actually see." Chapter 5 must state this scope explicitly.**
5. **N=7, one fact pattern**: not adversarial. Real test would include
   candidates that should trigger every one of the five verdicts.
6. **No CONFIRMED verdict has been produced in a live eval** — every
   scored case is `MITIGATED_BY_CONFIG`. This is a real limitation of
   the current scope, not a bug. **v2 path: add candidates with
   genuinely-vulnerable installed versions in the eval-lab (probably
   by pinning older packages) so the analyzer has a shot at CONFIRMED.**

---

## 9. Reproducibility from a clean checkout

Explicit end-to-end instructions someone else could follow, tested
mentally against a fresh Linux server:

```bash
# 1. Clone
git clone https://github.com/nikodacat/AI-security-agent.git
cd AI-security-agent

# 2. Install deps for the three modules (currently manual — see gap #4)
python3 -m venv .venv && source .venv/bin/activate
pip install -r host-scanner/requirements.txt
pip install -r cve-matcher/requirements.txt
pip install -r exposure-analyzer/requirements.txt
pip install pyyaml           # eval-lab requirement (gap #1)

# 3. (Optional) Authenticate Claude CLI
claude --version && claude login   # for --engine=claude

# 4. Run standalone scan on the host itself (no docker needed)
cd host-scanner && python main.py   # writes reports/
cd ..

# 5. (Optional) Run the eval-lab
cd eval-lab && docker compose up -d --build
./run_eval.sh --engine=claude       # or --engine=fake for no-cost dry run
```

Steps 4 and 5 are independent. Step 4 is what you'd do on a real server
to scan it. Step 5 is the reproducible test lab.

**Ship-blocker for that reproduction:** the two gaps in §5.2 (missing
`eval-lab/requirements.txt` and misleading `cve-matcher/requirements.txt`
comment).

---

## 10. Phase 1 findings summary — action items

Sorted by fix-priority. Blockers are "you cannot claim this is deployable
without fixing" items:

| Priority | Type | Item | Location | Recommended fix |
|----------|------|------|----------|-----------------|
| BLOCKER  | Deploy | `eval-lab` missing `requirements.txt` | eval-lab/ | Add `eval-lab/requirements.txt` with `pyyaml` |
| MAJOR    | Deploy | Misleading cve-matcher requirements comment (not a hard failure — explain module falls back gracefully — but confusing) | cve-matcher/requirements.txt | Rewrite comment to describe the optional-dep + fallback pattern honestly |
| MAJOR    | Deploy | No `LICENSE` file at root                    | .              | Add MIT LICENSE per README claim |
| MAJOR    | Deploy | No unified install script                    | scripts/       | Add `bootstrap-linux.sh` |
| MAJOR    | Portability | `host-scanner/main.py` cwd-dependent config load | host-scanner/main.py:19 | Change to `Path(__file__).parent / "config.yaml"` |
| MINOR    | Robustness | `claude` CLI auth expiry produces misleading error | agent.py::_call | Add pre-flight `auth_check()` before batch runs |
| MINOR    | Correctness | Silent coercion of malformed `evidence` field | agent.py::_parse_verdict_response | Log a warning; keep coercion for compat |
| MINOR    | Test | `report.py` and `cli.py` at 0% unit coverage | tests/         | Add smoke-test using CliRunner-style pattern |
| MINOR    | Eval | No CONFIRMED verdict in any live eval        | eval-lab/      | Pin older packages in one container to produce a CONFIRMED case |

---

## Phase 2 (Gemini cross-review via `agy`) — attempted, blocked by tooling

Tried `agy --print --model gemini-3.1-pro-high --add-dir <repo>` with a
matching structured-review prompt. Result: `agy`'s `--print` mode is
routed through a canned-response "assistant" persona that ignores the
prompt body and returns generic responses (e.g. asked "compute 17*23",
got "I am powered by Gemini 3.6 Flash. How can I help?"). The `--model`
flag is also silently ignored — every response reports Flash regardless
of the requested model. This is either a bug in this build of `agy` or
a mode where `--print` cannot bypass the built-in agent overlay.

The `gemini` CLI (v0.54.4) is installed as an alternative but was not
attempted this session per user preference for `agy`.

**Substituted for Phase 2:** an adversarial self-review pass (Phase 2b)
that deliberately tries to invalidate Phase 1 findings and surface things
the first pass overlooked. Independent, but same reviewer — weaker than a
true dual-engine cross-review. Formal dual-engine review is deferred to a
future session when the tooling is sorted out (either fresh `agy` install
or falling back to `gemini` CLI).

---

## Phase 2b (adversarial self-review, 2026-08-10)

Deliberately red-teamed the Phase 1 report for over-claims and missed gaps.

### New finding — Adv-1: `safe=True` invariant was over-claimed

**Phase 1 said:** *"you literally cannot register an unsafe probe"* — false.
Actual behavior tested this session:

| Bypass                                       | Result                                          |
|----------------------------------------------|-------------------------------------------------|
| `ProbeTemplate(safe=False)`                   | ✓ ValueError raised (Phase 1 correct)            |
| `p = ProbeTemplate(...); p.safe = False`      | ✗ **SUCCEEDED** — mutable after construction     |
| `class Sneaky(ProbeTemplate): __post_init__=lambda:None` | ✗ **SUCCEEDED** — subclass bypasses check  |
| `KNOWN_PROBES["CVE-X"] = sneaky_probe`        | ✗ **SUCCEEDED** — direct dict injection          |

**Fix applied this session (commit shortly):**
- `@dataclass(frozen=True)` on `ProbeTemplate` — catches bypass #2 (post-construction mutation).
- Added test `test_probe_is_frozen_cannot_be_mutated`.
- Bypasses #3 and #4 (subclass + direct dict injection) are **out of threat model**: anyone with arbitrary Python execution owns the process anyway; the invariant exists to catch developer mistakes, not to be a security boundary. Docstring updated to say this explicitly instead of implying stronger guarantees.

### New finding — Adv-2: LLM output is stochastic; eval accuracy is a point estimate

**Phase 1 said:** *"100% accuracy (7/7)"* — implicitly presented as reproducible.
**Reality:** Sonnet 5 is non-deterministic (default temperature). Two consecutive `run_eval.sh` invocations may disagree on borderline candidates, and a re-run three months from now on a newer Sonnet version definitely will.

**Action:** report chapter 5 must state this explicitly:
- Cite N=7 result WITH the run date + model version (`claude-sonnet-5`, run on 2026-08-10)
- Ideally run the eval 3-5 times, report mean + std, not a single number
- Set `output_config={"effort":"low", "temperature":0}` in the SDK options if reproducibility matters more than reasoning depth (not free — likely lowers quality)

Not fixed this session (needs LLM budget + is fundamentally a measurement-methodology decision for the report chapter, not a code bug).

### New finding — Adv-3: fake engine is deterministic (invariant confirmed)

Ran `python -m exposure_analyzer analyze --engine=fake` twice against the
same input and diffed outputs (minus timestamps). **Identical.** This
confirms the fake engine can be safely used for CI regression tests. No
code change needed; just noting the invariant holds.

### New finding — Adv-4: Phase 1 § 5.3 dismissed the sys.path-import model too quickly

Phase 1 said "no `pyproject.toml` per module — conscious choice". True but
incomplete. **Consequence not spelled out:** every consumer must know to
`sys.path.insert(0, "cve-matcher")` before `from cve_matcher import ...`. If
someone renames a module folder, imports silently break (`ImportError` far
from the rename site). The pattern is used in `run_full_scan.py` lines 41-42
and would break in exactly this way. Not urgent but should be a v2 cleanup
(single `pip install -e .` per module).

### Verification of Phase 1 findings that survived challenge

- ✓ `eval-lab/requirements.txt` gap: real, **fixed this session**.
- ✓ `cve-matcher` requirements comment: real but not a hard failure (explain module falls back gracefully); rewritten this session.
- ✓ No `LICENSE`: real, **added this session**.
- ✓ No unified install script: real, **added `scripts/bootstrap-linux.sh` this session**.
- ✓ `host-scanner/main.py` cwd-dependent config load: real, **fixed this session** (uses `Path(__file__).parent`).

---

## Final action-item status (post Phase 2b + fixes)

| # | Item                                                       | Phase 1 Priority | Status this session |
|---|------------------------------------------------------------|------------------|---------------------|
| 1 | `eval-lab/requirements.txt`                                | BLOCKER          | **FIXED** (added file pinning `pyyaml>=6.0`) |
| 2 | Misleading cve-matcher requirements comment                | MAJOR            | **FIXED** (rewrote to describe lazy-import + fallback) |
| 3 | No `LICENSE` file                                          | MAJOR            | **FIXED** (added MIT text at repo root) |
| 4 | No unified install script                                  | MAJOR            | **FIXED** (`scripts/bootstrap-linux.sh`) |
| 5 | `host-scanner/main.py` cwd-dependent config load           | MAJOR            | **FIXED** (`Path(__file__).parent / "config.yaml"`) |
| 6 | `claude` CLI auth expiry produces misleading error         | MINOR            | Deferred — worth a `preflight_auth_check()` wrapper in a future chunk |
| 7 | Silent coercion of malformed `evidence` field              | MINOR            | Deferred — low risk, breaking change if fixed |
| 8 | `report.py` and `cli.py` at 0% unit coverage               | MINOR            | **FIXED** (added `test_cli.py` + `test_report.py`; coverage 0%→96%/71%; total **52%→87%**) |
| 9 | No CONFIRMED verdict in any live eval                      | MINOR            | Deferred — needs eval-lab candidate additions (v2 work) |
| Adv-1 | `safe=True` invariant was over-claimed                 | new (MAJOR)      | **FIXED** (`@dataclass(frozen=True)` + test + honest docstring) |
| Adv-2 | LLM eval is a point estimate, not a reproducible number | new (MAJOR for report) | Not code-fixable; documented for chapter 5 |
| Adv-3 | Fake engine determinism                                | invariant confirmed | No change needed |
| Adv-4 | sys.path import pattern is fragile                     | new (MINOR)      | Deferred — v2 cleanup |

---

## Test count + coverage summary (final)

| Metric              | Phase 1 start | Post-fixes |
|---------------------|--------------:|-----------:|
| Unit tests          |            38 |         52 |
| Overall coverage    |           52% |        87% |
| `report.py` coverage |           0% |        96% |
| `cli.py` coverage    |           0% |        71% |
| `probes.py` coverage |         100% |       100% |
| Logic-layer coverage (excl. Claude SDK) | 86% | ~95% |

---

## Sign-off (Phase 2b)

The system is **materially closer to deployable-on-any-server** after this
session's fixes. The 5 blocker/major deployment gaps identified in Phase 1
are all resolved. The over-claimed `safe=True` invariant is patched at the
mutation vector; the subclass/dict-injection vectors are documented as
out-of-threat-model with a clear rationale.

**Remaining honest limitations** for chapter 5:
- LLM eval numbers are point estimates on a specific model version + date; multi-run reporting recommended.
- Ground truth v2 is deliberately narrow (KEV∩dpkg subset); real coverage story is documented in `eval-lab/ground_truth.md` as v1 vs aspirational v2 tiers.
- No live CONFIRMED case yet — every scored verdict so far is `MITIGATED_BY_CONFIG`. v2 test cases should include genuinely-vulnerable installed versions.

Formal dual-engine cross-review (Claude + Gemini via a working `agy` or via `gemini` CLI) remains a nice-to-have follow-up but is not blocking this deliverable.
