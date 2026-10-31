"""Run ONE arm of the week-9 vs current comparison on ONE container.

An "arm" is a scanner output (host.json) plus an analyzer source tree:

  --arm w9   host.json from the week-9 scanner, analyzer from the week-9
             commit's tree (--analyzer-root), no banner candidates.
  --arm now  host.json from the current scanner, analyzer from this tree,
             banner candidates ON (needs --network-state).
  --arm nvd  arm "now" plus NVD discovery (v3-2): CVEs NVD lists for the
             detected software, CVSS >= --nvd-min-cvss, capped.

Everything else is shared on purpose: KEV catalog, matcher adapters,
network_state, probe runner (`docker exec`), model and prompts-per-tree.
The model is Claude (Agent SDK) or any OpenAI-compatible endpoint (the local
Qwen), selected with --engine.

    python compare_arms.py --container eval-web-vuln --arm now \
        --host-json h.json --network-state n.json --engine claude --out out/

Emits <out>/result.json:
  {container, arm, engine, model, run, candidates:[{cve_id, source, verdict}], ...}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent


def _parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="compare_arms.py")
    p.add_argument("--container", required=True)
    p.add_argument("--arm", choices=("w9", "now", "nvd"), required=True)
    p.add_argument("--host-json", type=Path, required=True)
    p.add_argument("--network-state", type=Path, default=None)
    p.add_argument("--engine", choices=("claude", "openai"), default="claude")
    p.add_argument("--base-url", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--api-key", default=os.environ.get("QWEN_API_KEY"))
    p.add_argument("--timeout", type=float, default=240.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--analyzer-root", type=Path, default=REPO_ROOT,
                   help="Repo root whose exposure-analyzer/ is imported (week-9 worktree for the w9 arm).")
    p.add_argument("--no-nvd", action="store_true", help="Skip the NVD version-range pass.")
    p.add_argument("--nvd-min-cvss", type=float, default=7.0)
    p.add_argument("--nvd-max", type=int, default=40)
    p.add_argument("--max-calls", type=int, default=60,
                   help="Hard cap on model calls for this run (0 = no cap). Remaining candidates get no verdict.")
    p.add_argument("--max-cost-usd", type=float, default=2.0,
                   help="Hard cap on cost reported by the Claude SDK (0 = no cap). Checked before each call, "
                        "so a run can overshoot by one call.")
    p.add_argument("--candidates-only", action="store_true",
                   help="Stop after building candidates; no model call, no quota. "
                        "result.json then has verdict=null for every candidate.")
    p.add_argument("--run", type=int, default=1)
    p.add_argument("--out", type=Path, required=True)
    return p.parse_args()


def _retrying(fn, retries: int):
    async def wrapped(system_prompt: str, user_prompt: str) -> str:
        last: Exception | None = None
        for i in range(retries):
            try:
                return await fn(system_prompt, user_prompt)
            except Exception as e:  # transport flakiness over the VPN
                last = e
                await asyncio.sleep(5 * (i + 1))
        raise last  # type: ignore[misc]
    return wrapped


def main() -> int:
    a = _parse()
    a.out.mkdir(parents=True, exist_ok=True)

    # Matcher + adapters always come from this tree; only the analyzer
    # (agent, prompts) is swapped for the w9 arm, after host_state is derived.
    sys.path.insert(0, str(REPO_ROOT / "cve-matcher"))
    sys.path.insert(0, str(HERE))
    import run_full_scan as drv  # adapters only; no scanning happens here
    # The w9 arm matches with the week-9 matcher too (its KEV cache is copied in).
    sys.path.insert(0, str(a.analyzer_root / "cve-matcher"))
    from cve_matcher import kev as kev_mod
    from cve_matcher import matcher as matcher_mod

    scan = json.loads(a.host_json.read_text(encoding="utf-8"))
    inventory = drv._scan_to_inventory(a.container, scan)
    catalog = kev_mod.load()
    result = matcher_mod.match(inventory, catalog)
    if not a.no_nvd and result.findings:
        matcher_mod.enrich_with_versions(result.findings)
    kev_findings = [drv._finding_to_kev_finding(f) for f in result.findings]
    for f in kev_findings:
        f.setdefault("source", "inventory")
    host_state = drv._derive_host_state(a.container, scan)

    network_state: list[dict[str, Any]] | None = None
    if a.network_state is not None:
        network_state = json.loads(a.network_state.read_text(encoding="utf-8"))

    n_inventory = len(kev_findings)
    if a.arm in ("now", "nvd"):
        if network_state is None:
            print("error: --arm now requires --network-state", file=sys.stderr)
            return 1
        from exposure_analyzer.candidates import banner_candidates
        extra = banner_candidates(
            network_state,
            existing_cve_ids=[f["cve_id"] for f in kev_findings],
            enrich=not a.no_nvd,
            log=lambda m: print(m, file=sys.stderr),
        )
        kev_findings = kev_findings + extra
    n_banner = len(kev_findings) - n_inventory
    if a.arm == "nvd":
        from exposure_analyzer import candidates as cand_mod
        pkgs = list(inventory.packages) + cand_mod.banner_packages(cand_mod.banner_services(network_state))
        kev_findings = kev_findings + cand_mod.nvd_candidates(
            pkgs, existing_cve_ids=[f["cve_id"] for f in kev_findings],
            min_cvss=a.nvd_min_cvss, max_total=a.nvd_max, log=lambda m: print(m, file=sys.stderr))
    n_nvd = len(kev_findings) - n_inventory - n_banner
    print(f"[{a.container}/{a.arm}/{a.engine}] candidates: {n_inventory} from inventory"
          f" + {n_banner} from banners + {n_nvd} from NVD", file=sys.stderr)

    if a.candidates_only:
        cands = [{"cve_id": f["cve_id"], "source": f.get("source", "inventory"),
                  "package": f"{f.get('package_name')} {f.get('package_version')}", "verdict": None}
                 for f in kev_findings]
        out = {"container": a.container, "arm": a.arm, "engine": "none", "model": "none", "run": a.run,
               "candidates_only": True, "n_candidates": len(cands), "candidates": cands,
               "verdicts": [], "batch_errors": [], "error": None}
        (a.out / "result.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        return 0

    if a.analyzer_root.resolve() != REPO_ROOT.resolve():
        for name in [m for m in sys.modules if m == "exposure_analyzer" or m.startswith("exposure_analyzer.")]:
            del sys.modules[name]
        sys.path.insert(0, str(a.analyzer_root / "exposure-analyzer"))
    from exposure_analyzer import agent as agent_mod
    print(f"      analyzer from {Path(agent_mod.__file__).resolve().parents[1]}", file=sys.stderr)

    budget = None
    if hasattr(agent_mod, "CallBudget"):
        budget = agent_mod.CallBudget(max_calls=a.max_calls or None, max_cost_usd=a.max_cost_usd or None)
    else:  # the week-9 analyzer tree predates budgets
        print("      warning: this analyzer tree has no CallBudget; --max-calls/--max-cost-usd not enforced",
              file=sys.stderr)

    if a.engine == "claude":
        verdict_fn = agent_mod.build_claude_verdict_fn(budget) if budget else agent_mod.build_claude_verdict_fn()
        model = "claude"
    else:
        if not (a.base_url and a.model):
            print("error: --engine openai needs --base-url and --model", file=sys.stderr)
            return 1
        verdict_fn = _retrying(
            agent_mod.build_openai_compatible_verdict_fn(
                base_url=a.base_url, model=a.model, api_key=a.api_key, timeout=a.timeout),
            a.retries)
        model = a.model

    if a.engine != "claude" and budget:  # the Claude fn does its own check/record (it knows the cost)
        _raw = verdict_fn

        async def verdict_fn(system_prompt: str, user_prompt: str) -> str:
            budget.check()
            try:
                return await _raw(system_prompt, user_prompt)
            finally:
                budget.record(None)

    _inner, _calls, _t_start = verdict_fn, [0], time.time()

    async def verdict_fn(system_prompt: str, user_prompt: str) -> str:  # progress to stderr
        _calls[0] += 1
        t = time.time()
        try:
            return await _inner(system_prompt, user_prompt)
        finally:
            print(f"      model call {_calls[0]} took {time.time() - t:.0f}s "
                  f"(total {time.time() - _t_start:.0f}s)", file=sys.stderr, flush=True)

    cfg = agent_mod.AgentConfig(run_probes=True)
    runner = agent_mod.docker_exec_probe_runner(a.container, cfg)
    agent = agent_mod.ExposureAgent(verdict_fn=verdict_fn, config=cfg, probe_runner=runner)

    t0 = time.time()
    try:
        verdicts = asyncio.run(agent.analyze_batch(kev_findings, host_state, network_state=network_state))
        error = None
    except Exception as e:
        verdicts, error = [], f"{type(e).__name__}: {e}"
    elapsed = round(time.time() - t0, 1)
    batch_errors = list(getattr(agent, "last_batch_errors", []))  # w9 analyzer predates this attribute

    by_id = {v.cve_id: v for v in verdicts}
    cands = []
    for f in kev_findings:
        v = by_id.get(f["cve_id"])
        cands.append({
            "cve_id": f["cve_id"],
            "source": f.get("source", "inventory"),
            "package": f"{f.get('package_name')} {f.get('package_version')}",
            "verdict": v.verdict.value if v else None,
        })
    out = {
        "container": a.container, "arm": a.arm, "engine": a.engine, "model": model, "run": a.run,
        "elapsed_sec": elapsed, "error": error, "batch_errors": batch_errors,
        "n_calls": budget.calls if budget else None,
        "cost_usd": round(budget.cost_usd, 4) if budget else None,
        "stopped_by_budget": getattr(agent, "stopped_by_budget", ""),
        "n_candidates": len(kev_findings), "candidates": cands,
        "verdicts": [{"cve_id": v.cve_id, "verdict": v.verdict.value, "reason": v.reason} for v in verdicts],
    }
    (a.out / "result.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"      done in {elapsed}s, {len(verdicts)}/{len(kev_findings)} verdicts"
          + (f", {budget.calls} calls, ${budget.cost_usd:.3f}" if budget else "")
          + (f", STOPPED BY BUDGET ({agent.stopped_by_budget})" if getattr(agent, "stopped_by_budget", "") else "")
          + (f", ERROR {error}" if error else ""), file=sys.stderr)
    return 0 if not error else 2


if __name__ == "__main__":
    raise SystemExit(main())
