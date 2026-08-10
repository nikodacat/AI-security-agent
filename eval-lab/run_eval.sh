#!/usr/bin/env bash
# Full eval: iterate the pipeline over every container in ground_truth.yaml,
# diff verdicts, write eval_results.csv + eval_summary.md.
#
# Usage:  ./run_eval.sh [--engine=claude|fake] [--reuse-existing] [--containers=a,b,c]

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export MSYS_NO_PATHCONV=1
export PYTHONIOENCODING=utf-8
exec python "$HERE/run_eval.py" "$@"
