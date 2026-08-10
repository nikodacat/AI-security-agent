#!/usr/bin/env bash
# Full eval: iterate the pipeline over every container in ground_truth.yaml,
# diff verdicts, write eval_results.csv + eval_summary.md.
#
# Usage:  ./run_eval.sh [--engine=claude|fake] [--reuse-existing] [--containers=a,b,c]

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Convert to a Windows-native path for the native-Windows Python interpreter.
# (MSYS_NO_PATHCONV, exported for the docker-exec calls inside, would otherwise
# leave the script arg as /c/... and Python would read it as C:\c\...)
if command -v cygpath >/dev/null 2>&1; then
    SCRIPT="$(cygpath -w "$HERE/run_eval.py")"
else
    SCRIPT="$HERE/run_eval.py"
fi
export MSYS_NO_PATHCONV=1
export PYTHONIOENCODING=utf-8
exec python "$SCRIPT" "$@"
