#!/usr/bin/env bash
# Run the full KING REAPER X test suite.
#
# Non-interactive by design: CI and cron must never sit waiting on a consent
# prompt, so REAPER_NONINTERACTIVE is set for the whole run.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE" || exit 2

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }

export REAPER_ACCEPT_TERMS=1
export REAPER_NONINTERACTIVE=1
export NO_COLOR=1
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"

echo "== syntax check =="
"$PY" -m compileall -q core modules data dashboard tests main.py || exit 1

echo
echo "== offline unit tests =="
"$PY" -m unittest tests.test_offline -v 2>&1 | tail -5
unit=${PIPESTATUS[0]}

echo
echo "== localhost integration tests =="
"$PY" -m unittest tests.test_smoke -v 2>&1 | tail -5
smoke=${PIPESTATUS[0]}

echo
if [ "$unit" -eq 0 ] && [ "$smoke" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
fi
echo "TESTS FAILED (unit=$unit smoke=$smoke)" >&2
exit 1
