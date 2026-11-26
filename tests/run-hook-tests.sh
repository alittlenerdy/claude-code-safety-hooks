#!/usr/bin/env bash
# Runs every hook's --self-test, then the cross-hook contract checks.
#
# Hooks that support a `--self-test` flag are discovered automatically, so adding a
# hook with a self-test needs no change to this file.
#
# Usage:  tests/run-hook-tests.sh            (tests the hooks in this repo)
#         HOOKS_DIR=~/.claude/hooks tests/run-hook-tests.sh   (tests an install)
set -uo pipefail

HOOKS="${HOOKS_DIR:-$(cd "$(dirname "$0")/../hooks" && pwd)}"
PY="${PYTHON:-python3}"
fail=0
ran=0

for hook in "$HOOKS"/*.py; do
  [ -f "$hook" ] || continue
  grep -q -- '--self-test' "$hook" || continue
  name="$(basename "$hook")"
  ran=$((ran + 1))
  printf '%-28s ' "$name"
  if out="$("$PY" "$hook" --self-test 2>&1)"; then
    echo "$out"
  else
    echo "$out"
    fail=$((fail + 1))
  fi
done

# A payload with no recognized field must be allowed, not denied.
if [ -f "$HOOKS/secret-exposure-guard.py" ]; then
  for probe in '{}' '{"tool_name":"Bash","tool_input":{}}' '{"tool_input":null}'; do
    out="$(printf '%s' "$probe" | "$PY" "$HOOKS/secret-exposure-guard.py" 2>/dev/null)"
    if printf '%s' "$out" | grep -q '"deny"'; then
      echo "FAIL secret-exposure-guard.py denied an empty payload: $probe"
      fail=$((fail + 1))
    fi
  done
fi

# Every hook must FAIL OPEN on garbage input: exit 0 and emit no deny/block.
for hook in "$HOOKS"/*.py; do
  [ -f "$hook" ] || continue
  name="$(basename "$hook")"
  out="$(printf 'not json at all' | "$PY" "$hook" 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ] || printf '%s' "$out" | grep -qE '"(deny|block)"'; then
    echo "FAIL $name did not fail open on malformed stdin (rc=$rc)"
    fail=$((fail + 1))
  fi
done

echo
if [ "$ran" -eq 0 ]; then
  echo "FAILED  no self-test suites found in $HOOKS"
  exit 1
fi
if [ "$fail" -eq 0 ]; then
  echo "OK  $ran self-test suite(s) passed; all hooks fail open on bad input."
else
  echo "FAILED  $fail problem(s)."
fi
exit "$fail"
