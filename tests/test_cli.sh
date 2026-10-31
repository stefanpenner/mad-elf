#!/bin/bash
# Portable CLI checks. No Python. macOS and Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/mad-elf"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -x "$CLI" ]] || fail "build/mad-elf is missing"

"$CLI" --help >/dev/null

set +e
"$CLI" >/dev/null 2>"$WORK/err"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail "no args should exit 2 (got $rc)"

set +e
out="$("$CLI" install "$WORK/missing" "$WORK/out" 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "missing file exit $rc"
printf '%s\n' "$out" | grep -q 'not a file' || fail "missing file message: $out"

printf 'hello\n' > "$WORK/hello"
set +e
out="$("$CLI" install "$WORK/hello" "$WORK/out" 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "non-binary exit $rc"
printf '%s\n' "$out" | grep -q 'not an ELF or Mach-O' || fail "non-binary message: $out"

set +e
out="$("$CLI" inspect "$WORK/hello" 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "inspect non-binary exit $rc"
printf '%s\n' "$out" | grep -q 'not an ELF or Mach-O' || fail "inspect message: $out"

set +e
out="$("$CLI" install --flag '' "$WORK/hello" "$WORK/out" 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "empty flag exit $rc"
printf '%s\n' "$out" | grep -q 'empty --flag' || fail "empty flag message: $out"

set +e
out="$("$CLI" install --setenv NOEQUALS "$WORK/hello" "$WORK/out" 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "bad setenv exit $rc"
printf '%s\n' "$out" | grep -q 'KEY=VALUE' || fail "bad setenv message: $out"
printf '%s\n' "$out" | grep -q "'NOEQUALS'" || fail "bad setenv repr: $out"

set +e
"$CLI" detect abc >/dev/null 2>"$WORK/err"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail "bad pid exit $rc"

set +e
out="$("$CLI" detect 2147483646 2>&1 >/dev/null)"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail "missing pid exit $rc"
printf '%s\n' "$out" | grep -q 'cannot inspect' || fail "missing pid message: $out"

echo "PASS: cli errors"
