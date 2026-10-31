#!/bin/bash
# CLI round-trip for the allowlist the extension reads. Runs on every OS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI="$ROOT/build/mad-elf-es"
if [[ ! -x "$CLI" ]]; then
  echo "missing $CLI; run make" >&2
  exit 1
fi
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

"$CLI" --dir "$DIR" mode monitor >/dev/null
"$CLI" --dir "$DIR" allow path "/bin/echo"
"$CLI" --dir "$DIR" allow path "/bin/echo"
"$CLI" --dir "$DIR" allow prefix "/usr/bin/"
"$CLI" --dir "$DIR" allow teamid ABCDE12345
"$CLI" --dir "$DIR" allow signingid com.apple.true
"$CLI" --dir "$DIR" mode enforce >/dev/null

grep -q '^path /bin/echo$' "$DIR/allowlist"
grep -q '^prefix /usr/bin/$' "$DIR/allowlist"
grep -q '^teamid ABCDE12345$' "$DIR/allowlist"
grep -q '^signingid com.apple.true$' "$DIR/allowlist"
# allow is idempotent
test "$(grep -c '^path /bin/echo$' "$DIR/allowlist")" -eq 1
grep -q '^enforce$' "$DIR/mode"
"$CLI" --dir "$DIR" status | grep -q 'mode: enforce'

"$CLI" --dir "$DIR" remove path "/bin/echo"
if grep -q '^path /bin/echo$' "$DIR/allowlist"; then
  echo "remove left the path rule in place" >&2
  exit 1
fi
"$CLI" --dir "$DIR" list | grep -q 'prefix /usr/bin/'
"$CLI" --dir "$DIR" mode monitor >/dev/null
grep -q '^monitor$' "$DIR/mode"
echo "test_cli: ok"
