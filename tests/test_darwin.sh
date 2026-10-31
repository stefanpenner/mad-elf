#!/bin/bash
# macOS LC_LOAD_DYLIB runtime test. Skips cleanly off Darwin.
# Proves the constructor runs before main with a clean environment:
# no DYLD_INSERT_LIBRARIES, absolute dylib path only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/mad-elf"

skip() { echo "SKIP: $*"; exit 0; }
fail() { echo "FAIL: $*" >&2; exit 1; }

[[ "$(uname -s)" == Darwin ]] || skip "LC_LOAD_DYLIB runtime test requires macOS"
command -v clang >/dev/null 2>&1 || skip "clang is not installed"
[[ -x "$CLI" ]] || fail "build/mad-elf is missing"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

run_to() {
    local secs="$1"
    local outfile="$2"
    shift 2
    "$@" >"$outfile" 2>"$outfile.err" &
    local p=$!
    local i
    for ((i = 0; i < secs * 10; i++)); do
        if ! kill -0 "$p" 2>/dev/null; then
            wait "$p"
            return $?
        fi
        sleep 0.1
    done
    kill "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
    echo "FAIL: process timed out (possible re-exec loop)" >&2
    return 1
}

mkdir -p "$WORK/lib"
DYLIB="$WORK/lib/libmadelf.dylib"
clang -dynamiclib -o "$DYLIB" \
    "$ROOT/src/shim_darwin.c" "$ROOT/src/logic.c" \
    -Wl,-install_name,"$DYLIB"
clang -Wl,-headerpad,0x400 -o "$WORK/host" "$ROOT/tests/fixtures/darwin_host.c"

MARKER="$WORK/order.txt"
"$CLI" install --dylib "$DYLIB" \
    --flag --madelf-flag \
    --setenv MADELF_PROFILE=from-shim \
    --marker-file "$MARKER" \
    "$WORK/host" "$WORK/host-patched"
PATCHED="$WORK/host-patched"
inspect="$("$CLI" inspect "$PATCHED")"
printf '%s\n' "$inspect" | grep -q "$DYLIB" || fail "absolute dylib path not in load commands: $inspect"
printf '%s\n' "$inspect" | grep -q '\[mad-elf\]' || fail "dylib was not marked mad-elf"
if printf '%s\n' "$inspect" | grep -E -q '@executable_path|@loader_path|@rpath'; then
    fail "special dyld path leaked into load commands: $inspect"
fi

run_to 20 "$WORK/host.out" env -i "$PATCHED" user-arg || {
    echo "---- stdout ----" >&2
    cat "$WORK/host.out" >&2 || true
    echo "---- stderr ----" >&2
    cat "$WORK/host.out.err" >&2 || true
    fail "patched host failed"
}
out="$(cat "$WORK/host.out")"
printf '%s\n' "$out" | grep -q 'SHIM=1' || fail "MADELF_SHIM was not visible to main: $out"
printf '%s\n' "$out" | grep -q 'PROFILE=from-shim' || fail "configured environment did not reach main: $out"
printf '%s\n' "$out" | grep -q 'DYLD=$' || fail "DYLD_INSERT_LIBRARIES was set: $out"
printf '%s\n' "$out" | grep -q 'arg=--madelf-flag' || fail "flag missing: $out"
printf '%s\n' "$out" | grep -q 'arg=user-arg' || fail "user arg missing: $out"
fpos="$(printf '%s\n' "$out" | grep -n 'arg=--madelf-flag' | head -1 | cut -d: -f1)"
upos="$(printf '%s\n' "$out" | grep -n 'arg=user-arg' | head -1 | cut -d: -f1)"
[[ "$fpos" -lt "$upos" ]] || fail "flag was not inserted before the original argument: $out"
[[ "$(cat "$MARKER" 2>/dev/null || true)" == $'ctor\nmain\n' ]] || fail "constructor order: $(cat "$MARKER" 2>/dev/null || true)"

rm -f "$MARKER"
run_to 20 "$WORK/host2.out" env -i "$PATCHED" --madelf-flag user-arg || fail "second host run failed: $(cat "$WORK/host2.out.err")"
count="$(grep -c 'arg=--madelf-flag' "$WORK/host2.out" || true)"
[[ "$count" -eq 1 ]] || fail "flag duplicated: $(cat "$WORK/host2.out")"
[[ "$(cat "$MARKER")" == $'ctor\nmain\n' ]] || fail "constructor ordering when the flag was already present"

rm -f "$MARKER"
run_to 20 "$WORK/host3.out" env -i MADELF_PROFILE=from-parent "$PATCHED" user-arg || fail "preset env run failed"
grep -q 'PROFILE=from-parent' "$WORK/host3.out" || fail "existing environment was overwritten: $(cat "$WORK/host3.out")"

if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node is not installed; host LC_LOAD_DYLIB test passed"
    echo "PASS: darwin LC_LOAD_DYLIB"
    exit 0
fi

NODE="$(command -v node)"
NODE_DST="$WORK/node-madelf"
NODE_MARKER="$WORK/node-order.txt"
set +e
err="$("$CLI" install --dylib "$DYLIB" --flag --no-warnings --marker-file "$NODE_MARKER" "$NODE" "$NODE_DST" 2>&1)"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    echo "SKIP: could not patch node ($err); host LC_LOAD_DYLIB test passed"
    echo "PASS: darwin LC_LOAD_DYLIB"
    exit 0
fi

cat > "$WORK/node.js" <<'EOF'
const fs = require('fs');
const marker = process.env.MADELF_MARKER_FILE;
if (marker) fs.appendFileSync(marker, 'js\n');
const out = {
  shim: process.env.MADELF_SHIM || null,
  execArgv: process.execArgv,
  dyld: process.env.DYLD_INSERT_LIBRARIES || null,
};
fs.writeFileSync(process.argv[1], JSON.stringify(out));
EOF

run_to 30 "$WORK/node.out" env -i "HOME=$WORK" "TMPDIR=$WORK" "$NODE_DST" -e "$(cat "$WORK/node.js")" "$WORK/node.json" || {
    cat "$WORK/node.out" >&2 || true
    cat "$WORK/node.out.err" >&2 || true
    fail "patched node did not run under a clean environment"
}
[[ -f "$WORK/node.json" ]] || fail "patched node wrote no result"
node -e '
const fs = require("fs");
const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
if (d.shim !== "1" || d.dyld !== null) {
  console.error(d);
  process.exit(1);
}
if (!d.execArgv.includes("--no-warnings")) {
  console.error(d);
  process.exit(1);
}
' "$WORK/node.json" || fail "node did not observe the shim under a clean environment"
[[ "$(cat "$NODE_MARKER")" == $'ctor\njs\n' ]] || fail "dylib constructor did not run before Node started JS: $(cat "$NODE_MARKER")"

echo "PASS: darwin LC_LOAD_DYLIB (host and node)"
