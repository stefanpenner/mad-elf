#!/bin/bash
# Linux shim integration. No Python.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/build/mad-elf"
SHIM="$ROOT/build/mad-elf-shim"
WORK="$(mktemp -d)"
PIDS=()

cleanup() {
    local p
    if [[ -f "$WORK/child.pid" ]]; then
        kill "$(cat "$WORK/child.pid")" 2>/dev/null || true
    fi
    for p in "${PIDS[@]+"${PIDS[@]}"}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Match one NUL-separated /proc field. grep -q in a pipe trips pipefail on SIGPIPE.
has_nul_entry() {
    local needle="$1" file="$2" line
    while IFS= read -r -d '' line || [[ -n "${line:-}" ]]; do
        [[ "$line" == "$needle" ]] && return 0
    done < "$file"
    return 1
}

[[ -x "$SHIM" ]] || fail "build/mad-elf-shim is missing; run make"
[[ -x "$CLI" ]] || fail "build/mad-elf is missing"

gcc -O2 -o "$WORK/printenv" "$ROOT/tests/fixtures/printenv.c"
gcc -nostdlib -static -o "$WORK/staticbin" "$ROOT/tests/fixtures/static_exit.S"

set +e
err="$("$SHIM" 2>&1 >/dev/null)"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail "shim direct exec exit $rc"
printf '%s\n' "$err" | grep -q 'PT_INTERP' || fail "shim stderr: $err"

set +e
err="$("$CLI" install --flag --no-warnings "$WORK/staticbin" "$WORK/static-out" 2>&1)"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "static install should fail"
printf '%s\n' "$err" | grep -q 'PT_INTERP' || fail "static message: $err"

"$CLI" install \
    --flag --from-shim \
    --setenv MADELF_PROFILE=from-shim \
    --mergeenv NODE_OPTIONS=--zero-fill-buffers \
    "$WORK/printenv" "$WORK/printenv-patched"

DST="$WORK/printenv-patched"
interp="$("$CLI" inspect "$DST" | sed -n 's/^interpreter: //p')"
orig="$("$CLI" inspect "$WORK/printenv" | sed -n 's/^interpreter: //p')"
[[ "$(readlink -f "$interp")" == "$(readlink -f "$SHIM")" ]] || fail "interpreter is $interp"
grep -q "loader=$orig" "$DST.madelf" || fail "config missing loader"
"$CLI" inspect "$DST" | grep -q 'mad-elf: yes' || fail "inspect should say yes"
"$CLI" inspect "$WORK/printenv" | grep -q 'mad-elf: no' || fail "original should say no"

run_clean() {
    env -u MADELF_SHIM -u MADELF_PROFILE -u NODE_OPTIONS "$@"
}

out="$(run_clean "$DST" user-arg)"
printf '%s\n' "$out" | grep -q 'SHIM=1' || fail "$out"
printf '%s\n' "$out" | grep -q 'PROFILE=from-shim' || fail "$out"
printf '%s\n' "$out" | grep -q 'NODE_OPTIONS=--zero-fill-buffers' || fail "$out"
printf '%s\n' "$out" | grep -q 'arg=--from-shim' || fail "$out"
printf '%s\n' "$out" | grep -q 'arg=user-arg' || fail "$out"
fpos="$(printf '%s\n' "$out" | grep -n 'arg=--from-shim' | head -1 | cut -d: -f1)"
upos="$(printf '%s\n' "$out" | grep -n 'arg=user-arg' | head -1 | cut -d: -f1)"
[[ "$fpos" -lt "$upos" ]] || fail "flag was not inserted first: $out"

out="$(run_clean "$DST" --from-shim user-arg)"
count="$(printf '%s\n' "$out" | grep -c 'arg=--from-shim' || true)"
[[ "$count" -eq 1 ]] || fail "flag duplicated: $out"

out="$(env -u MADELF_SHIM MADELF_PROFILE=from-parent NODE_OPTIONS=--throw-deprecation "$DST")"
printf '%s\n' "$out" | grep -q 'PROFILE=from-parent' || fail "$out"
printf '%s\n' "$out" | grep -q 'NODE_OPTIONS=--throw-deprecation --zero-fill-buffers' || fail "$out"

out="$(run_clean bash -c 'exec -a my-name "$1" user-arg' bash "$DST")"
printf '%s\n' "$out" | grep -q 'argv0=my-name' || fail "argv0 lost: $out"

set +e
err="$("$CLI" install "$DST" "$DST" 2>&1)"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "in-place install should fail"
printf '%s\n' "$err" | grep -q 'in place' || fail "in-place message: $err"

set +e
err="$("$CLI" install --shim /no/such/mad-elf-shim "$WORK/printenv" "$WORK/missing-shim" 2>&1)"
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "missing shim should fail"
printf '%s\n' "$err" | grep -q 'shim not found' || fail "shim message: $err"

cat > "$WORK/extra.cfg" <<'EOF'
# comment
loader=/ignored/loader
flag=--from-config
setenv=MADELF_PROFILE=from-config
EOF
"$CLI" install --config "$WORK/extra.cfg" "$WORK/printenv" "$WORK/from-config"
rec="$("$CLI" inspect "$WORK/from-config" | sed -n 's/^recorded-loader: //p')"
[[ "$rec" == "$orig" ]] || fail "config loader= was not ignored (got $rec)"
out="$(run_clean "$WORK/from-config")"
printf '%s\n' "$out" | grep -q 'PROFILE=from-config' || fail "$out"
printf '%s\n' "$out" | grep -q 'arg=--from-config' || fail "$out"

"$CLI" install --forceenv MADELF_PROFILE=forced "$WORK/printenv" "$WORK/forced"
out="$(env -u MADELF_SHIM MADELF_PROFILE=from-parent "$WORK/forced")"
printf '%s\n' "$out" | grep -q 'PROFILE=forced' || fail "forceenv: $out"

if command -v objcopy >/dev/null 2>&1; then
    "$CLI" install --embed-only --setenv MADELF_PROFILE=from-section \
        "$WORK/printenv" "$WORK/printenv-embedded"
    [[ ! -e "$WORK/printenv-embedded.madelf" ]] || fail "embed-only wrote a sidecar"
    out="$(run_clean "$WORK/printenv-embedded")"
    printf '%s\n' "$out" | grep -q 'PROFILE=from-section' || fail "$out"
    printf '%s\n' "$out" | grep -q 'SHIM=1' || fail "$out"
    printf 'loader=%s\nsetenv=MADELF_PROFILE=from-sidecar\n' "$orig" > "$WORK/printenv-embedded.madelf"
    out="$(run_clean "$WORK/printenv-embedded")"
    printf '%s\n' "$out" | grep -q 'PROFILE=from-sidecar' || fail "sidecar should win: $out"

    "$CLI" install --embed --setenv MADELF_PROFILE=from-both \
        "$WORK/printenv" "$WORK/printenv-both"
    [[ -f "$WORK/printenv-both.madelf" ]] || fail "--embed should keep the sidecar"
    mv "$WORK/printenv-both.madelf" "$WORK/printenv-both.madelf.bak"
    out="$(run_clean "$WORK/printenv-both")"
    printf '%s\n' "$out" | grep -q 'PROFILE=from-both' || fail "embedded section unused: $out"
else
    echo "SKIP: objcopy is not installed"
fi

if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node is not installed"
    echo "PASS: linux shim"
    exit 0
fi

NODE="$(command -v node)"
"$CLI" install \
    --flag --no-warnings \
    --setenv MADELF_PROFILE=from-shim \
    --mergeenv NODE_OPTIONS=--zero-fill-buffers \
    "$NODE" "$WORK/node-madelf"
NDST="$WORK/node-madelf"
cat > "$WORK/report.js" <<'EOF'
const fs = require('fs');
const out = {
  shim: process.env.MADELF_SHIM || null,
  profile: process.env.MADELF_PROFILE || null,
  nodeOptions: process.env.NODE_OPTIONS || null,
  execArgv: process.execArgv,
  argv0: process.argv0,
};
fs.writeFileSync(process.env.OUT, JSON.stringify(out));
EOF

check_node() {
    node -e '
const fs = require("fs");
const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const want = process.argv[2];
function fail(m) { console.error(m); console.error(JSON.stringify(d)); process.exit(1); }
if (want === "base") {
  if (d.shim !== "1") fail("shim");
  if (d.profile !== "from-shim") fail("profile");
  if (!String(d.nodeOptions).includes("--zero-fill-buffers")) fail("nodeOptions");
  if (d.execArgv.filter(x => x === "--no-warnings").length !== 1) fail("execArgv");
} else if (want === "again") {
  if (d.execArgv.filter(x => x === "--no-warnings").length !== 1) fail("dup flag");
} else if (want === "preset") {
  if (d.profile !== "from-parent") fail("profile overwritten");
  const o = String(d.nodeOptions);
  if (!o.includes("--throw-deprecation") || !o.includes("--zero-fill-buffers")) fail(o);
} else if (want === "argv0") {
  if (d.argv0 !== "my-node") fail("argv0 " + d.argv0);
}
' "$1" "$2"
}

export OUT="$WORK/node-out.json"
run_clean "$NDST" "$WORK/report.js"
check_node "$OUT" base
run_clean "$NDST" --no-warnings "$WORK/report.js"
check_node "$OUT" again
env -u MADELF_SHIM MADELF_PROFILE=from-parent NODE_OPTIONS=--throw-deprecation OUT="$OUT" \
    "$NDST" "$WORK/report.js"
check_node "$OUT" preset
run_clean bash -c 'exec -a my-node "$1" "$2"' bash "$NDST" "$WORK/report.js"
check_node "$OUT" argv0

pidfile="$WORK/child.pid"
cat > "$WORK/child.js" <<EOF
const {spawn} = require('child_process');
const fs = require('fs');
const c = spawn('/bin/sleep', ['60'], {stdio: 'ignore'});
fs.writeFileSync(${pidfile@Q}, String(c.pid));
setInterval(() => {}, 1000);
EOF

env -u MADELF_SHIM -u MADELF_PROFILE -u NODE_OPTIONS \
    "$NDST" -e "$(cat "$WORK/child.js")" >/dev/null 2>&1 &
npid=$!
PIDS+=("$npid")
ready=0
for _ in $(seq 1 50); do
    if [[ -f "$WORK/child.pid" ]] && kill -0 "$npid" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
[[ "$ready" -eq 1 ]] || fail "patched node exited before detect"
has_nul_entry --no-warnings "/proc/$npid/cmdline" || fail "cmdline missing flag"
set +e
det="$("$CLI" detect "$npid" 2>"$WORK/det.err")"
rc=$?
set -e
[[ "$rc" -eq 0 ]] || fail "detect patched node exit $rc ($det)"
printf '%s\n' "$det" | grep -q 'mad-elf: yes' || fail "detect stdout: $det"

child="$(tr -d '[:space:]' < "$WORK/child.pid")"
has_nul_entry 'MADELF_SHIM=1' "/proc/$child/environ" || fail "child did not inherit marker"
set +e
"$CLI" detect "$child" >"$WORK/child.out" 2>"$WORK/child.err"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "inherited child exit $rc"
grep -q 'inherited' "$WORK/child.err" || fail "child detect: $(cat "$WORK/child.err")"
kill "$npid" 2>/dev/null || true
kill "$child" 2>/dev/null || true
wait "$npid" 2>/dev/null || true

"$NODE" -e 'setInterval(() => {}, 1000)' >/dev/null 2>&1 &
plain=$!
PIDS+=("$plain")
sleep 0.3
set +e
"$CLI" detect "$plain" >"$WORK/plain.out" 2>"$WORK/plain.err"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "plain node detect exit $rc"
grep -q 'mad-elf: no' "$WORK/plain.err" || fail "plain detect: $(cat "$WORK/plain.err")"
kill "$plain" 2>/dev/null || true
wait "$plain" 2>/dev/null || true

env -u MADELF_PROFILE MADELF_SHIM=1 /bin/sleep 60 >/dev/null 2>&1 &
slept=$!
PIDS+=("$slept")
set +e
"$CLI" detect "$slept" >"$WORK/sleep.out" 2>"$WORK/sleep.err"
rc=$?
set -e
[[ "$rc" -eq 1 ]] || fail "sleep detect exit $rc"
grep -q 'inherited' "$WORK/sleep.err" || fail "sleep detect: $(cat "$WORK/sleep.err")"
kill "$slept" 2>/dev/null || true
wait "$slept" 2>/dev/null || true

echo "PASS: linux shim"
