#!/bin/bash
# Proves an active Endpoint Security extension denies a non-allowlisted binary
# and allows an allowlisted one. Skips unless the extension is loaded.
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "SKIP: Endpoint Security deny/allow test requires macOS"
  exit 0
fi
if ! command -v systemextensionsctl >/dev/null 2>&1; then
  echo "SKIP: systemextensionsctl is not available"
  exit 0
fi
if ! systemextensionsctl list 2>/dev/null | grep -q 'com.madelf.es.extension'; then
  echo "SKIP: com.madelf.es.extension is not installed (see es-demo/README.md)"
  exit 0
fi
if ! systemextensionsctl list 2>/dev/null | grep 'com.madelf.es.extension' | grep -Eq 'activated|enabled'; then
  echo "SKIP: com.madelf.es.extension is installed but not activated"
  exit 0
fi

DIR="/Library/Application Support/MadElfES"
LOG="/var/log/madelf-es.log"
if [[ ! -d "$DIR" || ! -w "$DIR" ]]; then
  echo "SKIP: $DIR is not writable. Run this test as a user who can edit the allowlist (often root)."
  exit 0
fi
if [[ -f "$LOG" && ! -r "$LOG" ]]; then
  echo "SKIP: $LOG is not readable"
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cc -O2 -o "$WORK/allowed-helper" -x c - <<'EOF'
#include <stdio.h>
int main(void) { puts("ok"); return 0; }
EOF
cp "$WORK/allowed-helper" "$WORK/denied-helper"
chmod 755 "$WORK/allowed-helper" "$WORK/denied-helper"
ALLOWED="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$WORK/allowed-helper")"
DENIED="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$WORK/denied-helper")"

ALLOW="$DIR/allowlist"
MODE="$DIR/mode"
cp "$ALLOW" "$WORK/allowlist.bak" 2>/dev/null || true
cp "$MODE" "$WORK/mode.bak" 2>/dev/null || true
restore() {
  if [[ -f "$WORK/allowlist.bak" ]]; then cp "$WORK/allowlist.bak" "$ALLOW"; else rm -f "$ALLOW"; fi
  if [[ -f "$WORK/mode.bak" ]]; then cp "$WORK/mode.bak" "$MODE"; else rm -f "$MODE"; fi
}
trap 'restore; rm -rf "$WORK"' EXIT

# Prefixes cover normal system execs during the short enforce window.
# The denied helper lives under the temp dir, which is not on this list.
cat > "$ALLOW" <<EOF
prefix /bin/
prefix /usr/
prefix /System/
prefix /Library/
prefix /Applications/
prefix /opt/
prefix /sbin/
prefix /private/var/
prefix /dev/
path $ALLOWED
EOF
printf 'enforce\n' > "$MODE"
# The extension re-reads on the next exec. Give it a moment to observe the files.
sleep 0.5

BEFORE=0
if [[ -f "$LOG" ]]; then BEFORE="$(wc -c < "$LOG" | tr -d ' ')"; fi

set +e
"$DENIED" >"$WORK/denied.out" 2>"$WORK/denied.err"
DENIED_RC=$?
set -e
if [[ "$DENIED_RC" -eq 0 ]]; then
  echo "FAIL: $DENIED ran; ES did not deny it" >&2
  echo "stderr: $(cat "$WORK/denied.err")" >&2
  exit 1
fi
if grep -q '^ok$' "$WORK/denied.out"; then
  echo "FAIL: denied helper produced output" >&2
  exit 1
fi

sleep 0.3
NEW=""
if [[ -f "$LOG" ]]; then NEW="$(tail -c +"$((BEFORE + 1))" "$LOG" || true)"; fi
if ! printf '%s\n' "$NEW" | grep -F "decision=deny" | grep -F "$DENIED" >/dev/null; then
  echo "FAIL: log has no deny record for $DENIED" >&2
  echo "$NEW" >&2
  exit 1
fi

"$ALLOWED" >"$WORK/allowed.out"
grep -q '^ok$' "$WORK/allowed.out"
sleep 0.3
NEW=""
if [[ -f "$LOG" ]]; then NEW="$(tail -c +"$((BEFORE + 1))" "$LOG" || true)"; fi
if ! printf '%s\n' "$NEW" | grep -F "decision=allow" | grep -F "$ALLOWED" >/dev/null; then
  echo "FAIL: log has no allow record for $ALLOWED" >&2
  echo "$NEW" >&2
  exit 1
fi

echo "test_integration: ok (deny blocked $DENIED, allow ran $ALLOWED)"
