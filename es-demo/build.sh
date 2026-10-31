#!/bin/bash
# Assemble MadElfES.app. Signing with your developer identity is a separate step;
# see es-demo/README.md. This script only runs on macOS.
set -euo pipefail
cd "$(dirname "$0")"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "es-demo/build.sh builds a macOS system extension bundle; this host is $(uname -s)" >&2
  exit 1
fi

ROOT="$(pwd)"
APP="$ROOT/build/MadElfES.app"
EXT="$APP/Contents/Library/SystemExtensions/com.madelf.es.extension.systemextension"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$EXT/Contents/MacOS"

clang -fobjc-arc -fblocks -O2 -Wall \
  -I "$ROOT" \
  -framework Foundation \
  -lbsm -lEndpointSecurity \
  -o "$EXT/Contents/MacOS/madelf-es-extension" \
  "$ROOT/extension/main.m" "$ROOT/policy.c"
cp "$ROOT/extension/Info.plist" "$EXT/Contents/Info.plist"

swiftc -O -framework Foundation -framework SystemExtensions \
  -o "$APP/Contents/MacOS/madelf-es-host" \
  "$ROOT/host/main.swift"
cp "$ROOT/host/Info.plist" "$APP/Contents/Info.plist"

echo "built $APP"
echo "sign both binaries with a profile that carries the Endpoint Security entitlement, then copy the app to /Applications"
