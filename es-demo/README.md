# Mad Elf Endpoint Security demo

A small macOS system extension that subscribes to process-exec authorization and answers allow or deny. It is a sketch of what Endpoint Security can do, not a product, and it is separate from the Linux `PT_INTERP` / macOS `LC_LOAD_DYLIB` shim.

It starts in **monitor** mode: every exec is allowed and logged. Nothing is denied until you set mode to `enforce`. Leave it there only while you are watching the machine, and switch back to `monitor` when you are done. An enforce-mode allowlist that does not cover the programs the system actually execs will make those execs fail with `EPERM`.

## What it does

The extension (`com.madelf.es.extension`) calls `es_new_client` and subscribes to:

- `ES_EVENT_TYPE_AUTH_EXEC`
- `ES_EVENT_TYPE_AUTH_EXEC_TRANSITION` when the SDK defines it (the subscribe is retried with `AUTH_EXEC` only if the kernel rejects the transition event)

For each event it logs one line to `/var/log/madelf-es.log` and to stdout:

- event name
- `decision=allow` or `decision=deny`
- `mode=monitor` or `mode=enforce`
- binary path
- team id and signing id from the exec target
- parent pid (the process that called exec)
- arguments (truncated)

The decision is `es_respond_auth_result` with `ES_AUTH_RESULT_ALLOW` or `ES_AUTH_RESULT_DENY`, and the cache flag is false so an allowlist edit applies to the next exec. The extension re-reads the allowlist on every event. If the allowlist cannot be read, it fails open (allow) and logs `reason=config-unreadable`, so a permissions mistake does not wedge the machine. Unknown mode text is treated as monitor.

Allowlist rules, one per line, in `/Library/Application Support/MadElfES/allowlist`:

```text
path /usr/local/bin/node
prefix /usr/bin/
teamid ABCDE12345
signingid com.apple.bash
```

`prefix` is a raw string prefix. Use a trailing slash (`/usr/bin/`) so `/usr/bin` does not also match `/usr/bin-evil`. A path, team id, or signing id match is enough; the rules are OR'd. In enforce mode, anything that matches nothing is denied.

`/Library/Application Support/MadElfES/mode` contains `monitor` or `enforce`.

## CLI

`make` builds `build/mad-elf-es`. It edits those files. The extension picks the change up on the next exec. No socket.

```bash
sudo build/mad-elf-es allow path /usr/bin/true
sudo build/mad-elf-es allow prefix /usr/bin/
sudo build/mad-elf-es allow teamid ABCDE12345
sudo build/mad-elf-es remove path /usr/bin/true
sudo build/mad-elf-es list
sudo build/mad-elf-es mode monitor
sudo build/mad-elf-es status
```

`MADELF_ES_DIR` or `--dir` points the CLI at another directory. The extension itself always reads `/Library/Application Support/MadElfES`. The tests that do not need the extension use `--dir` with a temp directory and run on Linux too.

## Build the bundle

On the Mac:

```bash
cd es-demo
./build.sh
```

That produces `es-demo/build/MadElfES.app` with the system extension at:

```text
MadElfES.app/Contents/Library/SystemExtensions/com.madelf.es.extension.systemextension
```

`build.sh` does not sign. An ad-hoc signature is not enough for Endpoint Security on a machine with SIP enabled.

### Xcode, if you would rather drive it from there

1. Create a macOS App project. Set the host bundle id to `com.madelf.es.host`. Turn off the App Sandbox. Delete the SwiftUI template entry point and add `host/main.swift`. Link `SystemExtensions.framework`. Set `CODE_SIGN_ENTITLEMENTS` to `host/entitlements.plist` (`com.apple.developer.system-extension.install`).
2. Add a system-extension target. Bundle id `com.madelf.es.extension`. `CFBundlePackageType` is `SYSX` (see `extension/Info.plist`). `NSSystemExtensionUsageDescription` must be set. Add `extension/main.m` and `policy.c`. Link `libEndpointSecurity`, `libbsm`, and Foundation. Compile as Objective-C with blocks (`-fblocks`). Set `CODE_SIGN_ENTITLEMENTS` to `extension/entitlements.plist` (`com.apple.developer.endpoint-security.client`). Do not sandbox the extension.
3. On the host target, add an Embed System Extensions phase that copies the extension into `Contents/Library/SystemExtensions`.
4. Sign both targets with a development certificate whose provisioning profile includes those two restricted entitlements. Product > Build.

## Entitlements, SIP, notarization, approval

Endpoint Security is a restricted entitlement. Apple grants `com.apple.developer.endpoint-security.client` per team after you request it (developer.apple.com, System Extension / Endpoint Security request). The host needs `com.apple.developer.system-extension.install`. Both have to be in the provisioning profile, not only in the `.entitlements` file. `codesign -d --entitlements :-` on the built binaries is what matters.

With that grant, SIP stays on. That is the configuration this demo is written for.

Until the grant arrives, a local experiment means disabling SIP (`csrutil disable` from recovery) so the entitlement is honored without a profile. Some OS versions also need AMFI relaxed. Disabling SIP is a development workaround. It is not required once the profile is real, and it is a bad idea on a machine you care about.

Distribution outside your team also needs notarization. A development-signed build loaded from Xcode on your own Mac does not.

Activation:

1. Copy `MadElfES.app` to `/Applications`. System extensions are rejected from other locations.
2. Run `/Applications/MadElfES.app/Contents/MacOS/madelf-es-host`.
3. Approve the extension when macOS asks. On current macOS that prompt lands in **System Settings > Privacy & Security**. Older releases used **System Preferences > Security & Privacy > General**.
4. Grant **Full Disk Access** to the extension. Without it, `es_new_client` returns not-permitted and the process exits.
5. On Apple silicon, development-signed system extensions may also need Developer Mode (System Settings > Privacy & Security > Developer Mode), which requires a reboot.
6. Confirm with `systemextensionsctl list`. You want `com.madelf.es.extension` in an activated/enabled state.
7. `log stream` or `tail -f /var/log/madelf-es.log` should show execs. Mode is still monitor, so nothing is denied.

Deactivate with:

```bash
/Applications/MadElfES.app/Contents/MacOS/madelf-es-host deactivate
```

## Try a deny

Do this only after the log is flowing, and switch back to monitor immediately after.

```bash
# Cover ordinary system locations, then flip to enforce.
sudo build/mad-elf-es allow prefix /bin/
sudo build/mad-elf-es allow prefix /usr/
sudo build/mad-elf-es allow prefix /System/
sudo build/mad-elf-es allow prefix /Library/
sudo build/mad-elf-es allow prefix /Applications/
sudo build/mad-elf-es allow path /path/to/some-allowed-tool
sudo build/mad-elf-es mode enforce

# Not on the allowlist. The exec fails (permission error) and the log says decision=deny.
/path/to/not-allowed ; echo exit:$?

sudo build/mad-elf-es mode monitor
```

An allowed binary runs, and the log says `decision=allow` with its path, team id, signing id, parent pid, and arguments.

## Tests

`make test` from the repo root always runs:

- `es-demo/tests/test_policy.c` — allow, prefix, team id, signing id, monitor vs enforce
- `es-demo/tests/test_cli.sh` — add, idempotent add, remove, mode file

`es-demo/tests/test_integration.sh` is the deny/allow proof. It skips with exit 0 unless all of these are true:

- the machine is macOS
- `systemextensionsctl list` shows `com.madelf.es.extension` activated or enabled
- `/Library/Application Support/MadElfES` is writable by the user running the test
- `/var/log/madelf-es.log` is readable if it already exists

When those hold, the script saves your allowlist and mode, writes a prefix allowlist that keeps `/bin`, `/usr`, `/System`, and the other usual locations working, adds one temp helper as `path`, sets `enforce`, and checks:

1. A second helper that is **not** on the allowlist fails to exec (non-zero status, no `ok` output) and the new log lines contain `decision=deny` for its path.
2. The allowlisted helper runs, prints `ok`, and the log contains `decision=allow` for its path.

It restores the previous allowlist and mode on the way out, including on failure. If a previous run died in enforce mode, run `sudo build/mad-elf-es mode monitor` before doing anything else.
