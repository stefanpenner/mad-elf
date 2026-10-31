# Mad Elf Endpoint Security demo

This is a small macOS system extension. It gets exec authorization events and allows or denies each exec.
It is a demo. It is not part of the Mad Elf shim.

**Warning:** The default mode is `monitor`. In `monitor` mode, all execs are allowed and logged.
In `enforce` mode, all execs that are not on the allowlist fail with `EPERM`.
Use `enforce` only when you watch the machine. Then set `monitor` again.

## Function

- Subscribes to `ES_EVENT_TYPE_AUTH_EXEC` (and `AUTH_EXEC_TRANSITION` if available).
- Writes one line for each event to `/var/log/madelf-es.log`: decision, mode, path, team id, signing id, parent pid, arguments.
- Reads the allowlist on each event. No cache.
- If it cannot read the allowlist, it allows the exec.

Allowlist: `/Library/Application Support/MadElfES/allowlist`

```text
path /usr/local/bin/node
prefix /usr/bin/
teamid ABCDE12345
signingid com.apple.bash
```

One match is sufficient. Put a `/` at the end of a `prefix`.

Mode: `/Library/Application Support/MadElfES/mode` (`monitor` or `enforce`).

## CLI

```bash
sudo build/mad-elf-es allow path /usr/bin/true
sudo build/mad-elf-es remove path /usr/bin/true
sudo build/mad-elf-es list
sudo build/mad-elf-es mode monitor
sudo build/mad-elf-es status
```

Use `--dir` or `MADELF_ES_DIR` to use a different directory (for tests).

## Build

```bash
cd es-demo && ./build.sh
```

The output is `build/MadElfES.app`. `build.sh` does not sign it.

## Requirements

- Apple must give your team the `com.apple.developer.endpoint-security.client` entitlement.
- The host must have `com.apple.developer.system-extension.install`.
- Both entitlements must be in the provisioning profile.
- Without the entitlement, you must disable SIP. Do this only on a test machine.

## Activate

1. Copy `MadElfES.app` to `/Applications`.
2. Run `/Applications/MadElfES.app/Contents/MacOS/madelf-es-host`.
3. Approve the extension in System Settings > Privacy & Security.
4. Give the extension Full Disk Access.
5. Make sure that `systemextensionsctl list` shows it as enabled.

To deactivate:

```bash
/Applications/MadElfES.app/Contents/MacOS/madelf-es-host deactivate
```

## Test a deny

```bash
sudo build/mad-elf-es allow prefix /bin/
sudo build/mad-elf-es allow prefix /usr/
sudo build/mad-elf-es allow prefix /System/
sudo build/mad-elf-es allow prefix /Library/
sudo build/mad-elf-es allow prefix /Applications/
sudo build/mad-elf-es mode enforce
/path/to/not-allowed ; echo exit:$?   # fails, log shows decision=deny
sudo build/mad-elf-es mode monitor
```

## Tests

`make test` runs `tests/test_policy.c` and `tests/test_cli.sh` on all systems.

`tests/test_integration.sh` does a real deny and allow test. It skips (exit 0) if the extension is not active on macOS.
It saves and restores your allowlist and mode.
If a test stops in `enforce` mode, run `sudo build/mad-elf-es mode monitor`.
