# Mad Elf

Mad Elf makes a specific binary start with flags and environment variables you choose, even when something else execs it. The configuration is attached to the binary. A wrapper script on `PATH` does not do that, because the next caller can exec the real binary and skip the wrapper.

The primary target is Node.js: `NODE_OPTIONS`, ordinary `node` flags, and a marker you can see from inside the process (`process.env.MADELF_SHIM`, `process.execArgv`) and from outside (`mad-elf detect <pid>`).

Linux and macOS use different mechanisms. Both are env-var-free for the caller. The caller does not have to set anything.

## Linux: `PT_INTERP`

A dynamically linked ELF names its dynamic loader in the `PT_INTERP` program header (usually `/lib64/ld-linux-x86-64.so.2`). The kernel maps that file and jumps to it before the program's own entry point.

Mad Elf installs a small freestanding static-PIE shim as that interpreter:

1. Copy `node` (do not patch the only copy you have).
2. Record the original interpreter path in `<copy>.madelf`.
3. Point the copy's `PT_INTERP` at `mad-elf-shim`.

On exec the kernel runs the shim. The shim reads the config, fills in missing flags and environment variables, sets `MADELF_SHIM=1`, and `execve`s the original loader:

```text
ld-linux --argv0 <original argv0> <binary> <injected flags> <original args...>
```

`ld.so` then maps the binary the way it always does. It does not consult `PT_INTERP` again, so this does not loop. `--argv0` (glibc 2.33+) keeps the `argv0` the caller passed, including `exec -a my-node`.

The shim is freestanding on purpose. A normal glibc static-PIE relocates itself from the auxiliary vector, and that vector describes the main executable when the kernel invokes a `PT_INTERP`. That crashes. The shim uses syscalls only and is linked so it has no relocations.

Static binaries have no `PT_INTERP`. `mad-elf install` refuses them. There is nothing to run before their entry point.

You can do the interpreter swap yourself with `patchelf --set-interpreter` on a copy. `mad-elf install` does the same edit: if the new path fits in the existing header it is written in place, otherwise it is appended and the program header is retargeted. The original loader path has to live in the config either way. If you only change `PT_INTERP` and forget the config, the shim cannot find `ld.so` and exits 127.

## macOS: absolute `LC_LOAD_DYLIB`

Mach-O has `LC_LOAD_DYLINKER`, and on a normal executable it is dyld. SIP and the hardened runtime do not give you a supported way to replace dyld the way `PT_INTERP` replaces `ld.so`.

`DYLD_INSERT_LIBRARIES` is not the mechanism here. It is an environment variable whose value is a colon-separated list of dylib paths. dyld reads it for the process it is about to start. Like any other environment variable, a child inherits it unless the parent clears it or something strips it. dyld and SIP strip it for protected system binaries, and the hardened runtime strips it unless the binary has `com.apple.security.cs.allow-dyld-environment-variables`. A caller who does not set the variable gets no injection. That fails the requirement that Node behave the same no matter who execs it and with a clean environment.

The supported macOS path is a load command written into the Mach-O header:

- `mad-elf install --dylib /absolute/path/libmadelf.dylib node node-madelf`
- The path must be absolute. `@executable_path`, `@loader_path`, and `@rpath` are rejected.
- The filename must be `libmadelf.dylib`, so `mad-elf detect` can recognize it.
- dyld loads that dylib on every exec of that binary. No environment variable is required.
- The dylib's constructor runs before `main`. It reads `<binary>.madelf`, applies environment rules with `setenv`, and sets `MADELF_SHIM=1`.
- dyld has already captured the kernel argument vector by then, so a constructor cannot splice new slots into the argv array `main` is about to receive. When a configured flag is missing, the constructor `execve`s the same binary once (the pid does not change) with the flags inserted after `argv[0]`. The second start sees the flags and does not exec again. `process.execArgv` and `ps` then show them. Open file descriptors are preserved.

Tradeoff: the absolute path is part of the binary. Moving or renaming `libmadelf.dylib` breaks every patched binary until you run install again (or rewrite the load command). That is deliberate. A relative path would resolve differently depending on the working directory or which copy of Node was exec'd.

The load command has to be applied to every binary that actually gets exec'd. Patching `node` covers child processes that exec that same file. It does not cover a different `node` elsewhere on `PATH`.

Header slack is required. The injector will not shift segments (that breaks the virtual addresses the linker already baked in). If install reports that there is not enough slack, relink with `-Wl,-headerpad_max_install_names`, or start from a Node build that has header padding. Homebrew and the official Node builds usually do.

After the header changes, the signature is invalid. Install ad-hoc signs the copy (`codesign -f -s -`) without the hardened runtime, and signs the dylib the same way. Library validation (the default once the hardened runtime is on) rejects a dylib signed by a different team, and two ad-hoc signatures do not share a team id. To keep the hardened runtime, sign both with the same Team ID, or add `com.apple.security.cs.disable-library-validation`. SIP still prevents modifying binaries on the sealed system volume. Copy Node off that volume and patch the copy. A self-built Node is the straightforward case.

## Config

`<binary>.madelf`, next to the binary. On Linux, install can also embed the same text in an ELF section named `.madelf` (`--embed` or `--embed-only`). A sibling file wins over the section when both exist, so you can edit the file without rewriting the binary.

```text
loader=/lib64/ld-linux-x86-64.so.2
flag=--no-warnings
setenv=MADELF_PROFILE=strict
forceenv=OTHER=value
mergeenv=NODE_OPTIONS=--zero-fill-buffers
markerfile=/tmp/madelf-order
```

| Directive | Meaning |
| --- | --- |
| `loader=` | Original `PT_INTERP`. First line wins. Install writes this. Required on Linux. Ignored on macOS. |
| `flag=` | One argv element, inserted after `argv[0]` when that exact element is not already present. Repeated lines are deduped. |
| `setenv=` | `KEY=VALUE`, set only when the variable is absent. |
| `forceenv=` | `KEY=VALUE`, replace an existing value. |
| `mergeenv=` | Append whitespace-separated tokens that are not already present. `NODE_OPTIONS` is the usual key. |
| `markerfile=` | macOS constructor appends `ctor\n` once it is about to return to `main`. |

`MADELF_SHIM=1` is always forced, including when a directive tried to set another value. Other variables follow the rules above: an existing `MADELF_PROFILE` is left alone by `setenv`, and an existing `NODE_OPTIONS` gains only the tokens it does not already have.

Limits: 64 env directives, 64 flags, keys under 256 bytes, values and flags under 1024 bytes, paths under 512 bytes, config text under 64 KiB.

On macOS the inserted flags are real argv, so they have to be legal for the program. For Node that means a normal node option such as `--no-warnings`, not a script argument.

## Detecting it

From inside Node:

```javascript
process.env.MADELF_SHIM === "1"
process.execArgv.includes("--no-warnings")  // whatever flag= you configured
```

`examples/check-from-node.js` prints that and exits 0 when the marker is set.

From outside:

```bash
mad-elf detect <pid>
```

Exit 0 when the process is a mad-elf launch. On macOS that means `proc_pidpath` is a binary with an absolute `LC_LOAD_DYLIB` ending in `/libmadelf.dylib`. On Linux the kernel cmdline is the handoff to the real loader:

```text
ld-linux --argv0 <argv0> <patched-binary> <injected flags> <original args...>
```

`/proc/<pid>/exe` is therefore `ld.so`, not Node. `ps` shows the same prefix. The injected flags are still in that cmdline. Node itself sees the original `argv0` (`process.argv0`) because of `--argv0`. `mad-elf detect` recognizes the layout when `<patched-binary>` is a mad-elf binary (`PT_INTERP` is `mad-elf-shim`, or it differs from the `loader=` recorded in its config) and says whether `MADELF_SHIM=1` is set. A process whose `/proc/<pid>/exe` is already the patched file counts too.

`MADELF_SHIM` is an environment variable, so children inherit it until something clears it. `mad-elf detect` does not treat that inherited variable as a match. A `/bin/sleep` spawned by a patched Node can show `MADELF_SHIM=1` and still be reported as not launched through the shim. A child that execs the patched Node binary does go through the shim again, because the kernel or dyld consults the binary, not the inherited environment.

Someone who runs the dynamic loader by hand (`ld.so ./node-madelf`) bypasses `PT_INTERP`. `detect` may still notice the patched file. That invocation did not run the shim.

## Install and run

Linux x86_64. You need `gcc`, `python3`, and a dynamically linked Node if you want the Node test. `objcopy` is only needed for `--embed`.

```bash
make
python3 mad-elf install \
  --flag --no-warnings \
  --setenv MADELF_PROFILE=strict \
  "$(command -v node)" ./build/node-madelf

./build/node-madelf -e 'console.log(process.env.MADELF_SHIM, process.execArgv)'
python3 mad-elf inspect ./build/node-madelf
python3 mad-elf detect <pid>
```

The shim in that example is `build/mad-elf-shim`. Its path is absolute inside `PT_INTERP`. Moving the shim without reinstalling breaks the copies that point at it, same as moving the macOS dylib.

macOS, after `make` (the Linux shim is not built there):

```bash
clang -dynamiclib -o /opt/mad-elf/lib/libmadelf.dylib \
  -Wl,-install_name,/opt/mad-elf/lib/libmadelf.dylib \
  src/shim_darwin.c src/logic.c

python3 mad-elf install \
  --dylib /opt/mad-elf/lib/libmadelf.dylib \
  --flag --no-warnings \
  "$(command -v node)" ./build/node-madelf

env -i HOME="$HOME" TMPDIR="${TMPDIR:-/tmp}" ./build/node-madelf \
  -e 'console.log(process.env.MADELF_SHIM, process.execArgv, process.env.DYLD_INSERT_LIBRARIES)'
```

`env -i` is the interesting case: nothing, including `DYLD_INSERT_LIBRARIES`, is set by the caller.

`mad-elf inspect <file>` prints the interpreter or the Mach-O load commands and the config.

## What this does not do

This is not a security boundary. Anyone who can write the binary, or point `exec` at a different binary, skips it. It does not stop Node from spawning other programs. The separate `es-demo/` directory is a minimal Endpoint Security example that can deny execs; it is not wired into the shim.

Setuid binaries are not supported. The shim does not try to be careful about `AT_SECURE`.

The Linux shim is x86_64 only. The entry code is `src/entry_x86_64.S`.

macOS re-exec costs one extra dyld startup when flags have to be inserted. File descriptors without `CLOEXEC` stay open, which is what a normal `execve` does. The final process image runs constructors once.

## Tests

```bash
make test
```

On Linux that builds the shim, runs unit tests for the config/argv/env logic, patches a small dynamic binary and a real `node`, and checks flags, environment merging, `argv0`, embedded config, `/proc/<pid>/cmdline`, and `mad-elf detect` (including the inherited-env false positive). Mach-O injection is tested against synthetic thin and fat binaries, including rejection of relative and `@rpath` paths. The macOS runtime test and the Endpoint Security deny/allow test skip with status 0.

On macOS, `tests/test_darwin.py` builds `libmadelf.dylib`, injects an absolute `LC_LOAD_DYLIB` into a throwaway host (and into `node` when that binary has header slack), launches it with `env -i`, and checks that the constructor ran before `main` (`ctor` then `main` in the marker file), that the flag is in argv, and that `DYLD_INSERT_LIBRARIES` is unset. The Node portion also checks `process.execArgv` and that the constructor ran before the first line of JavaScript.

GitHub Actions runs the same `make test` on `ubuntu-latest` and `macos-latest` (`.github/workflows/ci.yml`).

## Endpoint Security demo

`es-demo/` is a separate, minimal macOS system extension. It subscribes to exec authorization events and can deny binaries that are not on an allowlist. It is not required for the shim. Read `es-demo/README.md` before loading it. It starts in monitor mode so that installing it does not deny every exec on the machine.
