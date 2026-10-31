# Mad Elf

Mad Elf starts a binary with flags and environment variables that you set.
The configuration is part of the binary.
A wrapper on `PATH` does not do this, because a caller can start the real binary and ignore the wrapper.

The primary target is Node.js.
You can see the marker from the process (`process.env.MADELF_SHIM`, `process.execArgv`) and from outside (`mad-elf detect <pid>`).
The caller does not set environment variables.

## Linux

Mad Elf sets `PT_INTERP` on a **copy** of the binary to a small static-PIE shim.

1. Copy the binary.
2. Write the original interpreter path in `<copy>.madelf`.
3. Point `PT_INTERP` at `mad-elf-shim`.

On start, the kernel runs the shim.
The shim reads the config, adds missing flags and environment variables, sets `MADELF_SHIM=1`, and starts the original loader with `execve`.
Static binaries have no `PT_INTERP`. Install refuses them.

## macOS

Mad Elf does **not** use `DYLD_INSERT_LIBRARIES`.
Install writes an absolute `LC_LOAD_DYLIB` for `libmadelf.dylib` into the Mach-O header.

- The path must be absolute.
- dyld loads the dylib on every start. No environment variable is necessary.
- The constructor reads `<binary>.madelf`, applies the rules, and sets `MADELF_SHIM=1`.
- If a configured flag is missing, the constructor starts the same binary once with the flags after `argv[0]`.

If you move `libmadelf.dylib`, run install again.
Install does an ad-hoc `codesign` on the copy and the dylib.

## Config

File: `<binary>.madelf` (next to the binary).

| Directive | Meaning |
| --- | --- |
| `loader=` | Original `PT_INTERP` (Linux). Install writes this. |
| `flag=` | One argv element after `argv[0]` if it is not already there. |
| `setenv=` | Set `KEY=VALUE` only if the key is absent. |
| `forceenv=` | Replace `KEY=VALUE`. |
| `mergeenv=` | Add tokens that are not already present (usual key: `NODE_OPTIONS`). |

`MADELF_SHIM=1` is always set.

## Detect

```javascript
process.env.MADELF_SHIM === "1"
```

```bash
mad-elf detect <pid>   # exit 0 if this process is a Mad Elf start
mad-elf inspect <file>
```

## Install

```bash
make

# Linux
python3 mad-elf install --flag --no-warnings \
  "$(command -v node)" ./build/node-madelf

# macOS
clang -dynamiclib -o /opt/mad-elf/lib/libmadelf.dylib \
  -Wl,-install_name,/opt/mad-elf/lib/libmadelf.dylib \
  src/shim_darwin.c src/logic.c
python3 mad-elf install --dylib /opt/mad-elf/lib/libmadelf.dylib \
  --flag --no-warnings "$(command -v node)" ./build/node-madelf
```

## Limits

This is not a security boundary.
Setuid binaries are not supported.
The Linux shim is x86_64 only.

`es-demo/` is a separate Endpoint Security example. It is not part of the shim. See `es-demo/README.md`.

## Test

```bash
make test
```

CI runs `make test` on Linux and macOS.
