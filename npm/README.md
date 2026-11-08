# remxo

**Remote execution for humans and agents.**

This package is a thin native launcher. It contains no Rust code and no prebuilt
binary of its own: it resolves the exact-version platform package for your
`process.platform` and `process.arch`, validates it, and hands your `argv` to the
native `remxo` executable.

## Install

```console
npm install -g remxo
```

Requires Node.js 18 or newer.

Release candidates are published to the `rc` dist-tag instead:
`npm install -g remxo@rc`.

## Supported platforms

| Platform | Package |
| --- | --- |
| Windows x64 | `@remxo/core-win32-x64` |
| Linux x64 (glibc) | `@remxo/core-linux-x64` |

Both platform packages are installed automatically as optional dependencies.
A missing or version-mismatched platform package fails with an explicit error
instead of falling back to some other `remxo` found on `PATH`.

Alpine/musl and other unlisted platforms need a separate native build and
verification; the glibc package is not guaranteed to run there. macOS support is
paused until a real Apple device is available for verification, so the current
optional packages intentionally cover only Windows and Linux.

## First run

The launcher does not print a banner and runs no install script. The native CLI
guides you from your first command:

```console
remxo init --lang zh-CN   # or: remxo init --lang en
remxo unlock              # master password, entered hidden with * feedback
remxo status
remxo hosts

remxo prod-01 df -hT
remxo --json prod-01 ls -la
```

On a fresh install `remxo status` reports an empty inventory, and adding a host
tells you to run `remxo init` first. Master and backup passwords must be at
least 12 bytes and are only accepted at hidden interactive-terminal prompts.

## What the launcher does not do

- It never invokes a local `sh -c` or any other shell to start the core.
- It has no postinstall step: nothing is downloaded, compiled, or updated at
  install or run time.
- It never searches `PATH` for a `remxo` binary. `REMXO_CORE_PATH` exists only
  for development and isolated test fakes, and an empty or invalid value fails
  closed rather than silently falling back.
- On Unix it uses `execve` with `argv0` preserved; on Windows it spawns a direct
  child with inherited stdio and forwards exit codes and signals.

## Security posture

Remxo is a development build **without an independent security audit**. Its
security level is **L1**, not L2 same-user isolation. It does not claim absolute
production safety and does not replace the authorization boundary of the remote
account. It reuses the system OpenSSH client and does not disable host-key
verification.

Credentials live in an encrypted Vault protected by a master password you enter
yourself. Remxo never asks you to hand a password, private key, or passphrase to
an AI agent or to another process.

## Documentation

- Project documentation: <https://github.com/handsomezhuzhu/remxo/tree/main/docs>
- Issues: <https://github.com/handsomezhuzhu/remxo/issues>

## License

MIT
