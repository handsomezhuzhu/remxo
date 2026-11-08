# @remxo/core-win32-x64

Precompiled native `remxo` core for **Windows x64**.

You normally never install this package directly. It is an optional dependency
of [`remxo`](https://www.npmjs.com/package/remxo), which resolves and validates
it automatically:

```console
npm install -g remxo
```

## What this package contains

A single executable, placed at the versioned vendor path the launcher expects:

```text
vendor/x86_64-pc-windows-msvc/bin/remxo.exe
```

The package version and the output of `remxo --version` must match exactly. The
launcher checks this on every invocation and fails closed on a mismatch, so this
package is published only together with the matching `remxo` launcher version.

## If you installed this on purpose

Only do so on Windows x64, and only at the same version as your `remxo`
launcher. Installing it on another platform, or at a different version, will
make `remxo` refuse to run rather than silently pick a wrong binary.

## Documentation and issues

- <https://github.com/handsomezhuzhu/remxo/tree/main/docs>
- <https://github.com/handsomezhuzhu/remxo/issues>

## License

MIT
