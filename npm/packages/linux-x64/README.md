# @remxo/core-linux-x64

Precompiled native `remxo` core for **Linux x64 (glibc)**.

You normally never install this package directly. It is an optional dependency
of [`remxo`](https://www.npmjs.com/package/remxo), which resolves and validates
it automatically:

```console
npm install -g remxo
```

## What this package contains

A single executable, placed at the versioned vendor path the launcher expects:

```text
vendor/x86_64-unknown-linux-gnu/bin/remxo
```

The package version and the output of `remxo --version` must match exactly. The
launcher checks this on every invocation and fails closed on a mismatch, so this
package is published only together with the matching `remxo` launcher version.

## Platform notes

This package is built against **glibc** and declares `"os": ["linux"]`,
`"cpu": ["x64"]`, `"libc": ["glibc"]`, so npm will not install it on other
platforms.

Alpine and other musl-based distributions are **not** covered by this package.
Remxo needs a separate native build and verification there; the glibc binary is
not guaranteed to run on musl.

macOS support is paused until a real Apple device is available for verification,
so there is intentionally no `@remxo/core-darwin-*` package yet.

## If you installed this on purpose

Only do so on Linux x64 with glibc, and only at the same version as your `remxo`
launcher. Installing it on another platform, or at a different version, will
make `remxo` refuse to run rather than silently pick a wrong binary.

## Documentation and issues

- <https://github.com/handsomezhuzhu/remxo/tree/main/docs>
- <https://github.com/handsomezhuzhu/remxo/issues>

## License

MIT
