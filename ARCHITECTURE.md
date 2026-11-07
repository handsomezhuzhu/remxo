# Architecture

## Overview

Single Cargo package with a shared library, one `remxo` binary and a per-data-directory long-lived Broker process. Human CLI, AI CLI and TUI reuse Broker methods rather than separate policy/Vault implementations.

```text
CLI / TUI / Agent
       │ JSON-RPC over 127.0.0.1, random per-start token
       ▼
 Broker (locked on startup)
 ├─ config and target resolution
 ├─ policy + typed profiles + one-time approvals
 ├─ Vault session (encrypted disk ↔ DEK in Broker only)
 ├─ normalize → execute / transfer / tunnel / task
 ├─ output cap → redaction/exact-secret removal → truncate → control escaping
 └─ audit metadata
       │ argv only, never a local shell
       ▼
 OpenSSH ssh / scp -s / sftp            Telnet boundary (unsupported automation)
```

Loopback TCP is used for a simple cross-platform IPC prototype, with a random 256-bit endpoint token stored alongside the broker address in a permission-checked file. No DEK is passed through environment variables or returned to clients. This is **L1**, not OS-user isolation.

Automatic background startup uses the internal `__broker-daemon` path. On Unix, daemonization happens before Tokio creates worker threads, canonicalizes the private data root and applies umask `077`; this prevents an `unlock` PTY from taking the Broker down when its terminal closes. The independent foreground `__broker` entry remains useful for test process-group lifecycle management. Neither path transmits a master password or DEK through argv or environment variables.

## Modules

- `cli.rs`: clap contract, hidden password prompts, single-document JSON output, target-tail preservation.
- `config.rs`: strict serde/TOML models, host validation, `AppPaths`, deterministic target resolution.
- `broker.rs`: request dispatch, authentication, execution preparation, transfer authorization, lifecycle RPC and JSON envelope.
- `vault.rs`: two-key encryption, credential-kind checks, DEK rewrap, explicit locking.
- `backup.rs`: versioned RXB1 envelope, independent KDF/AEAD, verify/conflict/restore.
- `transport/`: object-safe Transport trait, capability reporting, bounded process I/O, OpenSSH and explicit Telnet unsupported boundary.
- `shell.rs`: POSIX-only command composition, cwd and sudo script generation.
- `policy.rs`: fixed typed profiles and approval decision aids; no keyword-blacklist security claim.
- `approval.rs`: expiring, approved-before-use, digest-bound, single-consumption in-memory approvals.
- `transfer.rs`: remote path parser, overwrite controls, argv-based SCP/SFTP.
- `task.rs` / `tunnel.rs`: in-memory states, bounded post-processed logs, cancellation and local process lifecycle.
- `output.rs` / `redact.rs`: bounded processing and untrusted-output controls.
- `audit.rs`: append-only JSONL event metadata without default full output.
- `tui.rs`: ratatui/crossterm panels, host filter and separate interactive SSH/hidden unlock flow.
- `store.rs`: private directory/file helpers and atomic writes.

## Data formats

Configuration has `version = 1`, strict unknown-field rejection, `settings` and `[hosts.alias]`. Save operations use same-directory temporary files, permission restriction and atomic replacement; existing configuration is backed up first.

Vault disk JSON has version, Argon2id parameters and salt, XChaCha-wrapped DEK and encrypted data. Replay/modification is detected according to AEAD for each envelope, but rollback to a previously valid same-password file is not a global freshness guarantee. Data serialization includes credential kinds; sudo requests must resolve `sudo-password` specifically.

RXB1 files contain a short magic/version prefix and encrypted envelope. Payload includes original config and encrypted Vault `VaultFile`, thus restoring requires its original master password. Restores are conflict-detected and per-file atomic but do not provide an all-or-nothing transaction across config and Vault.

## Execution flow

1. Parse global options only before the target/subcommand.
2. Broker loads config and resolves exact alias, number, registered IP or explicitly enabled ad-hoc IP.
3. Build POSIX script/profile; apply shell support and policy.
4. Compute SHA-256 operation digest including resolved connection configuration, relevant parameters and limits.
5. Require an unused human-approved matching approval if necessary.
6. If sudo is requested, obtain a typed sudo credential from the unlocked in-Broker Vault; never expose it in the request or argv.
7. Start system OpenSSH with piped/null stdin, bounded stdout/stderr readers, BatchMode and timeout; no host-key bypass or auto-retry.
8. Process outputs independently (including exact sudo-secret replacement), audit only digest/metadata and return result or stable error.
9. Remote nonzero exit remains different from connection/auth/host-key failures. A local cancel/timeout does not claim the remote process stopped.

Task and tunnel state lives only in the Broker process. A restarted Broker is locked and starts with empty runtime state. File transfers go through `prepare_transfer` so host raw mode, auth, overwrite mode and upload/overwrite approvals apply before `scp -s` starts. Tunnel creation waits for OpenSSH's completed interaction signal and a still-running process before storing the tunnel; bind-preview messages are not readiness. Startup is bounded, failed starts terminate the local child, and verbose child diagnostics are discarded rather than written to AI/audit output.

## Compatibility and future boundaries

Only POSIX non-interactive composition is supported in this phase. PowerShell, CMD, network device/custom shells must be separately designed and tested. Transport capabilities let callers distinguish secure OpenSSH from plaintext Telnet unsupported automation. No Telnet behavior is silently emulated over SSH.

L2 must move Broker to another OS user with least-privilege IPC and independent approval; merely moving the current token or password into that process is not enough. Native biometric unlock must bind key release to Hello/TPM or Keychain cryptographic operations. Later remote-detached tasks need a durable remote execution ID/state protocol rather than `nohup ... &` plus assumed success.

## Test strategy

Unit tests cover parsing, target rules, quoting/profiles, approval one-shot behavior, Vault/crypto properties, backup fresh-directory recovery, sudo typing/injection scrubbing, tasks and tunnel arguments. Fake ssh/scp executables validate argv, no host-key bypass, timeout, error classification, JSON secrecy, non-TTY behavior and actual fake transfer bytes.

`tests/integration/fault_and_stress.py` adds concurrent failures and lifecycle checks. `tests/integration/pty_acceptance.py` uses Linux PTYs for real hidden-password CLI and basic TUI flows. `tests/integration/sshd_acceptance.py` builds a disposable Alpine sshd container, generating temporary host/user keys and strict known_hosts; it covers real OpenSSH command/SFTP/tunnel/task behavior before destroying the test container. `tests/run_all.py` unifies these strata and reports unavailable environments explicitly. Detailed isolation, environment requirements and untested properties are in `TESTING.md`. No user's real server, production Vault, real `~/.ssh`, credentials or secret-bearing Infabox content is used.
