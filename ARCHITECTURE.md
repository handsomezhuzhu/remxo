# Architecture

## Overview

Single Cargo package with a shared library, one `remxo` binary and a per-data-directory long-lived Broker process. Human CLI, AI CLI and TUI reuse Broker methods rather than separate policy/Vault implementations. OpenSSH itself performs SSH protocol and authentication; Remxo prepares arguments and narrowly scoped credential handoffs.

```text
CLI / TUI / Agent                    OpenSSH-invoked ASKPASS
       │                                      │ current remxo executable + one prompt
       │ JSON-RPC over 127.0.0.1,             │ non-secret environment context
       │ random per-start token               ▼
       └──────────────────────────────► Broker (locked on startup)
                                        ├─ config and target resolution
                                        ├─ policy + typed profiles + one-time approvals
                                        ├─ Vault session (encrypted disk ↔ DEK in Broker only)
                                        ├─ typed single-Secret authentication lookup
                                        ├─ normalize → execute / transfer / tunnel / task
                                        ├─ output cap → redaction/exact-secret removal
                                        │  → truncate → control escaping
                                        └─ audit metadata
                                               │ argv only, never a local shell
                                               ▼
                           OpenSSH ssh / scp -s / sftp       Telnet boundary
                           + ASKPASS / managed temp key       (unsupported automation)
```

Loopback TCP is used for a simple cross-platform IPC prototype, with a random 256-bit endpoint token stored alongside the broker address in a permission-checked file. No DEK is passed through environment variables or returned to clients. The authentication RPC can return **one typed Secret** (`ssh-password` or `ssh-private-key`) selected from Host configuration; this is intentionally different from ordinary operation-result payloads but is not a Vault-dump facility or L2 boundary. This design is **L1**, not OS-user isolation.

Automatic background startup uses the internal `__broker-daemon` path. On Unix, daemonization happens before Tokio creates worker threads, canonicalizes the private data root and applies umask `077`; this prevents an `unlock` PTY from taking the Broker down when its terminal closes. The independent foreground `__broker` entry remains useful for test process-group lifecycle management. Neither path transmits a master password or DEK through argv or environment variables.

The binary has a second environment-selected internal entry. When `REMXO_ASKPASS_CONFIG` is present, `main` bypasses normal clap dispatch and passes OpenSSH's prompt arguments to the ASKPASS implementation. There is no `__askpass` CLI subcommand.

## Authentication flow

### External OpenSSH configuration and Agent

`openssh-config` and `external-agent` leave credential selection to OpenSSH. Noninteractive execution, SCP and tunnels add `BatchMode=yes`; interactive SSH/SFTP does not force that batch setting. External-Agent availability is checked where required and an unavailable Agent fails explicitly. Remxo never adds `ForwardAgent=yes` or weakens `known_hosts` checking.

### Vault password and private-key passphrase

Vault modes use these conventional names unless the Host explicitly supplies another credential stem:

| Purpose | Record name | Serialized kind |
| --- | --- | --- |
| SSH login password or private-key passphrase | `<stem>:ssh`, normally `<alias>:ssh` | `ssh-password` |
| Imported OpenSSH private key | `<stem>:key`, normally `<alias>:key` | `ssh-private-key` |
| Independent sudo password | `<alias>:sudo` for new sudo-enabled registrations | `sudo-password` |

Any Host without `sudo_credential`, including a legacy Host, continues to resolve the bare `<alias>` sudo record for compatibility. Type checks prevent an SSH or sudo credential from silently substituting for the other kind.

For `vault-password`, `prepare_authentication` adds `BatchMode=no`, `NumberOfPasswordPrompts=1`, password-only preferred authentication, and disables public-key and keyboard-interactive authentication. For `vault-key`, it obtains `<stem>:key` through `SecretForAuth { private_key: true }`, writes a short-lived managed identity file, and selects only that identity with `IdentitiesOnly=yes`, `IdentityAgent=none`, public-key authentication and no password/keyboard-interactive fallback. Both modes set:

```text
SSH_ASKPASS=<current remxo executable>
SSH_ASKPASS_REQUIRE=force
REMXO_ASKPASS_CONFIG=<config path>
REMXO_ASKPASS_TARGET=<target alias>
REMXO_ASKPASS_PENDING_HOST=<serialized non-secret Host; wizard only>
```

No password, passphrase, private key, master password or DEK enters those environment variables or OpenSSH argv. The serialized pending Host contains connection/policy and credential-name metadata, not imported file contents or password fields.

OpenSSH invokes the current executable with exactly one prompt. The internal entry accepts only password/passphrase prompt categories, with a length bound, and rejects host-key/yes/no/fingerprint confirmation, OTP, MFA, hardware PIN, token and unknown prompts. Valid requests call `SecretForAuth { private_key: false }`, verify the returned `ssh-password` kind, and write only that value plus a newline to helper stdout. Host-key confirmation is never converted into an automated “yes”; strict `known_hosts` behavior remains in force.

For normal registered operations, `credential_for_authentication` reloads configuration and resolves the target's current Host before selecting record name and expected type. It does not accept an arbitrary record name from ASKPASS. A pre-save wizard test instead supplies an explicit `pending_host`; the Broker validates it and rejects use of an alias that is already present in the saved inventory, so saved hosts must use registered configuration.

Secret plaintext is required transiently in process memory and serialized same-user RPC data. Passwords/passphrases also cross ASKPASS stdout into OpenSSH. Private keys are obtained by the process preparing OpenSSH and stored in `<data-root>/runtime` only for the child lifetime. `NamedTempFile` cleanup occurs when `ProcessAuthentication` drops; tunnel records retain that guard for the tunnel lifetime. A crash can bypass cleanup, deletion is not secure erasure, and zeroization cannot remove every copy. Unix temporary files are set to `0600`; equivalent native Windows ACL enforcement and real Windows Vault authentication have not been verified.

`vault import-key`/`ImportPrivateKey` reads and encrypts a copy in Vault. Import uses `symlink_metadata`, accepts a regular file only, rejects symlinks/directories/special files, enforces a 1 MiB metadata and streaming-read limit, and requires ASCII text whose first PEM marker is OpenSSH, RSA, EC or PKCS#8 (`PRIVATE KEY`). This is bounded structural validation, not a claim that the key was decrypted, authenticated or accepted by OpenSSH. The original path is not saved in Host and the source file is not changed.

The shared preparation path is used by one-shot exec, tasks, Broker-authorized SCP, interactive SFTP, TUI host-list interactive SSH, and tunnels. Public credential commands are `remxo vault set-ssh-password <host>` and `remxo vault import-key <host> [--path <file>]`; sudo remains separately configured with `vault set-sudo`.

### Wizard transaction boundary

Both Test and Save call SSH credential configuration before using the draft Host: `vault-password` stores the hidden password; `vault-key` imports the key first and then stores an optional passphrase. Test uses pending-Host authentication without saving the Host. Failed tests and Esc leave the saved inventory unchanged, but already imported credentials remain encrypted in Vault. Direct Save writes the Host after successful SSH credential import and does not require a previous Test. Optional sudo is a separate step after Host persistence; its failure does not roll back the Host. No part of this sequence is presented as an all-or-nothing transaction across Vault and configuration.

Editing is a separate flow. The alias is fixed, `edit_host` rejects an expected-Host mismatch and nonsecret edits reuse existing records without Broker access. Explicit credential rotation or auth-mode changes write new credentials beneath a versioned stem; only the edited Host save changes which stem is active, and abandoned or older encrypted records are not automatically erased. Save & test persists first and then probes through registered authentication, so saved aliases never become pending Hosts. Post-save test failure and sudo failure do not roll back configuration.

## Modules

- `main.rs`: pre-clap internal ASKPASS and detached-Broker entry selection; Unix daemonization before Tokio startup.
- `cli.rs`: clap contract, masked password prompts through `masked_prompt`, `init --lang`, internal ASKPASS prompt filtering/output, localized human-facing errors with stable JSON details, public Vault credential commands, single-document JSON output and target-tail preservation.
- `config.rs`: strict serde/TOML models, host validation, persisted `en`/`zh-CN` UI language with English legacy default, `AppPaths` and deterministic target resolution.
- `text_input.rs`: cursor-safe single-line editing, bounded paste, Unicode display-width/window helpers and best-effort zeroized storage, used by ordinary and masked inputs.
- `masked_prompt.rs`: one-line secret prompts that keep terminal ECHO disabled while rendering only local `*` masks and a movable cursor; no CPR-dependent cursor query is used.
- `i18n.rs`: sanitized human-facing English/Chinese error mappings; machine JSON codes/details remain unchanged.
- `broker.rs`: request dispatch, Vault unlock/mutation, typed single-Secret authentication lookup, registered/pending Host re-resolution, execution preparation, transfer authorization, lifecycle RPC and JSON envelope.
- `vault.rs`: two-key encryption, credential-kind checks, DEK rewrap and explicit locking.
- `credential.rs`: bounded private-key import, conventional SSH/key/sudo record names, and restricted managed temporary-key lifetime.
- `backup.rs`: versioned RXB1 envelope, independent KDF/AEAD, verify/conflict/restore.
- `transport/`: object-safe Transport trait, capability reporting, bounded process I/O, shared `AuthenticationContext`, OpenSSH `prepare_authentication`, ASKPASS process environment and explicit Telnet unsupported boundary.
- `shell.rs`: POSIX-only command composition, cwd and sudo script generation.
- `policy.rs`: fixed typed profiles and approval decision aids; no keyword-blacklist security claim.
- `approval.rs`: expiring, approved-before-use, digest-bound, single-consumption in-memory approvals.
- `transfer.rs`: remote path parser, overwrite controls, argv-based authenticated SCP/SFTP.
- `task.rs` / `tunnel.rs`: in-memory states, bounded post-processed logs, cancellation, shared authentication preparation and local process lifetime (including managed-key guards).
- `output.rs` / `redact.rs`: bounded processing and untrusted-output controls.
- `audit.rs`: append-only JSONL event metadata without default full output or credential values.
- `tui.rs`: ratatui/crossterm bilingual panels, searchable host list, editable basic settings, explicit saved-Host connection tests, numeric pages and separate interactive authenticated SSH and masked unlock flow.
- `tui_wizard.rs`: bilingual add/edit forms with real cursor handling, masked secrets, quoted private-key-path normalization, pending-Host creation tests, registered-Host post-edit tests, non-transactional credential/versioned-stem persistence and optional post-save sudo.
- `host.rs`: shared add/edit registration used by command-line and form flows; validates and atomically saves without storing secret values or imported private-key paths in Host or preview. Edits use expected-Host checks to reject stale forms.
- `store.rs`: private directory/file helpers and atomic writes. Unix modes are explicit; non-Unix helpers do not by themselves establish equivalent native Windows ACLs.

## Native npm launcher

The optional npm distribution is not another runtime or UI. `npm/bin/remxo.js` and `npm/lib/*` map the current OS/architecture to a same-version platform package under `@remxo/core-*`. Current optional packages are intentionally limited to Windows x64 and Linux x64 (glibc); macOS package targets are paused until real-device verification is available. Each package carries only its native `vendor/<target>/bin/remxo[.exe]`; no postinstall download or user-side Cargo/N-API build is used. Strict manifests, package versions and native `--version` are checked during staging. Missing packages, unsupported targets and version mismatches fail closed; the launcher never falls back to PATH. Supporting Unix uses `execve` with the native binary as argv0; other hosts use a direct argv-based child with inherited terminal I/O and preserve exit/signal behavior. `REMXO_CORE_PATH` is reserved for development/isolated fixtures, not production resolution. The packaged Broker-daemon and ASKPASS paths still select the native executable itself, never Node.

## Data formats

Configuration has `version = 1`, strict unknown-field rejection, `settings` and `[hosts.alias]`. `settings.language` is persisted as `en` or `zh-CN`; missing legacy values deserialize as `en`. Save operations use same-directory temporary files, permission restriction where implemented and atomic replacement; existing configuration is backed up first.

`remxo init --lang en|zh-CN` selects language explicitly. An interactive TTY without the option offers a numbered `1`/`2` language menu (empty input defaults to English) and also accepts the existing language names. JSON/non-TTY avoids that question and defaults to English. Hidden master-password input still requires a TTY. `unlock` reads the saved language for its masked prompt and success message. New passwords are validated before creating config or Vault. An existing Vault is never implicitly overwritten. If only a valid config exists after interrupted setup, initialization preserves it—including its language, hosts and settings—and completes only the missing locked Vault; invalid config fails closed without replacement.

Vault disk JSON has version, Argon2id parameters and salt, XChaCha-wrapped DEK and encrypted data. Replay/modification is detected according to AEAD for each envelope, but rollback to a previously valid same-password file is not a global freshness guarantee. Data serialization includes credential kinds and values for SSH passwords/passphrases, imported private keys, sudo and Telnet records. Sudo and SSH lookups require their specific kinds.

RXB1 files contain a short magic/version prefix and encrypted envelope. Payload includes original config and encrypted Vault `VaultFile`, including imported Vault private keys in ciphertext form; restore requires the original master password. External Agent/private hardware-key material and platform-bound identities are not exported. Restores are conflict-detected and per-file atomic but do not provide an all-or-nothing transaction across config and Vault.

## Execution flow

1. Parse global options only before the target/subcommand.
2. Broker loads config and resolves exact alias, number, registered IP or explicitly enabled ad-hoc IP.
3. Build POSIX script/profile; apply shell support and policy.
4. Compute SHA-256 operation digest including resolved connection configuration, relevant parameters and limits.
5. Require an unused human-approved matching approval if necessary.
6. Obtain an independent typed sudo credential if requested. Vault SSH authentication uses a separate typed lookup at transport preparation time.
7. Build a registered authentication context for Vault modes. `prepare_authentication` applies external/Vault OpenSSH options; Vault keys are materialized only into the managed temporary identity file and ASKPASS carries no secret environment values.
8. Start system OpenSSH with piped/null noninteractive stdin, bounded stdout/stderr readers and timeout. Legitimate ASKPASS callbacks re-resolve their registered Host in Broker; unknown host keys fail rather than being accepted.
9. Process outputs independently (including exact sudo-secret replacement), audit only digest/metadata and return result or stable error.
10. Remote nonzero exit remains different from connection/auth/host-key failures. A local cancel/timeout does not claim the remote process stopped and does not trigger write retry.

The TUI's interactive host-list action and the ordinary `remxo <alias>` path without a remote command both use the same Vault preparation with inherited terminal I/O; SFTP does likewise. SCP and tunnel startup use noninteractive authentication rules. Task and tunnel state lives only in the Broker process. A restarted Broker is locked and starts with empty runtime state. File transfers go through `prepare_transfer` so host raw mode, auth, overwrite mode and upload/overwrite approvals apply before `scp -s` starts. Tunnel creation waits for OpenSSH's completed interaction signal and a still-running process before storing the tunnel; bind-preview messages are not readiness. Startup is bounded, failed starts terminate the local child, and verbose child diagnostics are discarded rather than written to AI/audit output.

## Compatibility and future boundaries

Only POSIX non-interactive composition is supported in this phase. PowerShell, CMD, network device/custom shells must be separately designed and tested. Transport capabilities let callers distinguish secure OpenSSH from plaintext Telnet unsupported automation. No Telnet behavior is silently emulated over SSH.

L2 must move Broker to another OS user with least-privilege IPC and independent approval. Moving the token, Secret response, ASKPASS helper or password into a different same-user process is not L2. Native biometric unlock must bind key release to Hello/TPM or Keychain cryptographic operations. Later remote-detached tasks need a durable remote execution ID/state protocol rather than `nohup ... &` plus assumed success.

## Test strategy

Rust unit tests cover configuration language defaults/persistence, ASKPASS prompt classification, private-key marker/shape and Unix temp-file/symlink behavior, wizard hidden-secret rendering and bilingual controls, in addition to the existing target/policy/Vault/backup/sudo/task/tunnel tests. `tests/cli_end_to_end.rs` also contains a fake-ssh Vault-password fixture that invokes the real current-executable ASKPASS helper, checks prompt rejection and secret-free argv/audit, and verifies managed-key cleanup after transport timeout. Their exact scope and the results of actually running them are described below and in [TESTING.md](TESTING.md).

Fake ssh/scp executables validate argv, no host-key bypass, timeout, error classification, JSON secrecy, non-TTY behavior and fake transfer bytes. `tests/integration/fault_and_stress.py` adds failures/concurrency/lifecycle. `tests/integration/pty_acceptance.py` drives Linux masked-password asterisks, explicit-English and numeric Chinese init/localized unlock, real cursor-based host editing, saved-Host `doctor`, basic TUI, and Vault password/key wizard Test→Save flows. `tests/integration/sshd_acceptance.py` and `sudo_acceptance.py` use disposable Alpine sshd and strict `known_hosts` for real protocol paths. `tests/integration/vault_auth_acceptance.py` adds real-sshd Vault-password/encrypted-key exec and SCP, strict-host-key negative/restore checks, completed-runtime-key cleanup and secret-hygiene assertions. It is wired into `--only real`; task/tunnel/interactive/Vault variants remain separate unvalidated paths rather than implied coverage.

The current working tree was actually checked on 2026-11-08: Windows native Clippy/all-target Rust tests/build passed, and an isolated Linux Instabox run of `python3 tests/run_all.py` passed every listed suite, including fake, six PTY cases, real SSH, Vault password/encrypted-key exec and SCP, sudo, and cleanup. [TESTING.md](TESTING.md) records the result and remaining untested branches. Windows native permission/real authentication, every Vault task/tunnel/interactive path, and crash cleanup are **NOT_RUN**; the result is not a cross-platform or independent security assurance.
