# Remxo

**Remote execution for humans and agents.**

[English](README.md) | [简体中文](README.zh-CN.md)

Remxo is a local remote-server inventory, orchestration, and execution tool. It reuses the system OpenSSH client and provides an encrypted Vault, a same-user Broker, policies and one-time approvals, AI-oriented JSON, metadata audit, a basic bilingual TUI, and limited file-transfer, tunnel, and background-task support.

> This is a development build without an independent security audit. Its security level is **L1**, not L2 same-user isolation. It does not claim absolute production safety and does not replace the authorization boundary of the remote account.

## Implemented scope

- Strict TOML v1 configuration; host aliases, numbers, and registered-IP resolution; unregistered IPs denied by default.
- OpenSSH one-shot commands and interactive SSH through `argv`, never a local `sh -c`, without disabling host-key verification.
- Four authentication modes: `openssh-config`, `external-agent`, `vault-password`, and `vault-key`.
- Noninteractive `BatchMode=yes` for OpenSSH config/external Agent authentication; Vault authentication uses `BatchMode=no`, forced ASKPASS, and one password prompt.
- Masked TUI/CLI entry of SSH passwords and private-key passphrases, with visible `*` feedback and editable cursors; Vault import of regular-file OpenSSH/RSA/EC/PKCS#8 PEM private keys, with symlink rejection and a 1 MiB limit.
- Argon2id-derived KEK, random DEK, and XChaCha20Poly1305 Vault encryption. A Broker starts locked; changing the master password rewraps the same DEK.
- Independently encrypted `.rxb` backup, verification, conflict detection, and fresh-directory restore. The backup nests the still-encrypted Vault and contains no plaintext DEK, sockets, tasks, approvals, or logs.
- Same-user loopback Broker with a random IPC token and restricted requests. Normal operation results do not contain the Vault; the internal authentication RPC can return one typed Secret when required for SSH authentication.
- Raw/profile policies, short-lived one-time approvals, SHA-256 request digests, and JSONL metadata audit.
- Bounded output, common-secret redaction, control-character escaping, and exact removal of echoed sudo passwords.
- Broker task state/logs/cancellation, basic OpenSSH tunnel lifecycle, and Broker-authorized SCP upload/download using forced SFTP mode.
- English and Simplified Chinese main TUI and host wizard, with Hosts, Sessions, Tasks, Approvals, Audit, Backup, and Settings panels.

## Build and test

Stable Rust (MSRV 1.88), Python 3 for the integration driver, and a system OpenSSH client are required.

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build
```

On Linux, run the self-contained fake, PTY, and optional Docker/real-sshd suites without supplying any real server or credential:

```console
python3 tests/run_all.py
```

See [TESTING.md](TESTING.md) for test layers, cleanup rules, environment requirements, and current verification limits. On 2026-11-08 this working tree passed Windows native Clippy, all-target Rust tests, and build, plus the complete Linux `python3 tests/run_all.py` suite on an isolated Instabox machine (fake, six PTY cases including numeric Chinese init/localized unlock, masked input, cursor-based host editing and saved-Host `doctor`, real SSH/SFTP/tunnel/task checks, Vault-password/encrypted-key exec and SCP, sudo, and cleanup). These results do not establish Windows native ACL/real Vault authentication, every Vault task/tunnel/interactive path, crash cleanup, credential-rotation failures, or universal server compatibility.

`REMXO_SSH` and `REMXO_SCP` may point to isolated test fakes. Never point them at an untrusted program for a real host.

## Quick start

Master and backup passwords must contain at least 12 bytes and are accepted only at hidden interactive-terminal prompts. A short password is rejected before any configuration or Vault file is written. If an earlier attempt left a valid `config.toml` but no `vault.json`, rerunning `init` preserves that configuration and creates only the missing locked Vault; it does not reset the configuration or rewrap an existing Vault.

```console
# Choose the UI language explicitly; passwords are entered with visible * masks.
remxo init --lang en
# Or select Simplified Chinese:
remxo init --lang zh-CN

# Reuse an existing OpenSSH Host alias without modifying ~/.ssh/config.
remxo host add prod-01 --ssh-alias real-prod-alias --number 2 \
  --environment production --auth external-agent

remxo unlock
remxo status
remxo hosts

remxo prod-01 ls -la
remxo 2 df -h
remxo --json prod-01 'cd /var/www && git status'
remxo --cwd /var/www prod-01 ls -la
remxo host edit prod-01
remxo doctor prod-01
remxo prod-01 --profile logs --arg service=nginx --arg lines=100
```

Without `--lang`, a TTY offers a numbered English/Simplified Chinese menu (`1` for English, `2` for Simplified Chinese) and defaults to English on an empty response. Language names remain accepted at this prompt, while `--lang` still accepts `en|zh-CN`. `--json` or a non-TTY invocation selects English without asking a language question; masked master-password entry with `*` feedback still requires an interactive terminal. Old configurations without `settings.language` default to `en`. Recovery with an existing valid configuration preserves its saved language, regardless of the language selected for the recovery messages. `unlock` localizes its hidden prompt and success message from the saved language. The main TUI and wizard follow the configured language; this is not a claim that every CLI/JSON error is localized.

Global options before the target include `--json`, `--no-color`, `--timeout`, `--max-output`, `--cwd`, `--config`, `--verbose`, `--sudo`, and `--overwrite`. Arguments after the target belong to the remote command: `remxo prod-01 ls -l --help` does not treat the remote `--help` as local help.

In `openssh-config`/`external-agent` modes, no command on a TTY opens interactive SSH; no command without a TTY is a usage error. Bare `remxo` enters the TUI only on a real interactive TTY. Subcommand names and global-option positions are reserved, so host aliases must not conflict with them. The TUI host-list **Enter** path supplies Broker authentication context for Vault-managed interactive SSH.

A human should perform first-use host-key verification in advance. Remxo never adds `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, or `ForwardAgent=yes`.

`remxo doctor [alias]` first validates local configuration and explicitly, on request, probes one saved Host with a bounded POSIX `true` handshake through the same authentication preparation. It reports the result without weakening host-key checks or issuing a write command; it is not an automatic background health monitor.

## SSH authentication and Vault credentials

| Host `auth` value | Credential source | OpenSSH behavior |
| --- | --- | --- |
| `openssh-config` | Existing OpenSSH configuration and its normal interactive login | Noninteractive operations use `BatchMode=yes`; interactive operations retain normal OpenSSH interaction. |
| `external-agent` | Existing external SSH Agent | Noninteractive operations use `BatchMode=yes`; an unavailable required Agent fails instead of silently choosing another credential. |
| `vault-password` | `ssh-password` record at `<credential-stem>:ssh`, normally `<alias>:ssh` | Uses `BatchMode=no`, forced ASKPASS, `NumberOfPasswordPrompts=1`, and password-only authentication with public-key and keyboard-interactive authentication disabled. |
| `vault-key` | `ssh-private-key` record at `<credential-stem>:key`, normally `<alias>:key`; an encrypted key also uses `<stem>:ssh` for its passphrase | Uses a managed temporary identity file, `IdentitiesOnly=yes`, `IdentityAgent=none`, public-key-only authentication, forced ASKPASS, and one passphrase prompt. |

For `vault-password`, the public CLI stores the SSH login password with `vault set-ssh-password`. For `vault-key`, it stores an optional private-key passphrase with the same command and imports the key with `vault import-key`. The host must already be registered with the matching authentication mode. An unencrypted Vault-managed key does not need a passphrase; an encrypted key needs the correct `ssh-password` record.

```console
remxo unlock

# For a registered host with auth = "vault-password":
remxo vault set-ssh-password prod-01

# For a registered host with auth = "vault-key":
remxo vault import-key prod-01 --path /path/to/id_ed25519
# Optional passphrase for that imported private key:
remxo vault set-ssh-password prod-01
```

The private-key path is accepted as an option or a visible TUI field; it is not the key contents and is not persisted in the Host object. Relative paths are resolved against the caller's working directory before being sent to the Broker, so daemon working-directory changes do not change their meaning. Password/passphrase input is shown only as `*` masks and never as “entered (hidden)” plaintext or preview content. Import accepts only a regular file, rejects symlinks/directories/special files, and limits the source to 1 MiB. The textual ASCII PEM's first private-key marker must identify OpenSSH, RSA, EC, or PKCS#8 format. This is structural import validation, not proof that OpenSSH can parse or use the key. The original file is not deleted or modified.

Importing a private key does not authorize its corresponding public key on a server. Select the private key rather than the `.pub` file, supply its passphrase when encrypted, use the intended remote username, and ensure that the matching public key is already present in that account's `authorized_keys` or equivalent server-side authorization. Remxo does not upload a public key automatically and cannot infer authorization without a real authentication attempt.

Execution, tasks, Broker SCP, interactive SFTP, TUI-launched interactive SSH, and tunnels share `prepare_authentication`. For Vault keys, the Broker returns the private key through the internal authentication RPC and the caller writes a restricted temporary file for OpenSSH. The temporary-key guard lives until the operation/child finishes and removes the file on normal drop. A crash or forced termination may leave residue; deletion is not guaranteed secure erasure.

Vault password/key authentication starts ASKPASS as the current Remxo executable with OpenSSH's single prompt argument. There is no public `__askpass` CLI subcommand. `main` selects the internal helper entry when `REMXO_ASKPASS_CONFIG` is present. The helper environment contains only the config path, target alias, and optional non-secret pending-Host metadata. It asks the Broker for one typed password/passphrase and writes that value to OpenSSH's ASKPASS stdout. It refuses host-key/yes/no/fingerprint confirmation and OTP, MFA, hardware PIN, token, and unrecognized prompts. Strict `known_hosts` handling is not relaxed.

For ordinary execution, the Broker re-resolves the registered Host to choose the expected record and type instead of trusting an arbitrary caller-provided secret name. An unsaved wizard connection test uses an explicit pending-Host context, and the Broker rejects that path if the alias is already registered. The internal RPC response is a deliberate single-Secret exception to ordinary operation results, not a general Vault-dump interface or an L2 security boundary.

Secret plaintext is necessarily present in relevant process memory and, at the authentication boundary, in same-user RPC data, ASKPASS stdout, and the temporary private-key file. These paths do not put secret values in argv, helper environment variables, host previews, or metadata audit. L1 does not protect them from a malicious process running as the same OS user.

## Interactive host wizard

When connection information is missing, the CLI opens a full-screen host-add wizard instead of reporting only one missing-field error. `remxo init` must have been run first.

```console
remxo host add
remxo host add prod-01
remxo host add prod-01 --interactive
# Press a on the Hosts page of the main Remxo TUI.
remxo host edit prod-01
# Or press e to edit and t to test the saved connection in the Hosts page.
```

The wizard follows Connection → Policy → Review. It supports alias prefill, port/number validation, environment, platform, all four authentication modes, raw/approval policy, optional sudo, Telnet INSECURE acknowledgement, and a configuration preview. Vault modes add an SSH password/private-key-passphrase field rendered only as `*` masks and a visible private-key-path field. Text fields have a real cursor with insertion, left/right/Home/End navigation, Backspace/Delete, bracketed paste, and Ctrl+U/Ctrl+W/Ctrl+L editing. Matched single or double quotes around a pasted private-key path are removed on import; they are not removed from arbitrary secret input. Focus is distinguished by color and status is separate; narrow terminals hide the side panel. `--no-color` or `NO_COLOR` disables that coloring. Main TUI and wizard labels are English or Simplified Chinese according to `settings.language`.

Keyboard controls:

```text
↑ / ↓          Move field focus
← / →          Move the cursor, or change a selected option
Home / End     Move to the start/end of a text field
Paste          Insert at the cursor (bracketed paste)
Backspace      Delete before the cursor
Delete         Delete at the cursor
Ctrl+U/W/L     Delete to start / previous word / clear the field
Enter          Advance, test, save, or save-and-test
Tab / BackTab  Move field focus
Esc            Cancel without saving the Host
```

Credential import is deliberately **not** an all-or-nothing Host transaction. For host creation, Test and Save first import the selected SSH password/passphrase and/or private key into the encrypted Vault. A failed test or Esc does not save the Host, but credentials already imported remain encrypted in Vault. Save writes the Host only after its SSH credential import succeeds; a direct Save does not require a prior successful test. Optional sudo configuration happens separately after the Host is saved, and sudo failure does not roll back that Host. No secret value enters the preview, Host object, argv, or metadata audit.

For `host edit`, the alias is fixed and a stale expected-Host check prevents an old form from silently overwriting a newer edit. Nonsecret edits retain the current credential records without asking for them again. An explicit credential or authentication-mode replacement uses a versioned credential stem so a failed Host save does not replace the old Host's active secret before the configuration reference changes. Old records remain encrypted; there is no cross-config/Vault rollback or automatic secure deletion. Save & test writes the edited Host first and tests it through the registered-Host authentication path—never a pending Host for an already registered alias. A failed test does not roll back the saved edit.

Traditional noninteractive calls with complete `--hostname`/`--ssh-alias` arguments remain supported. The wizard is incompatible with `--json` and never starts without a TTY. Its connection probe preserves strict host-key checking and uses the authentication behavior above; it does not replace host authorization review or production inspection.

The UI layout draws on Charmbracelet/gum's stepped inputs, lazygit's keyboard panel/status hierarchy, and Rich's border and color-adaptation ideas; Remxo itself implements the core form, policy, validation, and Vault flows.

## Policy and approval

A host supports `raw_mode = "allow" | "read-only" | "deny"` and `approval = "never" | "writes" | "always"`. `read-only` permits only built-in profiles; `deny` prohibits raw execution. Heuristics only choose approval convenience and are **not a command-security sandbox**. Once raw execution is allowed, the remote account's own permissions apply.

When approval is required, execution returns `approval_required` and an `approval_id`; an AI must stop. After human review:

```console
remxo approval list
remxo approval approve <approval-id>
# Before expiry, rerun exactly the same operation. Connection settings,
# command/parameters, or output-limit changes produce a different digest.
```

Same-user approval is an L1 convenience; a malicious same-user Agent can bypass it.

## sudo

```console
remxo unlock
remxo vault set-sudo prod-01
remxo --sudo prod-01 systemctl restart nginx
```

sudo uses an independent `sudo-password` Vault record, never the SSH password record. When sudo configuration is requested during a new wizard/CLI registration, `sudo_credential` is set to `<alias>:sudo`; legacy Hosts and other Hosts without that field retain the bare `<alias>` sudo-record lookup. The exact sudo password is sent through SSH stdin to remote `sudo -S`, not local/remote argv, and exact echoes are removed from output. `requiretty`, remote sudoers, PAM, and account configuration can still produce `sudo_not_permitted` or a remote failure. Prefer precise sudoers rules and never put passwords in scripts, logs, or AI context.

## Encrypted backup

```console
remxo backup create ./remxo.rxb
remxo backup verify ./remxo.rxb
# Verify restore in a fresh --config data directory; existing files are refused by default.
remxo --config /new-dir/config.toml backup restore ./remxo.rxb
```

Backup and master prompts display only `*` masks and cannot be supplied as CLI secret arguments. After restore, explicitly `unlock` with the **original Vault master password**; the backup password protects only the outer backup. Imported SSH passwords, passphrases, private keys, and sudo credentials remain inside the nested encrypted Vault backup. External Agent secrets, platform biometrics, and external private/hardware keys are not exported into the backup.

## File transfer, tunnels, and tasks

```console
remxo put ./app.tar.gz prod-01:/tmp/app.tar.gz
remxo get prod-01:/tmp/app.tar.gz ./app.tar.gz
remxo --overwrite put ./app.tar.gz prod-01:/tmp/app.tar.gz
remxo sftp prod-01

remxo tunnel start prod-01 --local 15432:127.0.0.1:5432
remxo tunnel list
remxo tunnel stop <tunnel-id>

remxo task start prod-01 -- ./deploy.sh
remxo task list
remxo task logs <task-id>
remxo task stop <task-id>
```

SCP uses `scp -s` to force SFTP mode and avoid legacy SCP remote-shell path expansion; an old client without that support fails explicitly. Transfers and tunnels pass through Broker host policy and approval. Tunnels bind to `127.0.0.1` by default; public binding requires `--yes`, and dynamic forwarding requires approval. Vault authentication also covers SFTP and tunnel children through the shared preparation path.

Tasks persist only for the current Broker process. Logs are bounded and retain processed output after completion. Killing local SSH does not prove the remote process stopped, state may be unknown after disconnection, and Remxo never automatically retries writes.

## JSON and errors

Remote execution returns one JSON document containing `schema_version`, `request_id`, `host`, `operation`, `decision`, `status`, `remote_exit_code`, `stdout`, `stderr`, `truncated`, `duration_ms`, and `error`, without mixed progress text. Common errors include `vault_locked`, `authentication_failed`, `agent_identity_unavailable`, `agent_unavailable`, `host_not_found`, `host_not_allowed`, `policy_denied`, `approval_required`, `host_key_failed`, `timeout`, `output_limit`, `unsupported_shell`, `sudo_password_not_configured`, and `insecure_transport`.

Remote output is untrusted data. Redaction and control-character handling reduce accidental disclosure and terminal effects, but cannot detect every secret or remove prompt-injection meaning.

## Current limitations

- L1 only: same-user processes, root, and local-machine compromise are outside its protection. The single-Secret authentication RPC and plaintext handoff points are not same-user isolation. See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- Telnet's data model, INSECURE marking, and unacknowledged rejection exist, but network automation is not implemented. Vault encryption does not encrypt a Telnet network connection.
- Only POSIX noninteractive command composition is supported. PowerShell, CMD, device/custom shells return explicit unsupported errors rather than receiving POSIX quoting.
- The TUI supports monitoring, search, host add/edit/connection-test, lock/unlock, and interactive SSH; host remove wizards and TUI approval/backup operations remain future work. Settings supports language, timeout, and max-output changes with atomic configuration saves.
- Tasks do not resume after Broker restart. Remote-detached execution, connection reuse, and universal SSH-server compatibility are not implemented or proven.
- Native Windows permission hardening and real Vault password/private-key authentication have not been verified. Unix temporary-file `0600` behavior must not be presented as validated Windows ACL behavior or cross-platform authentication support.
- Biometric unlock, Linux Secret Service, TPM, an L2 separate-OS-user Broker, and L3 short-lived certificates/central authorization are not implemented.

Architecture is documented in [ARCHITECTURE.md](ARCHITECTURE.md), security verification in [TESTING.md](TESTING.md), and AI development/usage rules in [AGENTS.md](AGENTS.md).
