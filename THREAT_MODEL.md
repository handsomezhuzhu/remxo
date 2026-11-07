# Remxo Threat Model (L1)

## Assets and trust boundaries

Assets include host inventory and connection metadata, Vault credentials, wrapped/unwrapped DEK, KEK/master and backup passwords, external Agent signing access, sudo credentials, approval intent, audit metadata, task/tunnel state and remote output integrity.

The primary boundary is between an AI caller/local CLI and the same-user local Broker; another boundary exists between Remxo/OpenSSH and remote output. L1 is defense against accidents, not isolation from malicious code running as the same user. A future L2 boundary is a distinct OS-user Broker with restricted IPC and independent human approval. L3 adds remote/central authorization and short-lived identities.

## Baseline assumptions

- The user intentionally unlocks Vault and approves dangerous operations.
- System OpenSSH and its host-key policy are trusted; unknown keys are not auto-accepted.
- Remote software is not assumed safe just because Remxo quotes its command.
- Protected files are created with private permissions and sensitive writes are atomic where practical.
- root, kernel and remote account compromise are outside the model. A malicious same-OS-user process can bypass virtually all L1 controls.

## Threats and controls

| Threat | Control in this version | Residual risk / required behavior |
| --- | --- | --- |
| Secrets enter AI context | Broker returns per-operation results only; Vault never returned wholesale; no secret CLI flags; output redaction; exact sudo echo stripping | Redaction is heuristic. Arbitrary remote secrets and memory inspection are not eliminated. AI must not read Vault, `~/.ssh`, Agent sockets or request passwords. |
| Unauthorized high-risk command | Per-host raw modes, profiles, `approval=never/writes/always`, bounded approvals, sudo approval | Raw allow confers remote account permissions. Read detection is intentionally conservative and not a sandbox. Same-user approval is L1 convenience. |
| Local command injection | `std::process::Command`/tokio argv; no local `sh -c`; connection fields validated | Untrusted local executable paths and compromised OpenSSH are outside the boundary. Test fakes must be isolated. |
| Remote raw-command injection | Multi-argument POSIX commands use single-argument quoting; single raw string is explicitly a shell script | Remote shell still interprets scripts/operators. Metacharacters in a single raw string are intended behavior, not escaped safety. |
| `--cwd` injection | `cd` uses POSIX single-quote escaping, never concatenates unquoted path | Only POSIX is supported. Other shell models fail unsupported rather than using wrong escaping. |
| Profile/template injection | Typed names, service regex, integer range 1–1000, duplicate/unknown argument rejection, shell quoting | Profiles are a fixed small allowlist, not arbitrary safe templating. |
| Unregistered IP bypass | Alias → number → registered IP resolution; ad-hoc disabled unless `allow_ad_hoc=true`; ad-hoc still uses policy/approval | Explicitly enabling ad-hoc widens the inventory boundary. Numeric aliases and duplicate numbers are rejected. |
| Approval forgery/modification/replay | In-memory random ID, SHA-256 digest of resolved host config, operation, script/paths and relevant limits, 5-minute expiry, explicit approval bit and single consumption | Same user can alter Broker memory or approve directly. L2 requires independent human approval; IDs are not portable authorization tokens. |
| Host-key disable | No `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `ForwardAgent=yes`; failures map to `host_key_failed` | Admins/user OpenSSH config may still weaken policy; a human must register unknown hosts. |
| Audit/error leakage | JSONL records metadata and request digests, no default full stdout/stderr; transferable content and remote errors are sanitized | Paths/metadata may be sensitive; same-user audit tampering is out of L1. Redaction cannot guarantee secret detection. |
| Untrusted output control/prompt effects | Raw-byte cap, sanitization before final truncation, UTF-8-safe limit, terminal control escapes | Output remains untrusted natural language and can instruct an AI; control stripping is not prompt-injection prevention. |
| Unsafe transfer overwrite/path expansion | Broker policy and digest; default local overwrite refusal; default remote existence preflight; `--overwrite`/config policy; `scp -s` forces SFTP mode | Race between preflight and write is possible; older scp without `-s` fails. No claim of transactional remote directory sync. |
| Tunnel LAN exposure | Explicit loopback added by default, non-loopback requires `--yes`, dynamic needs approval, `ExitOnForwardFailure=yes`, local process list/stop | Remote `AllowTcpForwarding`, firewall and DNS affect exposure. Lifecycle belongs to running Broker; public binding needs operator review. |
| Duplicate long-running/write execution | No automatic retry; task IDs, timeouts, cancellation and state; local disconnect states remain uncertain | A killed SSH process doesn't prove remote process death. Restart loses task records; detached systemd/tmux not implemented. Verify remotely before retrying. |
| sudo password exposure | Independent typed Vault credential, no argv, secure stdin, no default SSH-password reuse, remove exact password from stdout/stderr | sudo/PAM may fail (`requiretty`); memory-zeroization isn't absolute; AI must not guess or brute force passwords. sudoers least privilege preferred. |
| Telnet mistaken for secure | Model and capabilities `encrypted=false`, `insecure_acknowledged` required, INSECURE UI text, dedicated error, audit transport where applicable | Telnet network automation isn't implemented. Future implementation must treat credentials/commands/output as plaintext. |
| Backup includes runtime/platform state | Payload only config and encrypted Vault envelope; independent backup password; exclude DEK plaintext, unlock state, sockets, approvals, sessions, caches/logs | Vault master password remains required after restore. External Agent/biometric/private hardware keys are not backed up. Atomicity is per-file, not a two-file transaction. |
| Weak permissions/torn writes | Private directories/temp files, Unix 0600 private files and permission check, atomic replace, config/restore pre-change backups | Windows ACL hardening is best effort in this version; multi-file crashes and same-user tampering need external protection. |

## Approved future controls

L2: dedicated OS user Broker and restricted socket, isolated human approval; L3: SSH CA/short-lived certificates, separate identities, remote enforcement and centralized audit. Native Hello/Touch ID must release keys through TPM/Keychain cryptographic operations, not a boolean check followed by reading a plaintext DEK.

## Security invariants for tests and reviews

No real production credentials or servers in tests; no fabricated build/audited-security result; no automatic writes retry; no secrets in logs/argv; stdout/stderr remain separate; unknown hosts fail closed; remote output is untrusted; explicit capabilities are returned for unsupported shells/protocols.
