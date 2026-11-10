use crate::config::{Config, Host, resolve_target};
use crate::error::{AppError, ErrorCode, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const KEYSCAN_TIMEOUT_SECONDS: &str = "10";
const TRUST_CONFIRMATION: &str = "TRUST";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostKeyFingerprint {
    pub key_type: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FetchedHostKey {
    pub key_type: String,
    pub protocol_key_type: String,
    pub key_blob: String,
    pub fingerprint: String,
    pub line: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostKeyStatus {
    pub host: String,
    pub address: String,
    pub port: u16,
    pub known: bool,
    pub fingerprints: Vec<HostKeyFingerprint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostKeyTrustResult {
    pub host: String,
    pub address: String,
    pub port: u16,
    pub added: Vec<HostKeyFingerprint>,
    pub already_known: Vec<HostKeyFingerprint>,
    pub known_hosts: PathBuf,
}

fn keyscan_binary() -> PathBuf {
    std::env::var_os("REMXO_SSH_KEYSCAN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh-keyscan"))
}

fn keygen_binary() -> PathBuf {
    std::env::var_os("REMXO_SSH_KEYGEN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh-keygen"))
}

fn ssh_binary() -> PathBuf {
    std::env::var_os("REMXO_SSH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ssh"))
}

pub fn known_hosts_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| {
        AppError::internal("cannot determine the user home directory for OpenSSH known_hosts")
    })?;
    Ok(home.join(".ssh").join("known_hosts"))
}

fn known_hosts_name(address: &str, port: u16) -> String {
    if port == 22 {
        address.to_string()
    } else {
        format!("[{address}]:{port}")
    }
}

fn require_ssh(host: &Host) -> Result<()> {
    if host.transport != crate::config::TransportKind::Ssh {
        return Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "host key management requires an SSH host",
        ));
    }
    Ok(())
}

/// Resolve the address and port OpenSSH will use, including `ssh -G` for an
/// OpenSSH Host alias. This never authenticates and never reads secrets.
pub fn endpoint(host: &Host) -> Result<(String, u16)> {
    require_ssh(host)?;
    if let Some(alias) = host.ssh_alias.as_deref() {
        let output = Command::new(ssh_binary())
            .arg("-G")
            .arg(alias)
            .output()
            .map_err(|error| AppError::io("resolve OpenSSH host alias", error))?;
        if !output.status.success() {
            let detail = crate::redact::external_error_detail(&output.stderr);
            return Err(AppError::new(
                ErrorCode::ConnectionFailed,
                format!("cannot resolve OpenSSH alias '{alias}': {}", detail.trim()),
            ));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut hostname = None;
        let mut port = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("hostname ") {
                hostname = Some(value.trim().to_string());
            }
            if let Some(value) = line.strip_prefix("port ") {
                port = value.trim().parse::<u16>().ok();
            }
        }
        let hostname = hostname.filter(|value| !value.is_empty()).ok_or_else(|| {
            AppError::new(
                ErrorCode::InvalidConfig,
                format!("OpenSSH alias '{alias}' did not resolve to a hostname"),
            )
        })?;
        return Ok((hostname, port.unwrap_or(22)));
    }
    let hostname = host
        .hostname
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::InvalidConfig,
                "an SSH host requires hostname or ssh_alias before host key operations",
            )
        })?
        .to_string();
    Ok((hostname, host.port))
}

fn display_key_type(key_type: &str) -> String {
    match key_type {
        "ssh-ed25519" => "ED25519".to_string(),
        "ssh-rsa" => "RSA".to_string(),
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            "ECDSA".to_string()
        }
        other => other.to_string(),
    }
}

fn fingerprint_from_public_key_line(line: &str) -> Result<HostKeyFingerprint> {
    let mut parts = line.split_whitespace();
    let _name = parts
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no name"))?;
    let key_type = parts
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no key type"))?;
    let blob = parts
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no key blob"))?;
    let bytes = BASE64
        .decode(blob)
        .map_err(|_| AppError::invalid_argument("host key blob is not valid base64"))?;
    let digest = Sha256::digest(&bytes);
    let fingerprint = format!("SHA256:{}", BASE64.encode(digest).trim_end_matches('='));
    Ok(HostKeyFingerprint {
        key_type: display_key_type(key_type),
        fingerprint,
    })
}

fn parse_host_key_lines(output: &str) -> Result<Vec<FetchedHostKey>> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let identity = identity_from_public_key_line(line)?;
            Ok(FetchedHostKey {
                key_type: identity.fingerprint.key_type,
                protocol_key_type: identity.key_type,
                key_blob: identity.blob,
                fingerprint: identity.fingerprint.fingerprint,
                line: line.to_string(),
            })
        })
        .collect()
}

/// Fetch the server host keys without trusting them.
pub fn fetch(host: &Host) -> Result<Vec<FetchedHostKey>> {
    fetch_with_retries(host, 1)
}

/// Fetch host keys with a bounded retry count for transient network failures.
pub fn fetch_with_retries(host: &Host, retries: u32) -> Result<Vec<FetchedHostKey>> {
    let attempts = retries.max(1);
    let mut last_error = None;
    for attempt in 1..=attempts {
        match fetch_once(host) {
            Ok(keys) => return Ok(keys),
            Err(error) => {
                last_error = Some(error);
            }
        }
        if attempt < attempts {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AppError::new(
            ErrorCode::ConnectionFailed,
            "ssh-keyscan returned no host key",
        )
    }))
}

pub(crate) fn fetch_once(host: &Host) -> Result<Vec<FetchedHostKey>> {
    let (address, port) = endpoint(host)?;
    let output = Command::new(keyscan_binary())
        .arg("-p")
        .arg(port.to_string())
        .arg("-T")
        .arg(KEYSCAN_TIMEOUT_SECONDS)
        .arg(&address)
        .output()
        .map_err(|error| AppError::io("start ssh-keyscan", error))?;
    if !output.status.success() && output.stdout.is_empty() {
        let detail = crate::redact::external_error_detail(&output.stderr);
        return Err(AppError::new(
            ErrorCode::ConnectionFailed,
            format!("ssh-keyscan could not fetch a host key: {detail}"),
        ));
    }
    let keys = parse_host_key_lines(&String::from_utf8_lossy(&output.stdout))?;
    if keys.is_empty() {
        return Err(AppError::new(
            ErrorCode::ConnectionFailed,
            "ssh-keyscan returned no host key",
        ));
    }
    Ok(keys)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostKeyIdentity {
    key_type: String,
    blob: String,
    fingerprint: HostKeyFingerprint,
}

fn identity_from_public_key_line(line: &str) -> Result<HostKeyIdentity> {
    let mut fields = line.split_whitespace();
    let _name = fields
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no name"))?;
    let key_type = fields
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no key type"))?;
    let blob = fields
        .next()
        .ok_or_else(|| AppError::invalid_argument("host key line has no key blob"))?;
    BASE64
        .decode(blob)
        .map_err(|_| AppError::invalid_argument("host key blob is not valid base64"))?;
    let fingerprint = fingerprint_from_public_key_line(line)?;
    Ok(HostKeyIdentity {
        key_type: key_type.to_string(),
        blob: blob.to_string(),
        fingerprint,
    })
}

fn known_host_identities(host: &Host) -> Result<Vec<HostKeyIdentity>> {
    let (address, port) = endpoint(host)?;
    let name = known_hosts_name(&address, port);
    let output = Command::new(keygen_binary())
        .arg("-F")
        .arg(&name)
        .arg("-f")
        .arg(known_hosts_path()?)
        .output()
        .map_err(|error| AppError::io("inspect OpenSSH known_hosts", error))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let key_lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("Host "))
        .collect::<Vec<_>>();
    key_lines
        .into_iter()
        .map(identity_from_public_key_line)
        .collect()
}

fn known_host_keys(host: &Host) -> Result<Vec<HostKeyFingerprint>> {
    Ok(known_host_identities(host)?
        .into_iter()
        .map(|identity| identity.fingerprint)
        .collect())
}

pub fn status(config: &Config, target: &str) -> Result<HostKeyStatus> {
    let resolved = resolve_target(config, target)?;
    require_ssh(&resolved.host)?;
    let (address, port) = endpoint(&resolved.host)?;
    let fingerprints = known_host_keys(&resolved.host)?;
    Ok(HostKeyStatus {
        host: resolved.alias,
        address,
        port,
        known: !fingerprints.is_empty(),
        fingerprints,
    })
}

pub fn list(config: &Config) -> Result<Vec<HostKeyStatus>> {
    let mut statuses = Vec::new();
    for (alias, host) in &config.hosts {
        if host.transport != crate::config::TransportKind::Ssh {
            continue;
        }
        let (address, port) = endpoint(host)?;
        let fingerprints = known_host_keys(host)?;
        statuses.push(HostKeyStatus {
            host: alias.clone(),
            address,
            port,
            known: !fingerprints.is_empty(),
            fingerprints,
        });
    }
    Ok(statuses)
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("SHA256:") {
        return Err(AppError::invalid_argument(
            "fingerprint must be an OpenSSH SHA256 fingerprint, for example SHA256:...",
        ));
    }
    Ok(trimmed.to_string())
}

fn select_fetched_keys(
    fetched: &[FetchedHostKey],
    fingerprint: Option<&str>,
) -> Result<Vec<FetchedHostKey>> {
    match fingerprint {
        Some(value) => {
            let wanted = normalize_fingerprint(value)?;
            let selected = fetched
                .iter()
                .filter(|key| key.fingerprint == wanted)
                .cloned()
                .collect::<Vec<_>>();
            if selected.is_empty() {
                let available = fetched
                    .iter()
                    .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(AppError::new(
                    ErrorCode::InvalidArgument,
                    format!("fingerprint does not match any fetched host key: {available}"),
                ));
            }
            Ok(selected)
        }
        None => Ok(fetched.to_vec()),
    }
}

fn append_known_hosts_at(path: &std::path::Path, lines: &[String]) -> Result<PathBuf> {
    let path = path.to_path_buf();
    if let Some(parent) = path.parent() {
        crate::store::ensure_private_dir(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| AppError::io("open OpenSSH known_hosts", error))?;
    for line in lines {
        writeln!(file, "{line}").map_err(|error| AppError::io("append host key", error))?;
    }
    file.sync_all()
        .map_err(|error| AppError::io("sync OpenSSH known_hosts", error))?;
    crate::store::restrict_path(&path)?;
    Ok(path)
}

/// Trust only keys from the same fetch that the user inspected. If a later fetch
/// differs, confirmation must start again instead of trusting an unseen key.
pub fn trust_confirmed(
    alias: &str,
    host: &Host,
    confirmed: &[FetchedHostKey],
    fingerprint: Option<&str>,
    retries: u32,
) -> Result<HostKeyTrustResult> {
    let (address, port) = endpoint(host)?;
    if confirmed.is_empty() {
        return Err(AppError::invalid_argument(
            "no fetched host keys were confirmed; fetch and verify them before trusting",
        ));
    }
    let name = known_hosts_name(&address, port);
    for key in confirmed {
        let key_name = key.line.split_whitespace().next().unwrap_or_default();
        if key_name != name {
            return Err(AppError::new(
                ErrorCode::HostKeyFailed,
                "the confirmed host keys belong to a different address or port; fetch and verify them again",
            ));
        }
    }
    let fetched = fetch_with_retries(host, retries)?;
    ensure_same_confirmed_keys(confirmed, &fetched)?;
    let selected = select_fetched_keys(confirmed, fingerprint)?;
    let known = known_host_identities(host)?;
    persist_confirmed_keys(alias, address, port, &selected, &known)
}

fn ensure_same_confirmed_keys(
    confirmed: &[FetchedHostKey],
    fetched: &[FetchedHostKey],
) -> Result<()> {
    if fetched != confirmed {
        return Err(AppError::new(
            ErrorCode::HostKeyFailed,
            "the server host keys changed after confirmation; fetch and verify them again before trusting",
        ));
    }
    Ok(())
}

fn persist_confirmed_keys(
    alias: &str,
    address: String,
    port: u16,
    selected: &[FetchedHostKey],
    known: &[HostKeyIdentity],
) -> Result<HostKeyTrustResult> {
    let known_hosts = known_hosts_path()?;
    let (added, already_known) = append_missing_at(&known_hosts, selected, known)?;
    Ok(HostKeyTrustResult {
        host: alias.to_string(),
        address,
        port,
        added,
        already_known,
        known_hosts,
    })
}

fn append_missing_at(
    known_hosts: &std::path::Path,
    selected: &[FetchedHostKey],
    known: &[HostKeyIdentity],
) -> Result<(Vec<HostKeyFingerprint>, Vec<HostKeyFingerprint>)> {
    let missing = selected
        .iter()
        .filter(|key| {
            !known.iter().any(|existing| {
                existing.key_type == key.protocol_key_type && existing.blob == key.key_blob
            })
        })
        .collect::<Vec<_>>();
    let added = if missing.is_empty() {
        Vec::new()
    } else {
        let lines = missing
            .iter()
            .map(|key| key.line.clone())
            .collect::<Vec<_>>();
        append_known_hosts_at(known_hosts, &lines)?;
        missing
            .iter()
            .map(|key| HostKeyFingerprint {
                key_type: key.key_type.clone(),
                fingerprint: key.fingerprint.clone(),
            })
            .collect()
    };
    let already_known = selected
        .iter()
        .filter(|key| {
            known.iter().any(|existing| {
                existing.key_type == key.protocol_key_type && existing.blob == key.key_blob
            })
        })
        .map(|key| HostKeyFingerprint {
            key_type: key.key_type.clone(),
            fingerprint: key.fingerprint.clone(),
        })
        .collect();
    Ok((added, already_known))
}

/// Fetch and trust in one bounded step. This is for non-interactive callers
/// with a verified fingerprint; interactive TUI confirmation must pass the
/// displayed keys to `trust_confirmed` instead.
pub fn trust_with_retries(
    alias: &str,
    host: &Host,
    fingerprint: Option<&str>,
    retries: u32,
) -> Result<HostKeyTrustResult> {
    let keys = fetch_with_retries(host, retries)?;
    trust_confirmed(alias, host, &keys, fingerprint, retries)
}

pub fn remove(host: &Host) -> Result<()> {
    let (address, port) = endpoint(host)?;
    let name = known_hosts_name(&address, port);
    let output = Command::new(keygen_binary())
        .arg("-R")
        .arg(&name)
        .output()
        .map_err(|error| AppError::io("remove OpenSSH host key", error))?;
    if !output.status.success() {
        let detail = crate::redact::external_error_detail(&output.stderr);
        return Err(AppError::new(
            ErrorCode::IoError,
            format!("ssh-keygen could not remove the host key: {detail}"),
        ));
    }
    Ok(())
}

/// Prompt for the explicit trust confirmation. This is intentionally not a
/// password prompt and never accepts an empty response.
pub fn confirm_trust_interactively(keys: &[FetchedHostKey]) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(AppError::invalid_argument(
            "host key trust without --fingerprint requires an interactive terminal",
        ));
    }
    println!("Server host key fingerprints:");
    for key in keys {
        println!("  {} {}", key.key_type, key.fingerprint);
    }
    println!("Verify these fingerprints out-of-band before continuing.");
    print!("Type {TRUST_CONFIRMATION} to add them to known_hosts, anything else to cancel: ");
    std::io::stdout()
        .flush()
        .map_err(|error| AppError::io("flush host key confirmation", error))?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|error| AppError::io("read host key confirmation", error))?;
    if input.trim() != TRUST_CONFIRMATION {
        return Err(AppError::invalid_argument("host key trust cancelled"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Host;

    fn host() -> Host {
        Host {
            hostname: Some("192.0.2.10".into()),
            port: 2222,
            ..Host::default()
        }
    }

    #[test]
    fn known_hosts_name_uses_brackets_for_nonstandard_ports() {
        assert_eq!(known_hosts_name("192.0.2.10", 22), "192.0.2.10");
        assert_eq!(known_hosts_name("192.0.2.10", 2006), "[192.0.2.10]:2006");
    }

    #[test]
    fn endpoint_uses_direct_hostname_and_port() {
        let (address, port) = endpoint(&host()).unwrap_or_else(|error| panic!("endpoint: {error}"));
        assert_eq!(address, "192.0.2.10");
        assert_eq!(port, 2222);
    }

    #[test]
    fn fingerprint_matches_openssh_sha256_format() {
        let line = "[192.0.2.10]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP";
        let fingerprint =
            fingerprint_from_public_key_line(line).unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(fingerprint.key_type, "ED25519");
        assert_eq!(
            fingerprint.fingerprint,
            "SHA256:Psw7YO69YO/A/02DddnLiUe4p/crHTsUxbWMpGgf0pQ"
        );
    }

    #[test]
    fn parse_host_key_lines_ignores_comments_and_empty_lines() {
        let output = "# comment\n\n[192.0.2.10]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP\n";
        let keys = parse_host_key_lines(output).unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ED25519");
    }

    #[test]
    fn changed_refetch_is_rejected_before_known_hosts_is_touched() {
        let confirmed =
            test_keys("AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP");
        let changed =
            test_keys("AAAAC3NzaC1lZDI1NTE5AAAAIKiL6VQDMroBdzGVw3hYYR91ODaGIT6prxY5CJh99aMY");
        assert_ne!(confirmed, changed);
        let error = ensure_same_confirmed_keys(&confirmed, &changed).unwrap_err();
        assert_eq!(error.code, ErrorCode::HostKeyFailed);
        assert!(
            error
                .detail()
                .message
                .contains("changed after confirmation")
        );
    }

    #[test]
    fn partially_known_selection_appends_only_missing_keys() {
        let confirmed =
            test_keys("AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP");
        let additional =
            test_keys("AAAAC3NzaC1lZDI1NTE5AAAAIKiL6VQDMroBdzGVw3hYYR91ODaGIT6prxY5CJh99aMY");
        let known = vec![
            identity_from_public_key_line(&confirmed[0].line)
                .unwrap_or_else(|error| panic!("identity: {error}")),
        ];
        let home = tempfile::tempdir().unwrap_or_else(|error| panic!("home: {error}"));
        let selected = [confirmed[0].clone(), additional[0].clone()];
        let (added, already_known) =
            append_missing_at(&home.path().join("known_hosts"), &selected, &known)
                .unwrap_or_else(|error| panic!("trust: {error}"));
        assert_eq!(
            added,
            vec![HostKeyFingerprint {
                key_type: additional[0].key_type.clone(),
                fingerprint: additional[0].fingerprint.clone(),
            }]
        );
        assert_eq!(
            already_known,
            known
                .iter()
                .map(|entry| entry.fingerprint.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("known_hosts")).ok(),
            Some(format!("{}\n", additional[0].line))
        );
    }

    fn test_keys(blob: &str) -> Vec<FetchedHostKey> {
        let line = format!("[192.0.2.10]:2222 ssh-ed25519 {blob}");
        parse_host_key_lines(&line).unwrap_or_else(|error| panic!("parse: {error}"))
    }

    #[test]
    fn fingerprint_selection_rejects_unknown_fingerprints() {
        let line = "[192.0.2.10]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP";
        let keys = parse_host_key_lines(line).unwrap_or_else(|error| panic!("parse: {error}"));
        let error = select_fetched_keys(&keys, Some("SHA256:wrong")).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}
