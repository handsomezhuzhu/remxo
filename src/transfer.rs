use crate::config::{AuthMode, Host};
use crate::error::{AppError, ErrorCode, Result};
use crate::output::process;
use crate::shell::posix_quote;
use crate::transport::openssh::{OpensshTransport, prepare_authentication};
use crate::transport::{
    AuthenticationContext, ExecutionRequest, ProcessTermination, Transport as _, run_process,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOutcome {
    pub bytes: u64,
    pub local: PathBuf,
    pub remote: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePath {
    pub target: String,
    pub path: String,
}

pub fn parse_remote_path(input: &str) -> Result<RemotePath> {
    let (target, path) = if let Some(rest) = input.strip_prefix('[') {
        let (target, suffix) = rest
            .split_once("]:")
            .ok_or_else(|| AppError::invalid_argument("expected [IPv6]:/remote/path"))?;
        (target, suffix)
    } else {
        input
            .split_once(':')
            .ok_or_else(|| AppError::invalid_argument("expected target:/remote/path"))?
    };
    if target.is_empty() || path.is_empty() || path.contains(['\0', '\n', '\r']) {
        return Err(AppError::invalid_argument("invalid remote path"));
    }
    Ok(RemotePath {
        target: target.to_string(),
        path: path.to_string(),
    })
}

fn remote_scp_path(host: &Host, path: &str) -> String {
    format!("{}:{path}", host.destination())
}

fn scp_arguments(host: &Host, timeout: Duration) -> Result<Vec<String>> {
    host.validate("transfer")?;
    let mut args = vec![
        "-o".into(),
        format!("ConnectTimeout={}", timeout.as_secs().max(1)),
    ];
    if host.ssh_alias.is_none() {
        args.extend(["-P".into(), host.port.to_string()]);
    }
    Ok(args)
}

pub async fn put(
    host: &Host,
    local: &Path,
    remote: &str,
    overwrite: bool,
    timeout: Duration,
    max_output: usize,
    auth_context: Option<&AuthenticationContext>,
) -> Result<TransferOutcome> {
    host.validate("transfer")?;
    let bytes = std::fs::metadata(local)
        .map_err(|e| AppError::io("inspect upload", e))?
        .len();
    if !overwrite {
        let script = format!("test ! -e {}", posix_quote(remote));
        let transport = OpensshTransport::default();
        let outcome = transport
            .exec(ExecutionRequest {
                host: host.clone(),
                script,
                timeout,
                max_output,
                sudo_password: None,
                auth_context: auth_context.cloned(),
            })
            .await?;
        if outcome.exit_code == Some(1) {
            return Err(AppError::new(
                ErrorCode::PolicyDenied,
                "remote destination exists; pass --overwrite to permit replacement",
            ));
        }
        if outcome.exit_code != Some(0) {
            return Err(AppError::new(
                ErrorCode::ConnectionFailed,
                "could not verify remote destination; upload was not attempted",
            ));
        }
    }
    scp(
        host,
        local,
        &remote_scp_path(host, remote),
        true,
        timeout,
        max_output,
        auth_context,
    )
    .await?;
    Ok(TransferOutcome {
        bytes,
        local: local.to_path_buf(),
        remote: remote.to_string(),
    })
}

pub async fn get(
    host: &Host,
    remote: &str,
    local: &Path,
    overwrite: bool,
    timeout: Duration,
    max_output: usize,
    auth_context: Option<&AuthenticationContext>,
) -> Result<TransferOutcome> {
    if local.exists() && !overwrite {
        return Err(AppError::new(
            ErrorCode::PolicyDenied,
            "local destination exists; pass --overwrite to permit replacement",
        ));
    }
    scp(
        host,
        local,
        &remote_scp_path(host, remote),
        false,
        timeout,
        max_output,
        auth_context,
    )
    .await?;
    let bytes = std::fs::metadata(local)
        .map_err(|e| AppError::io("inspect downloaded file", e))?
        .len();
    Ok(TransferOutcome {
        bytes,
        local: local.to_path_buf(),
        remote: remote.to_string(),
    })
}

async fn scp(
    host: &Host,
    local: &Path,
    remote: &str,
    upload: bool,
    timeout: Duration,
    max_output: usize,
    auth_context: Option<&AuthenticationContext>,
) -> Result<()> {
    let authentication = prepare_authentication(host, auth_context, false).await?;
    let binary = std::env::var_os("REMXO_SCP").unwrap_or_else(|| "scp".into());
    let mut command = Command::new(binary);
    authentication.apply(&mut command);
    command.args(scp_arguments(host, timeout)?);
    command.arg("-s").arg("--");
    if upload {
        command.arg(local).arg(remote);
    } else {
        command.arg(remote).arg(local);
    }
    let raw = run_process(
        &mut command,
        timeout,
        max_output.saturating_mul(4),
        None,
        None,
    )
    .await?;
    if raw.termination == ProcessTermination::TimedOut {
        return Err(AppError::new(
            ErrorCode::Timeout,
            "file transfer timed out; no automatic retry was attempted",
        ));
    }
    if raw.termination == ProcessTermination::Cancelled {
        return Err(AppError::new(
            ErrorCode::ConnectionFailed,
            "file transfer was cancelled",
        ));
    }
    if raw.exit_code != Some(0) {
        let stderr = process(&raw.stderr, max_output, raw.stderr_truncated).text;
        return Err(AppError::new(
            ErrorCode::ConnectionFailed,
            format!("scp failed: {}", stderr.trim()),
        ));
    }
    Ok(())
}

fn interactive_sftp_arguments(host: &Host) -> Result<Vec<String>> {
    host.validate("sftp")?;
    if host.transport != crate::config::TransportKind::Ssh {
        return Err(AppError::invalid_argument("SFTP requires an SSH host"));
    }
    if host.auth == AuthMode::ExternalAgent && !crate::transport::check_agent_available(host) {
        return Err(AppError::new(
            ErrorCode::AgentUnavailable,
            "external SSH agent is unavailable",
        ));
    }
    let mut arguments = vec!["-o".into(), "ConnectTimeout=30".into()];
    if host.ssh_alias.is_none() {
        arguments.extend(["-P".into(), host.port.to_string()]);
    }
    Ok(arguments)
}

pub async fn sftp(host: &Host, auth_context: Option<&AuthenticationContext>) -> Result<i32> {
    let authentication = prepare_authentication(host, auth_context, true).await?;
    let binary = std::env::var_os("REMXO_SFTP").unwrap_or_else(|| "sftp".into());
    let mut command = std::process::Command::new(binary);
    authentication.apply_std(&mut command);
    command.args(interactive_sftp_arguments(host)?);
    command.arg("--").arg(host.destination());
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| AppError::io("start interactive sftp", e))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sftp_arguments_do_not_reuse_scp_batch_flags() {
        let host = Host {
            hostname: Some("192.0.2.1".into()),
            port: 2222,
            ..Host::default()
        };
        let arguments =
            interactive_sftp_arguments(&host).unwrap_or_else(|e| panic!("sftp arguments: {e}"));
        assert!(!arguments.contains(&"-B".into()));
        assert!(!arguments.contains(&"BatchMode=yes".into()));
        assert!(arguments.contains(&"-P".into()));
        assert!(arguments.contains(&"2222".into()));
    }

    #[test]
    fn remote_path_parsing_does_not_confuse_ipv6_or_local_windows_paths() {
        assert_eq!(
            parse_remote_path("prod:/tmp/a").ok(),
            Some(RemotePath {
                target: "prod".into(),
                path: "/tmp/a".into()
            })
        );
        assert_eq!(
            parse_remote_path("[2001:db8::1]:/tmp/a")
                .ok()
                .map(|v| v.target),
            Some("2001:db8::1".into())
        );
        assert!(parse_remote_path("without-a-path").is_err());
        assert!(parse_remote_path("prod:line\nbreak").is_err());
    }

    #[test]
    fn existing_local_download_requires_overwrite() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("already-here");
        std::fs::write(&path, "keep").unwrap_or_else(|e| panic!("write: {e}"));
        let host = Host {
            number: None,
            transport: crate::config::TransportKind::Ssh,
            ssh_alias: Some("fake".into()),
            hostname: None,
            port: 22,
            username: None,
            platform: crate::config::Platform::Linux,
            shell: crate::config::ShellKind::Posix,
            auth: crate::config::AuthMode::OpensshConfig,
            environment: String::new(),
            tags: Vec::new(),
            raw_mode: crate::config::RawMode::Allow,
            approval: crate::config::ApprovalMode::Never,
            insecure_acknowledged: false,
            sudo_credential: None,
            credential: None,
            prompt: None,
        };
        let future = get(
            &host,
            "/tmp/remote",
            &path,
            false,
            Duration::from_secs(1),
            1024,
            None,
        );
        let runtime = tokio::runtime::Runtime::new().unwrap_or_else(|e| panic!("runtime: {e}"));
        assert_eq!(
            runtime.block_on(future).unwrap_err().code,
            ErrorCode::PolicyDenied
        );
        assert_eq!(std::fs::read_to_string(path).ok().as_deref(), Some("keep"));
    }
}
