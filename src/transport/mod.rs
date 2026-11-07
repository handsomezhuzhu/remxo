pub mod openssh;
pub mod telnet;

use crate::config::{AuthMode, Host};
use crate::error::{AppError, ErrorCode, Result};
use crate::output::ProcessedOutput;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTermination {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Debug)]
pub struct RawProcessOutput {
    pub termination: ProcessTermination,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl Drop for RawProcessOutput {
    fn drop(&mut self) {
        self.stdout.zeroize();
        self.stderr.zeroize();
    }
}

pub(crate) async fn run_process(
    command: &mut Command,
    timeout: Duration,
    raw_limit: usize,
    stdin_data: Option<Zeroizing<Vec<u8>>>,
    cancellation: Option<CancellationToken>,
) -> Result<RawProcessOutput> {
    command
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| {
        AppError::new(
            ErrorCode::ConnectionFailed,
            format!("cannot start remote transport: {e}"),
        )
    })?;
    if let Some(data) = stdin_data {
        let input_result = match child.stdin.take() {
            Some(mut stdin) => {
                async {
                    stdin
                        .write_all(&data)
                        .await
                        .map_err(|error| AppError::io("write secure standard input", error))?;
                    stdin
                        .shutdown()
                        .await
                        .map_err(|error| AppError::io("close secure standard input", error))
                }
                .await
            }
            None => Err(AppError::internal("missing secure standard input")),
        };
        if let Err(error) = input_result {
            // Authentication guards must not be released while this child may
            // still be using its temporary private-key file or other resources.
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(error);
        }
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::internal("missing child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::internal("missing child stderr"))?;
    let stdout_reader = tokio::spawn(read_bounded(stdout, raw_limit));
    let stderr_reader = tokio::spawn(read_bounded(stderr, raw_limit));
    let cancelled = async {
        match cancellation {
            Some(token) => token.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };
    let mut termination = ProcessTermination::Exited;
    let status = tokio::select! {
        result = child.wait() => Some(result.map_err(|e| AppError::io("wait for remote transport", e))?),
        _ = tokio::time::sleep(timeout) => {
            termination = ProcessTermination::TimedOut;
            None
        },
        _ = cancelled => {
            termination = ProcessTermination::Cancelled;
            None
        }
    };
    if status.is_none() {
        child
            .kill()
            .await
            .map_err(|e| AppError::io("stop local transport process", e))?;
        let _ = child.wait().await;
    }
    let (stdout, stdout_truncated) = stdout_reader
        .await
        .map_err(|e| AppError::internal(format!("stdout reader stopped: {e}")))??;
    let (stderr, stderr_truncated) = stderr_reader
        .await
        .map_err(|e| AppError::internal(format!("stderr reader stopped: {e}")))??;
    Ok(RawProcessOutput {
        termination,
        exit_code: status.and_then(|status| status.code()),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin, limit: usize) -> Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(limit.min(65_536));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|e| AppError::io("read remote output", e))?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(retained.len());
        let keep = remaining.min(count);
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < count;
    }
    Ok((retained, truncated))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Capabilities {
    pub exec: bool,
    pub interactive: bool,
    pub transfer: bool,
    pub tunnel: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct AuthenticationContext {
    pub paths: crate::config::AppPaths,
    pub alias: String,
    /// Present only for the wizard's connection test before the host is saved.
    pub pending_host: Option<Host>,
}

impl AuthenticationContext {
    pub fn registered(paths: crate::config::AppPaths, alias: &str, host: &Host) -> Option<Self> {
        matches!(host.auth, AuthMode::VaultPassword | AuthMode::VaultKey).then(|| Self {
            paths,
            alias: alias.to_string(),
            pending_host: None,
        })
    }

    pub fn pending(paths: crate::config::AppPaths, alias: &str, host: &Host) -> Option<Self> {
        matches!(host.auth, AuthMode::VaultPassword | AuthMode::VaultKey).then(|| Self {
            paths,
            alias: alias.to_string(),
            pending_host: Some(host.clone()),
        })
    }
}

#[derive(Clone)]
pub struct ExecutionRequest {
    pub host: Host,
    pub script: String,
    pub timeout: Duration,
    pub max_output: usize,
    pub sudo_password: Option<String>,
    pub auth_context: Option<AuthenticationContext>,
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub exit_code: Option<i32>,
    pub stdout: ProcessedOutput,
    pub stderr: ProcessedOutput,
    pub truncated: bool,
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn capabilities(&self, host: &Host) -> Capabilities;

    async fn exec(&self, request: ExecutionRequest) -> Result<ExecutionOutcome>;

    fn interactive(&self, host: &Host) -> Result<i32>;
}

pub fn validate_auth(host: &Host) -> Result<()> {
    match host.auth {
        AuthMode::VaultPassword | AuthMode::VaultKey => Ok(()),
        AuthMode::ExternalAgent | AuthMode::OpensshConfig => Ok(()),
    }
}

pub fn check_agent_available(host: &Host) -> bool {
    if host.auth != AuthMode::ExternalAgent {
        return true;
    }
    #[cfg(unix)]
    {
        std::env::var_os("SSH_AUTH_SOCK")
            .map(std::path::PathBuf::from)
            .is_some_and(|path| path.exists())
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn stdin_failure_kills_and_reaps_child_before_returning() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let pid_file = directory.path().join("pid");
        let script = directory.path().join("closed-stdin");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{}'\nexec 0<&-\nwhile :; do :; done\n",
                pid_file.display()
            ),
        )
        .unwrap_or_else(|error| panic!("fake: {error}"));
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|error| panic!("chmod: {error}"));
        let error = run_process(
            &mut Command::new(script),
            Duration::from_secs(5),
            1024,
            Some(Zeroizing::new(vec![b'x'; 1024 * 1024])),
            None,
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("secure standard input"));
        let pid = std::fs::read_to_string(pid_file)
            .unwrap_or_else(|error| panic!("pid: {error}"))
            .trim()
            .parse::<u32>()
            .unwrap_or_else(|error| panic!("pid parse: {error}"));
        let process_path = std::path::Path::new("/proc").join(pid.to_string());
        for _ in 0..20 {
            if !process_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process_path.exists(),
            "child was not reaped after stdin failure"
        );
    }
}
