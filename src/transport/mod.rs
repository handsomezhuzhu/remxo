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
    if let Some(data) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(&data)
            .await
            .map_err(|e| AppError::io("write secure standard input", e))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| AppError::io("close secure standard input", e))?;
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

#[derive(Clone)]
pub struct ExecutionRequest {
    pub host: Host,
    pub script: String,
    pub timeout: Duration,
    pub max_output: usize,
    pub sudo_password: Option<String>,
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
        AuthMode::VaultKey => Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "vault-key OpenSSH integration is reserved for a later phase",
        )),
        AuthMode::VaultPassword => Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "non-interactive vault-password OpenSSH integration is not enabled in this build; use interactive SSH or an external agent",
        )),
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
