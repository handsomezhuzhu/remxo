use crate::config::Host;
use crate::error::{AppError, ErrorCode, Result};
use crate::transport::openssh::{OpensshTransport, prepare_authentication};
use crate::transport::{AuthenticationContext, openssh::ProcessAuthentication};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelKind {
    Local,
    Remote,
    Dynamic,
}

#[derive(Debug, Clone)]
pub struct TunnelSpec {
    pub kind: TunnelKind,
    pub argument: String,
    pub public_bind: bool,
    pub dynamic: bool,
}

impl TunnelSpec {
    pub fn local(value: &str) -> Result<Self> {
        parse_forward(value, false)
    }

    pub fn remote(value: &str) -> Result<Self> {
        parse_forward(value, true)
    }

    pub fn dynamic(port: u16) -> Result<Self> {
        if port == 0 {
            return Err(AppError::invalid_argument(
                "dynamic port must be greater than zero",
            ));
        }
        Ok(Self {
            kind: TunnelKind::Dynamic,
            argument: format!("127.0.0.1:{port}"),
            public_bind: false,
            dynamic: true,
        })
    }
}

fn parse_forward(value: &str, remote: bool) -> Result<TunnelSpec> {
    if value.contains('\0') || value.chars().any(char::is_whitespace) {
        return Err(AppError::invalid_argument("invalid tunnel specification"));
    }
    let parts: Vec<&str> = value.split(':').collect();
    let (bind, listen_port, remote_host, remote_port) = match parts.as_slice() {
        [listen, host, port] => ("127.0.0.1", *listen, *host, *port),
        [bind, listen, host, port] => (*bind, *listen, *host, *port),
        _ => {
            return Err(AppError::invalid_argument(
                "forward must be [bind:]listen_port:remote_host:remote_port; IPv6 needs bracket-aware future support",
            ));
        }
    };
    let listen_port = checked_port(listen_port)?;
    let remote_port = checked_port(remote_port)?;
    if remote_host.is_empty()
        || bind.is_empty()
        || remote_host.contains(['[', ']'])
        || bind.contains(['[', ']'])
    {
        return Err(AppError::invalid_argument(
            "invalid tunnel host or bind address",
        ));
    }
    let public_bind = bind != "127.0.0.1" && bind != "localhost" && bind != "::1";
    let argument = format!("{bind}:{listen_port}:{remote_host}:{remote_port}");
    Ok(TunnelSpec {
        kind: if remote {
            TunnelKind::Remote
        } else {
            TunnelKind::Local
        },
        argument,
        public_bind,
        dynamic: false,
    })
}

fn checked_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| AppError::invalid_argument("tunnel ports must be integers from 1 to 65535"))?;
    if port == 0 {
        return Err(AppError::invalid_argument(
            "tunnel ports must be greater than zero",
        ));
    }
    Ok(port)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSummary {
    pub id: String,
    pub host: String,
    pub kind: TunnelKind,
    pub argument: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
struct TunnelRecord {
    summary: TunnelSummary,
    child: Child,
    _authentication: ProcessAuthentication,
}

#[derive(Debug, Default)]
pub struct TunnelManager {
    tunnels: Arc<Mutex<BTreeMap<String, TunnelRecord>>>,
}

fn forward_ready(diagnostic: &str) -> bool {
    // OpenSSH prints bind listener messages before attempting bind, so those do
    // not prove startup. Interactive mode follows forwarding setup.
    diagnostic
        .to_ascii_lowercase()
        .contains("entering interactive session.")
}

async fn wait_for_forward_ready(child: &mut Child, stderr: ChildStderr) -> Result<ChildStderr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut lines = BufReader::new(stderr).lines();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| AppError::io("inspect tunnel startup", error))?
        {
            return Err(AppError::new(
                ErrorCode::ConnectionFailed,
                format!(
                    "tunnel exited during startup with code {:?}; check port conflicts, host key state, and AllowTcpForwarding",
                    status.code()
                ),
            ));
        }
        if let Ok(result) =
            tokio::time::timeout(Duration::from_millis(100), lines.next_line()).await
        {
            let line = result.map_err(|error| AppError::io("read tunnel diagnostics", error))?;
            if let Some(mut line) = line {
                let ready = forward_ready(&line);
                line.zeroize();
                if ready {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|error| AppError::io("inspect completed tunnel startup", error))?
                    {
                        return Err(AppError::new(
                            ErrorCode::ConnectionFailed,
                            format!(
                                "tunnel exited after forwarding setup with code {:?}",
                                status.code()
                            ),
                        ));
                    }
                    return Ok(lines.into_inner().into_inner());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(AppError::new(
                ErrorCode::Timeout,
                "timed out waiting for OpenSSH forwarding readiness; local tunnel process was stopped without retry",
            ));
        }
    }
}

impl TunnelManager {
    pub async fn start(
        &self,
        host_alias: String,
        host: &Host,
        spec: TunnelSpec,
        auth_context: Option<&AuthenticationContext>,
    ) -> Result<TunnelSummary> {
        let transport = OpensshTransport::default();
        let mut arguments = transport.base_arguments(host, true, Duration::from_secs(30))?;
        let destination = arguments
            .pop()
            .ok_or_else(|| AppError::internal("missing tunnel destination"))?;
        arguments.extend([
            "-N".into(),
            "-v".into(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            match spec.kind {
                TunnelKind::Local => "-L",
                TunnelKind::Remote => "-R",
                TunnelKind::Dynamic => "-D",
            }
            .into(),
            spec.argument.clone(),
            destination,
        ]);
        let mut command = Command::new(transport.binary());
        crate::process::tokio_without_console_window(&mut command);
        let authentication = prepare_authentication(host, auth_context, false).await?;
        authentication.apply(&mut command);
        let mut child = command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AppError::io("start OpenSSH tunnel", e))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| AppError::internal("missing OpenSSH tunnel diagnostics"))?;
        let stderr = match wait_for_forward_ready(&mut child, stderr).await {
            Ok(stderr) => stderr,
            Err(error) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
        };
        // Continue draining verbose diagnostics after readiness without logging them.
        tokio::spawn(async move {
            let mut stderr = stderr;
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        });
        let id = Uuid::new_v4().to_string();
        let summary = TunnelSummary {
            id: id.clone(),
            host: host_alias,
            kind: spec.kind,
            argument: spec.argument,
            created_at: Utc::now(),
        };
        self.tunnels.lock().await.insert(
            id,
            TunnelRecord {
                summary: summary.clone(),
                child,
                _authentication: authentication,
            },
        );
        Ok(summary)
    }

    pub async fn list(&self) -> Result<Vec<TunnelSummary>> {
        let mut tunnels = self.tunnels.lock().await;
        let mut stale = Vec::new();
        for (id, record) in tunnels.iter_mut() {
            if record
                .child
                .try_wait()
                .map_err(|e| AppError::io("inspect tunnel", e))?
                .is_some()
            {
                stale.push(id.clone());
            }
        }
        for id in stale {
            tunnels.remove(&id);
        }
        Ok(tunnels
            .values()
            .map(|record| record.summary.clone())
            .collect())
    }

    pub async fn stop(&self, id: &str) -> Result<TunnelSummary> {
        let mut record = self
            .tunnels
            .lock()
            .await
            .remove(id)
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "tunnel not found"))?;
        record
            .child
            .kill()
            .await
            .map_err(|e| AppError::io("stop tunnel", e))?;
        let _ = record.child.wait().await;
        Ok(record.summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_uses_forward_setup_not_arbitrary_process_liveness() {
        assert!(forward_ready("debug1: Entering interactive session."));
        assert!(!forward_ready(
            "debug1: Local forwarding listening on 127.0.0.1 port 15432"
        ));
        assert!(!forward_ready(
            "debug1: Allocated port 5432 for remote forward to 127.0.0.1:5432"
        ));
        assert!(!forward_ready("bind: Address already in use"));
        assert!(!forward_ready("OpenSSH_10.0"));
    }

    #[test]
    fn defaults_to_loopback() {
        let spec =
            TunnelSpec::local("15432:127.0.0.1:5432").unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(spec.argument, "127.0.0.1:15432:127.0.0.1:5432");
        assert!(!spec.public_bind);
        assert!(
            TunnelSpec::local("0.0.0.0:15432:127.0.0.1:5432")
                .map(|s| s.public_bind)
                .unwrap_or(false)
        );
        assert!(TunnelSpec::dynamic(1080).is_ok());
        assert!(TunnelSpec::local("bad").is_err());
    }
}
