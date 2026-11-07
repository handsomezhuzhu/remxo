use super::{Capabilities, ExecutionRequest, Transport};
use crate::config::{Host, TransportKind};
use crate::error::{AppError, ErrorCode, Result};
use async_trait::async_trait;

#[derive(Debug, Clone, Default)]
pub struct TelnetTransport;

impl TelnetTransport {
    fn validate(host: &Host) -> Result<()> {
        if host.transport != TransportKind::Telnet {
            return Err(AppError::invalid_argument("not a Telnet host"));
        }
        if !host.insecure_acknowledged {
            return Err(AppError::new(
                ErrorCode::InsecureTransport,
                "Telnet transmits credentials, commands, and output without transport encryption; explicit insecure_acknowledged=true is required",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for TelnetTransport {
    fn capabilities(&self, _host: &Host) -> Capabilities {
        Capabilities {
            exec: false,
            interactive: false,
            transfer: false,
            tunnel: false,
            encrypted: false,
        }
    }

    async fn exec(&self, request: ExecutionRequest) -> Result<super::ExecutionOutcome> {
        Self::validate(&request.host)?;
        Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "Telnet command framing is not implemented in this build; the host remains explicitly INSECURE",
        ))
    }

    fn interactive(&self, host: &Host) -> Result<i32> {
        Self::validate(host)?;
        Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "Telnet interactive support is not implemented in this build",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unacknowledged_telnet_fails_closed() {
        let host = Host {
            number: None,
            transport: TransportKind::Telnet,
            ssh_alias: None,
            hostname: Some("192.0.2.2".into()),
            port: 23,
            username: None,
            platform: crate::config::Platform::NetworkDevice,
            shell: crate::config::ShellKind::Device,
            auth: crate::config::AuthMode::VaultPassword,
            environment: "legacy".into(),
            tags: Vec::new(),
            raw_mode: crate::config::RawMode::ReadOnly,
            approval: crate::config::ApprovalMode::Always,
            insecure_acknowledged: false,
            sudo_credential: None,
            credential: None,
            prompt: None,
        };
        let error = TelnetTransport::validate(&host).unwrap_err();
        assert_eq!(error.code, ErrorCode::InsecureTransport);
        assert!(!TelnetTransport.capabilities(&host).encrypted);
    }
}
