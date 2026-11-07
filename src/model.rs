use crate::error::{AppError, ErrorDetail, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    NotApplicable,
    Allowed,
    Denied,
    ApprovalRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Success,
    Failed,
    Pending,
    Running,
    Cancelled,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationReport {
    pub schema_version: u32,
    pub request_id: String,
    pub host: Option<String>,
    pub operation: String,
    pub decision: Decision,
    pub status: OperationStatus,
    pub remote_exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: u64,
    pub error: Option<ErrorDetail>,
}

impl OperationReport {
    pub fn new(host: Option<String>, operation: impl Into<String>) -> Self {
        Self {
            schema_version: JSON_SCHEMA_VERSION,
            request_id: Uuid::new_v4().to_string(),
            host,
            operation: operation.into(),
            decision: Decision::NotApplicable,
            status: OperationStatus::Pending,
            remote_exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            duration_ms: 0,
            error: None,
        }
    }

    pub fn success(mut self) -> Self {
        self.decision = Decision::Allowed;
        self.status = OperationStatus::Success;
        self
    }

    pub fn failed(mut self, error: &AppError) -> Self {
        self.status = OperationStatus::Failed;
        self.error = Some(error.detail());
        match error.code {
            crate::error::ErrorCode::ApprovalRequired => {
                self.decision = Decision::ApprovalRequired;
            }
            crate::error::ErrorCode::PolicyDenied
            | crate::error::ErrorCode::HostNotAllowed
            | crate::error::ErrorCode::InsecureTransport
            | crate::error::ErrorCode::SudoNotPermitted => {
                self.decision = Decision::Denied;
            }
            _ => {}
        }
        self
    }

    pub fn finish(mut self, started: std::time::Instant) -> Self {
        self.duration_ms = started.elapsed().as_millis() as u64;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub schema_version: u32,
    pub vault_exists: bool,
    pub vault_locked: bool,
    pub broker_running: bool,
    pub hosts: usize,
    pub agent_available: Option<bool>,
}

pub trait Operation {
    fn name(&self) -> &'static str;
}

pub fn require_tty(interactive: bool) -> Result<()> {
    if interactive {
        Ok(())
    } else {
        Err(AppError::invalid_argument(
            "A remote command is required in a non-interactive session; no input was read.",
        ))
    }
}
