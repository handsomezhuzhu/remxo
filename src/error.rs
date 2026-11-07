use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    VaultLocked,
    AgentUnavailable,
    AgentIdentityUnavailable,
    HostNotFound,
    HostNotAllowed,
    PolicyDenied,
    ApprovalRequired,
    AuthenticationFailed,
    HostKeyFailed,
    ConnectionFailed,
    Timeout,
    OutputLimit,
    UnsupportedPlatform,
    UnsupportedShell,
    UnsupportedOperation,
    SudoPasswordNotConfigured,
    SudoNotPermitted,
    InsecureTransport,
    InvalidConfig,
    InvalidArgument,
    AlreadyExists,
    NotFound,
    IoError,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub approval_id: Option<String>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            approval_id: None,
        }
    }

    pub fn with_approval(mut self, approval_id: impl Into<String>) -> Self {
        self.approval_id = Some(approval_id.into());
        self
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, message)
    }

    pub fn io(context: &str, error: std::io::Error) -> Self {
        Self::new(ErrorCode::IoError, format!("{context}: {error}"))
    }

    pub fn detail(&self) -> ErrorDetail {
        ErrorDetail {
            code: self.code,
            message: self.message.clone(),
            approval_id: self.approval_id.clone(),
        }
    }
}

impl From<AppError> for ErrorDetail {
    fn from(value: AppError) -> Self {
        value.detail()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
