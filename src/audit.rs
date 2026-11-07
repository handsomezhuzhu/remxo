use crate::error::{AppError, Result};
use crate::store::ensure_private_dir;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub time: DateTime<Utc>,
    pub request_id: String,
    pub host: String,
    pub operation: String,
    pub request_digest: String,
    pub decision: String,
    pub approval_id: Option<String>,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub truncated: bool,
    pub error: Option<String>,
    pub transport: String,
}

#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            lock: Mutex::new(()),
        })
    }

    pub fn append(&self, event: &AuditEvent) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| AppError::internal("audit lock poisoned"))?;
        let bytes = serde_json::to_vec(event)
            .map_err(|e| AppError::internal(format!("serialize audit event: {e}")))?;
        #[allow(unused_mut)]
        let mut options = OpenOptions::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| AppError::io("open audit log", e))?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|e| AppError::io("append audit log", e))?;
        crate::store::restrict_path(&self.path)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text =
            std::fs::read_to_string(&self.path).map_err(|e| AppError::io("read audit log", e))?;
        let events: BTreeMap<usize, AuditEvent> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
            .enumerate()
            .collect();
        Ok(events
            .into_iter()
            .rev()
            .take(limit)
            .map(|(_, event)| event)
            .collect())
    }
}

pub fn request_digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}
