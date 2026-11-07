use crate::error::{AppError, ErrorCode, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub host: String,
    pub operation: String,
    pub request_digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved: bool,
    pub used: bool,
}

#[derive(Debug, Default)]
pub struct ApprovalManager {
    approvals: Mutex<BTreeMap<String, Approval>>,
}

impl ApprovalManager {
    pub fn require(&self, host: &str, operation: &str, digest: &str) -> Result<()> {
        let mut approvals = self
            .approvals
            .lock()
            .map_err(|_| AppError::internal("approval lock poisoned"))?;
        approvals.retain(|_, approval| approval.expires_at > Utc::now() && !approval.used);
        if let Some(approval) = approvals.values_mut().find(|approval| {
            approval.host == host
                && approval.operation == operation
                && approval.request_digest == digest
                && approval.expires_at > Utc::now()
                && approval.approved
                && !approval.used
        }) {
            approval.used = true;
            return Ok(());
        }
        if let Some(existing) = approvals.values().find(|approval| {
            approval.host == host
                && approval.operation == operation
                && approval.request_digest == digest
        }) {
            return Err(AppError::new(
                ErrorCode::ApprovalRequired,
                "this operation requires one-time human approval; rerun the unchanged operation after approval",
            )
            .with_approval(existing.id.clone()));
        }
        let now = Utc::now();
        let approval = Approval {
            id: Uuid::new_v4().to_string(),
            host: host.to_string(),
            operation: operation.to_string(),
            request_digest: digest.to_string(),
            created_at: now,
            expires_at: now + Duration::minutes(5),
            approved: false,
            used: false,
        };
        let id = approval.id.clone();
        approvals.insert(id.clone(), approval);
        Err(AppError::new(
            ErrorCode::ApprovalRequired,
            "this operation requires one-time human approval; rerun the unchanged operation after approval",
        )
        .with_approval(id))
    }

    pub fn approve(&self, id: &str) -> Result<Approval> {
        let mut approvals = self
            .approvals
            .lock()
            .map_err(|_| AppError::internal("approval lock poisoned"))?;
        let approval = approvals
            .get_mut(id)
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "approval request not found"))?;
        if approval.used || approval.expires_at <= Utc::now() {
            return Err(AppError::new(
                ErrorCode::PolicyDenied,
                "approval request is expired or already consumed",
            ));
        }
        approval.approved = true;
        Ok(approval.clone())
    }

    pub fn list(&self) -> Result<Vec<Approval>> {
        let approvals = self
            .approvals
            .lock()
            .map_err(|_| AppError::internal("approval lock poisoned"))?;
        Ok(approvals
            .values()
            .filter(|approval| approval.expires_at > Utc::now() && !approval.used)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_bound_to_digest_and_single_use() {
        let manager = ApprovalManager::default();
        let first = manager.require("prod", "exec", "digest-a").unwrap_err();
        let id = first.approval_id.unwrap_or_default();
        assert_eq!(
            manager
                .require("prod", "exec", "digest-a")
                .unwrap_err()
                .approval_id,
            Some(id.clone())
        );
        assert!(manager.approve(&id).is_ok());
        assert!(manager.require("prod", "exec", "digest-a").is_ok());
        let replay = manager.require("prod", "exec", "digest-a").unwrap_err();
        assert_ne!(replay.approval_id, Some(id));
        let pending = manager.require("prod", "exec", "digest-b").unwrap_err();
        let pending_id = pending.approval_id.unwrap_or_default();
        manager
            .approve(&pending_id)
            .unwrap_or_else(|e| panic!("approve: {e}"));
        let error = manager.require("prod", "exec", "modified").unwrap_err();
        assert_eq!(error.code, ErrorCode::ApprovalRequired);
    }
}
