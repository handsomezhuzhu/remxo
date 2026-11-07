use crate::error::{AppError, ErrorCode, Result};
use crate::model::OperationReport;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Cancelling,
    Cancelled,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSummary {
    pub id: String,
    pub host: String,
    pub operation: String,
    pub request_digest: String,
    pub state: TaskState,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub remote_exit_code: Option<i32>,
    pub truncated: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct TaskRecord {
    summary: TaskSummary,
    stdout: String,
    stderr: String,
    cancellation: CancellationToken,
}

#[derive(Debug, Default)]
pub struct TaskManager {
    tasks: std::sync::Arc<Mutex<BTreeMap<String, TaskRecord>>>,
}

impl TaskManager {
    pub fn start<F, Fut>(
        &self,
        host: String,
        operation: String,
        digest: String,
        run: F,
    ) -> Result<TaskSummary>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = OperationReport> + Send + 'static,
    {
        let id = Uuid::new_v4().to_string();
        let summary = TaskSummary {
            id: id.clone(),
            host,
            operation,
            request_digest: digest,
            state: TaskState::Pending,
            created_at: Utc::now(),
            finished_at: None,
            remote_exit_code: None,
            truncated: false,
            error: None,
        };
        let cancellation = CancellationToken::new();
        {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| AppError::internal("task lock poisoned"))?;
            tasks.insert(
                id.clone(),
                TaskRecord {
                    summary: summary.clone(),
                    stdout: String::new(),
                    stderr: String::new(),
                    cancellation: cancellation.clone(),
                },
            );
        }
        let task_id = id.clone();
        let tasks = std::sync::Arc::clone(&self.tasks);
        tokio::spawn(async move {
            {
                let mut map = tasks
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(record) = map.get_mut(&task_id) {
                    record.summary.state = TaskState::Running;
                }
            }
            let report = run(cancellation.clone()).await;
            let mut map = tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(record) = map.get_mut(&task_id) {
                record.summary.remote_exit_code = report.remote_exit_code;
                record.summary.truncated = report.truncated;
                record.summary.error = report.error.as_ref().map(|error| error.message.clone());
                record.summary.finished_at = Some(Utc::now());
                record.summary.state = if cancellation.is_cancelled() {
                    TaskState::Cancelled
                } else {
                    match report.error.as_ref().map(|error| error.code) {
                        Some(ErrorCode::Timeout) => TaskState::TimedOut,
                        Some(_) => TaskState::Failed,
                        None if report.status == crate::model::OperationStatus::Success => {
                            TaskState::Succeeded
                        }
                        None => TaskState::Failed,
                    }
                };
                record.stdout = report.stdout;
                record.stderr = report.stderr;
            }
        });
        Ok(summary)
    }

    pub fn list(&self) -> Result<Vec<TaskSummary>> {
        let tasks = self
            .tasks
            .lock()
            .map_err(|_| AppError::internal("task lock poisoned"))?;
        Ok(tasks
            .values()
            .map(|record| record.summary.clone())
            .collect())
    }

    pub fn status(&self, id: &str) -> Result<TaskSummary> {
        let tasks = self
            .tasks
            .lock()
            .map_err(|_| AppError::internal("task lock poisoned"))?;
        tasks
            .get(id)
            .map(|record| record.summary.clone())
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "task not found"))
    }

    pub fn logs(&self, id: &str) -> Result<(String, String)> {
        let tasks = self
            .tasks
            .lock()
            .map_err(|_| AppError::internal("task lock poisoned"))?;
        let record = tasks
            .get(id)
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "task not found"))?;
        Ok((record.stdout.clone(), record.stderr.clone()))
    }

    pub fn stop(&self, id: &str) -> Result<TaskSummary> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| AppError::internal("task lock poisoned"))?;
        let record = tasks
            .get_mut(id)
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, "task not found"))?;
        if record.summary.finished_at.is_some() {
            return Err(AppError::invalid_argument("task has already finished"));
        }
        record.summary.state = TaskState::Cancelling;
        record.cancellation.cancel();
        Ok(record.summary.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OperationStatus;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn task_finishes_once_with_bounded_processed_logs() {
        let manager = TaskManager::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let summary = manager
            .start(
                "prod".into(),
                "exec".into(),
                "digest".into(),
                move |_| async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut report = OperationReport::new(Some("prod".into()), "exec").success();
                    report.status = OperationStatus::Success;
                    report.remote_exit_code = Some(0);
                    report.stdout = "sanitized output".into();
                    report
                },
            )
            .unwrap_or_else(|e| panic!("start: {e}"));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if manager
                    .status(&summary.id)
                    .map(|task| task.state == TaskState::Succeeded)
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("task did not finish"));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert_eq!(
            manager.logs(&summary.id).map(|logs| logs.0).ok().as_deref(),
            Some("sanitized output")
        );
    }

    #[tokio::test]
    async fn stop_cancels_local_wait_and_marks_remote_unknown() {
        let manager = TaskManager::default();
        let summary = manager
            .start(
                "prod".into(),
                "exec".into(),
                "digest".into(),
                |token| async move {
                    token.cancelled().await;
                    OperationReport::new(Some("prod".into()), "exec")
                },
            )
            .unwrap_or_else(|e| panic!("start: {e}"));
        let stopped = manager
            .stop(&summary.id)
            .unwrap_or_else(|e| panic!("stop: {e}"));
        assert_eq!(stopped.state, TaskState::Cancelling);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if manager
                    .status(&summary.id)
                    .map(|task| task.state == TaskState::Cancelled)
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("task did not cancel"));
    }
}
