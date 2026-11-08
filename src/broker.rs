use crate::approval::{Approval, ApprovalManager};
use crate::audit::{AuditEvent, AuditLog, request_digest};
use crate::config::{AppPaths, Config, TransportKind, resolve_target};
use crate::credential::{SSH_PASSWORD_KIND, SSH_PRIVATE_KEY_KIND};
use crate::error::{AppError, ErrorCode, ErrorDetail, Result};
use crate::model::{Decision, OperationReport, OperationStatus, StatusReport};
use crate::policy;
use crate::shell::{command_script, sudo_script, with_cwd};
use crate::sudo;
use crate::task::{TaskManager, TaskSummary};
use crate::transport::ExecutionRequest;
use crate::transport::openssh::OpensshTransport;
use crate::tunnel::{TunnelManager, TunnelSpec, TunnelSummary};
use crate::vault::{Credential, VaultSession};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteSpec {
    pub target: String,
    #[serde(default)]
    pub command: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub sudo: bool,
    pub profile: Option<String>,
    #[serde(default)]
    pub profile_args: BTreeMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub max_output: Option<usize>,
}

struct PreparedExecution {
    alias: String,
    host: crate::config::Host,
    script: String,
    timeout: Duration,
    max_output: usize,
    sudo_password: Option<zeroize::Zeroizing<String>>,
    digest: String,
    operation: String,
    auth_context: Option<crate::transport::AuthenticationContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSpec {
    pub target: String,
    pub local: std::path::PathBuf,
    pub remote: String,
    pub upload: bool,
    pub overwrite: bool,
    pub timeout_seconds: Option<u64>,
    pub max_output: Option<usize>,
}

struct PreparedTransfer {
    alias: String,
    host: crate::config::Host,
    local: std::path::PathBuf,
    remote: String,
    upload: bool,
    overwrite: bool,
    timeout: Duration,
    max_output: usize,
    operation: String,
    digest: String,
}

fn host_identity(host: &crate::config::Host) -> Result<String> {
    serde_json::to_string(host)
        .map_err(|error| AppError::internal(format!("serialize host identity: {error}")))
}

pub struct Broker {
    paths: AppPaths,
    vault: tokio::sync::Mutex<Option<VaultSession>>,
    approvals: ApprovalManager,
    audit: Arc<AuditLog>,
    tasks: TaskManager,
    tunnels: TunnelManager,
    transport: OpensshTransport,
}

impl Broker {
    pub fn new(paths: AppPaths) -> Result<Arc<Self>> {
        Self::with_transport(paths, OpensshTransport::default())
    }

    pub fn with_transport(paths: AppPaths, transport: OpensshTransport) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            audit: Arc::new(AuditLog::new(&paths.audit())?),
            paths,
            vault: tokio::sync::Mutex::new(None),
            approvals: ApprovalManager::default(),
            tasks: TaskManager::default(),
            tunnels: TunnelManager::default(),
            transport,
        }))
    }

    pub async fn status(&self) -> Result<StatusReport> {
        let config = Config::load(&self.paths.config)?;
        let vault = self.vault.lock().await;
        Ok(StatusReport {
            schema_version: 1,
            vault_exists: self.paths.vault().exists(),
            vault_locked: vault.as_ref().is_none_or(|vault| !vault.is_unlocked()),
            broker_running: true,
            hosts: config.hosts.len(),
            agent_available: None,
        })
    }

    pub async fn unlock(&self, password: &str) -> Result<()> {
        let mut guard = self.vault.lock().await;
        if guard.is_none() {
            *guard = Some(VaultSession::load(&self.paths.vault())?);
        }
        let vault = guard
            .as_mut()
            .ok_or_else(|| AppError::internal("vault initialization failed"))?;
        vault.unlock(password)
    }

    pub async fn lock(&self) {
        let mut guard = self.vault.lock().await;
        if let Some(vault) = guard.as_mut() {
            vault.lock();
        }
        *guard = None;
    }

    pub async fn change_password(&self, old: &str, new: &str) -> Result<()> {
        let mut guard = self.vault.lock().await;
        if guard.is_none() {
            *guard = Some(VaultSession::load(&self.paths.vault())?);
        }
        guard
            .as_mut()
            .ok_or_else(|| AppError::internal("vault initialization failed"))?
            .change_password(old, new)
    }

    pub async fn set_credential(&self, name: &str, kind: &str, value: &str) -> Result<()> {
        if name.is_empty()
            || name.len() > 256
            || !matches!(
                kind,
                "ssh-password" | "ssh-private-key" | "sudo-password" | "telnet-password"
            )
        {
            return Err(AppError::invalid_argument(
                "invalid credential name or kind",
            ));
        }
        let mut guard = self.vault.lock().await;
        let vault = guard.as_mut().ok_or_else(crate::vault::vault_locked)?;
        if value.len() > crate::credential::MAX_PRIVATE_KEY_BYTES {
            return Err(AppError::invalid_argument(
                "credential exceeds the 1 MiB secret size limit",
            ));
        }
        vault.put_record(
            name,
            Credential {
                kind: kind.to_string(),
                value: value.to_string(),
                metadata: BTreeMap::new(),
            },
        )
    }

    pub async fn import_private_key(&self, name: &str, path: &std::path::Path) -> Result<()> {
        {
            let guard = self.vault.lock().await;
            if guard.as_ref().is_none_or(|vault| !vault.is_unlocked()) {
                return Err(crate::vault::vault_locked());
            }
        }
        let key = crate::credential::read_private_key(path)?;
        self.set_credential(name, SSH_PRIVATE_KEY_KIND, &key).await
    }

    pub async fn credential_for_authentication(
        &self,
        target: &str,
        pending_host: Option<&crate::config::Host>,
        private_key: bool,
    ) -> Result<(String, String)> {
        let config = Config::load(&self.paths.config)?;
        let target = if let Some(host) = pending_host {
            if config.hosts.contains_key(target) {
                return Err(AppError::new(
                    ErrorCode::AlreadyExists,
                    "a saved host must use authentication derived from its registered configuration",
                ));
            }
            host.validate(target)?;
            crate::config::ResolvedTarget {
                alias: target.to_string(),
                host: host.clone(),
            }
        } else {
            resolve_target(&config, target)?
        };
        let (name, expected_kind) = match (target.host.auth, private_key) {
            (crate::config::AuthMode::VaultPassword, false)
            | (crate::config::AuthMode::VaultKey, false) => {
                let stem = target.host.credential.as_deref().unwrap_or(&target.alias);
                (
                    crate::credential::ssh_credential_name(stem),
                    SSH_PASSWORD_KIND,
                )
            }
            (crate::config::AuthMode::VaultKey, true) => {
                let stem = target.host.credential.as_deref().unwrap_or(&target.alias);
                (
                    crate::credential::key_credential_name(stem),
                    SSH_PRIVATE_KEY_KIND,
                )
            }
            _ => {
                return Err(AppError::new(
                    ErrorCode::UnsupportedOperation,
                    "requested authentication material is not valid for this host authentication mode",
                ));
            }
        };
        let mut guard = self.vault.lock().await;
        let vault = guard.as_mut().ok_or_else(crate::vault::vault_locked)?;
        let value = vault.credential_with_auth_kind(&name, expected_kind)?;
        Ok((expected_kind.to_string(), value))
    }

    async fn prepare(&self, spec: &ExecuteSpec) -> Result<PreparedExecution> {
        let config = Config::load(&self.paths.config)?;
        let target = resolve_target(&config, &spec.target)?;
        let is_profile = spec.profile.is_some();
        if is_profile && !spec.command.is_empty() {
            return Err(AppError::invalid_argument(
                "a profile cannot be combined with a raw remote command",
            ));
        }
        if spec.target.contains('\0') {
            return Err(AppError::invalid_argument("invalid target"));
        }
        if target.host.transport == TransportKind::Telnet {
            use crate::transport::Transport as _;
            return crate::transport::telnet::TelnetTransport
                .exec(ExecutionRequest {
                    host: target.host,
                    script: String::new(),
                    timeout: Duration::from_secs(1),
                    max_output: config.settings.max_output,
                    sudo_password: None,
                    auth_context: None,
                })
                .await
                .map(|_| {
                    unreachable!("Telnet execution currently always returns an explicit error")
                });
        }
        let operation = if is_profile { "profile" } else { "exec" };
        let script = match &spec.profile {
            Some(profile) => policy::profile_script(profile, &spec.profile_args)?,
            None => command_script(&spec.command, target.host.shell)?,
        };
        if target.host.shell != crate::config::ShellKind::Posix {
            return Err(AppError::new(
                ErrorCode::UnsupportedShell,
                "only POSIX shell non-interactive execution is implemented in this build",
            ));
        }
        let requires_approval = policy::evaluate(&target.host, &script, spec.sudo, is_profile)?;
        let script = with_cwd(&script, spec.cwd.as_deref(), target.host.shell)?;
        let timeout = Duration::from_secs(
            spec.timeout_seconds
                .unwrap_or(config.settings.timeout_seconds)
                .max(1),
        );
        let max_output = spec.max_output.unwrap_or(config.settings.max_output).max(1);
        let connection = host_identity(&target.host)?;
        let digest = request_digest(&[
            &target.alias,
            &connection,
            operation,
            &script,
            if spec.sudo { "sudo" } else { "no-sudo" },
            &timeout.as_secs().to_string(),
            &max_output.to_string(),
        ]);
        if requires_approval {
            self.approvals.require(&target.alias, operation, &digest)?;
        }
        let final_script = if spec.sudo {
            sudo_script(&script, target.host.shell)?
        } else {
            script
        };
        let sudo_password = if spec.sudo {
            let vault = self.vault.lock().await;
            Some(sudo::password_for(
                &target.alias,
                &target.host,
                vault.as_ref(),
            )?)
        } else {
            None
        };
        let auth_context = crate::transport::AuthenticationContext::registered(
            self.paths.clone(),
            &target.alias,
            &target.host,
        );
        Ok(PreparedExecution {
            alias: target.alias.clone(),
            host: target.host,
            script: final_script,
            timeout,
            max_output,
            sudo_password,
            digest,
            operation: operation.to_string(),
            auth_context,
        })
    }

    fn prepare_transfer(&self, spec: &TransferSpec) -> Result<PreparedTransfer> {
        let config = Config::load(&self.paths.config)?;
        let target = resolve_target(&config, &spec.target)?;
        if target.host.transport == TransportKind::Telnet {
            if !target.host.insecure_acknowledged {
                return Err(AppError::new(
                    ErrorCode::InsecureTransport,
                    "Telnet transfer is insecure and was not acknowledged",
                ));
            }
            return Err(AppError::new(
                ErrorCode::UnsupportedOperation,
                "file transfer is not supported over Telnet",
            ));
        }
        if spec.remote.is_empty() || spec.remote.contains(['\0', '\n', '\r']) {
            return Err(AppError::invalid_argument("invalid remote path"));
        }
        match (target.host.raw_mode, spec.upload) {
            (crate::config::RawMode::Deny, _) => {
                return Err(AppError::new(
                    ErrorCode::PolicyDenied,
                    "file transfer is denied for this host",
                ));
            }
            (crate::config::RawMode::ReadOnly, true) => {
                return Err(AppError::new(
                    ErrorCode::PolicyDenied,
                    "upload is denied by the read-only host policy",
                ));
            }
            _ => {}
        }
        crate::transport::validate_auth(&target.host)?;
        if target.host.auth == crate::config::AuthMode::ExternalAgent
            && !crate::transport::check_agent_available(&target.host)
        {
            return Err(AppError::new(
                ErrorCode::AgentIdentityUnavailable,
                "external SSH agent is unavailable",
            ));
        }
        let operation = if spec.upload { "put" } else { "get" };
        let overwrite = spec.overwrite || config.settings.allow_overwrite;
        let requires_approval = target.host.approval == crate::config::ApprovalMode::Always
            || (target.host.approval == crate::config::ApprovalMode::Writes
                && (spec.upload || overwrite));
        let timeout = Duration::from_secs(
            spec.timeout_seconds
                .unwrap_or(config.settings.timeout_seconds)
                .max(1),
        );
        let max_output = spec.max_output.unwrap_or(config.settings.max_output).max(1);
        let connection = host_identity(&target.host)?;
        let local = spec.local.to_string_lossy().into_owned();
        let digest = request_digest(&[
            &target.alias,
            &connection,
            operation,
            &local,
            &spec.remote,
            if overwrite {
                "overwrite"
            } else {
                "no-overwrite"
            },
        ]);
        if requires_approval {
            self.approvals.require(&target.alias, operation, &digest)?;
        }
        Ok(PreparedTransfer {
            alias: target.alias,
            host: target.host,
            local: spec.local.clone(),
            remote: spec.remote.clone(),
            upload: spec.upload,
            overwrite,
            timeout,
            max_output,
            operation: operation.into(),
            digest,
        })
    }

    pub async fn transfer(&self, spec: TransferSpec) -> OperationReport {
        let started = Instant::now();
        match self.prepare_transfer(&spec) {
            Err(error) => {
                let operation = if spec.upload { "put" } else { "get" };
                let digest = request_digest(&[&spec.target, operation, &spec.remote]);
                let report = OperationReport::new(Some(spec.target), operation)
                    .failed(&error)
                    .finish(started);
                audit_report(&self.audit, &report, digest, "ssh");
                report
            }
            Ok(prepared) => {
                let auth_context = crate::transport::AuthenticationContext::registered(
                    self.paths.clone(),
                    &prepared.alias,
                    &prepared.host,
                );
                let execution = if prepared.upload {
                    crate::transfer::put(
                        &prepared.host,
                        &prepared.local,
                        &prepared.remote,
                        prepared.overwrite,
                        prepared.timeout,
                        prepared.max_output,
                        auth_context.as_ref(),
                    )
                    .await
                } else {
                    crate::transfer::get(
                        &prepared.host,
                        &prepared.remote,
                        &prepared.local,
                        prepared.overwrite,
                        prepared.timeout,
                        prepared.max_output,
                        auth_context.as_ref(),
                    )
                    .await
                };
                let mut report =
                    OperationReport::new(Some(prepared.alias), prepared.operation.clone());
                report.decision = Decision::Allowed;
                match execution {
                    Ok(outcome) => {
                        report.remote_exit_code = Some(0);
                        report.status = OperationStatus::Success;
                        match serde_json::to_string(&outcome) {
                            Ok(value) => report.stdout = value,
                            Err(error) => {
                                let error =
                                    AppError::internal(format!("serialize transfer: {error}"));
                                report = report.failed(&error);
                            }
                        }
                    }
                    Err(error) => report = report.failed(&error),
                }
                report = report.finish(started);
                audit_report(&self.audit, &report, prepared.digest, "ssh");
                report
            }
        }
    }

    pub async fn execute(&self, spec: ExecuteSpec) -> OperationReport {
        let prepared = self.prepare(&spec).await;
        match prepared {
            Ok(prepared) => {
                execute_prepared(
                    prepared,
                    self.transport.clone(),
                    Arc::clone(&self.audit),
                    None,
                )
                .await
            }
            Err(error) => {
                let digest_input = spec.command.join("\u{1f}");
                let digest = request_digest(&[&spec.target, "exec", &digest_input]);
                let report = rejected_report(spec.target, "exec", error);
                let transport = Config::load(&self.paths.config)
                    .ok()
                    .and_then(|config| resolve_target(&config, report.host.as_deref()?).ok())
                    .map(|target| match target.host.transport {
                        TransportKind::Ssh => "ssh",
                        TransportKind::Telnet => "telnet",
                    })
                    .unwrap_or("unknown");
                audit_report(&self.audit, &report, digest, transport);
                report
            }
        }
    }

    pub async fn start_task(self: &Arc<Self>, spec: ExecuteSpec) -> Result<TaskSummary> {
        let prepared = self.prepare(&spec).await?;
        let host = prepared.alias.clone();
        let operation = prepared.operation.clone();
        let digest = prepared.digest.clone();
        let transport = self.transport.clone();
        let audit = Arc::clone(&self.audit);
        self.tasks
            .start(host, operation, digest, move |cancellation| async move {
                execute_prepared(prepared, transport, audit, Some(cancellation)).await
            })
    }

    pub fn tasks(&self) -> Result<Vec<TaskSummary>> {
        self.tasks.list()
    }

    pub fn task(&self, id: &str) -> Result<TaskSummary> {
        self.tasks.status(id)
    }

    pub fn task_logs(&self, id: &str) -> Result<(String, String)> {
        self.tasks.logs(id)
    }

    pub fn stop_task(&self, id: &str) -> Result<TaskSummary> {
        self.tasks.stop(id)
    }

    pub fn approvals(&self) -> Result<Vec<Approval>> {
        self.approvals.list()
    }

    pub fn approve(&self, id: &str) -> Result<Approval> {
        self.approvals.approve(id)
    }

    pub async fn start_tunnel(
        &self,
        target: &str,
        spec: TunnelSpec,
        confirm_public: bool,
    ) -> Result<TunnelSummary> {
        let config = Config::load(&self.paths.config)?;
        let target = resolve_target(&config, target)?;
        if target.host.raw_mode != crate::config::RawMode::Allow {
            return Err(AppError::new(
                ErrorCode::PolicyDenied,
                "tunnel creation requires raw_mode=allow for this host",
            ));
        }
        if spec.public_bind && !confirm_public {
            return Err(AppError::new(
                ErrorCode::PolicyDenied,
                "public/LAN tunnel binding requires explicit --yes confirmation",
            ));
        }
        let operation = "tunnel_start";
        let connection = host_identity(&target.host)?;
        let digest = request_digest(&[&target.alias, &connection, operation, &spec.argument]);
        if spec.dynamic || target.host.approval == crate::config::ApprovalMode::Always {
            self.approvals.require(&target.alias, operation, &digest)?;
        }
        crate::transport::validate_auth(&target.host)?;
        if target.host.auth == crate::config::AuthMode::ExternalAgent
            && !crate::transport::check_agent_available(&target.host)
        {
            return Err(AppError::new(
                ErrorCode::AgentIdentityUnavailable,
                "external SSH agent is unavailable",
            ));
        }
        let summary = self
            .tunnels
            .start(
                target.alias.clone(),
                &target.host,
                spec,
                crate::transport::AuthenticationContext::registered(
                    self.paths.clone(),
                    &target.alias,
                    &target.host,
                )
                .as_ref(),
            )
            .await?;
        let mut report = OperationReport::new(Some(target.alias), operation.to_string()).success();
        report.stdout = serde_json::to_string(&summary)
            .map_err(|e| AppError::internal(format!("serialize tunnel: {e}")))?;
        audit_report(&self.audit, &report, digest, "ssh");
        Ok(summary)
    }

    pub async fn tunnels(&self) -> Result<Vec<TunnelSummary>> {
        self.tunnels.list().await
    }

    pub async fn stop_tunnel(&self, id: &str) -> Result<TunnelSummary> {
        self.tunnels.stop(id).await
    }
}

async fn execute_prepared(
    prepared: PreparedExecution,
    transport: OpensshTransport,
    audit: Arc<AuditLog>,
    cancellation: Option<CancellationToken>,
) -> OperationReport {
    let started = Instant::now();
    let mut report = OperationReport::new(Some(prepared.alias.clone()), prepared.operation.clone());
    report.decision = Decision::Allowed;
    let request = ExecutionRequest {
        host: prepared.host.clone(),
        script: prepared.script.clone(),
        timeout: prepared.timeout,
        max_output: prepared.max_output,
        sudo_password: prepared
            .sudo_password
            .map(|password| password.as_str().to_string()),
        auth_context: prepared.auth_context,
    };
    let cancelled = cancellation
        .as_ref()
        .is_some_and(|token| token.is_cancelled());
    let execution = match cancellation {
        Some(token) => transport.exec_cancellable(request, token).await,
        None => crate::transport::Transport::exec(&transport, request).await,
    };
    match execution {
        Ok(outcome) => {
            report.remote_exit_code = outcome.exit_code;
            report.stdout = outcome.stdout.text;
            report.stderr = outcome.stderr.text;
            report.truncated = outcome.truncated;
            report.status = if outcome.exit_code == Some(0) {
                OperationStatus::Success
            } else {
                OperationStatus::Failed
            };
        }
        Err(error) => {
            if error.code == ErrorCode::ConnectionFailed && cancelled {
                report.status = OperationStatus::Disconnected;
            }
            report = report.failed(&error);
        }
    }
    report.duration_ms = started.elapsed().as_millis() as u64;
    audit_report(&audit, &report, prepared.digest, "ssh");
    report
}

fn rejected_report(target: String, operation: &str, error: AppError) -> OperationReport {
    OperationReport::new(Some(target), operation).failed(&error)
}

fn audit_report(audit: &AuditLog, report: &OperationReport, digest: String, transport: &str) {
    let event = AuditEvent {
        time: Utc::now(),
        request_id: report.request_id.clone(),
        host: report.host.clone().unwrap_or_default(),
        operation: report.operation.clone(),
        request_digest: digest,
        decision: format!("{:?}", report.decision).to_ascii_lowercase(),
        approval_id: report
            .error
            .as_ref()
            .and_then(|error| error.approval_id.clone()),
        status: format!("{:?}", report.status).to_ascii_lowercase(),
        exit_code: report.remote_exit_code,
        duration_ms: report.duration_ms,
        truncated: report.truncated,
        error: report
            .error
            .as_ref()
            .map(|error| format!("{:?}", error.code)),
        transport: transport.to_string(),
    };
    if let Err(error) = audit.append(&event) {
        eprintln!("Remxo could not append audit metadata: {}", error.message);
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BrokerEndpoint {
    pub address: String,
    pub token: String,
    pub pid: u32,
}

#[derive(Serialize, Deserialize)]
struct Call {
    token: String,
    request: RpcRequest,
}

#[derive(Serialize, Deserialize)]
struct RpcResponse {
    result: std::result::Result<RpcPayload, ErrorDetail>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RpcRequest {
    Ping,
    Shutdown,
    Status,
    Unlock {
        password: String,
    },
    Lock,
    ChangePassword {
        old: String,
        new: String,
    },
    SetCredential {
        name: String,
        kind: String,
        value: String,
    },
    ImportPrivateKey {
        name: String,
        path: std::path::PathBuf,
    },
    SecretForAuth {
        target: String,
        pending_host: Option<crate::config::Host>,
        private_key: bool,
    },
    Execute {
        spec: ExecuteSpec,
    },
    Transfer {
        spec: TransferSpec,
    },
    TaskStart {
        spec: ExecuteSpec,
    },
    TaskList,
    TaskStatus {
        id: String,
    },
    TaskLogs {
        id: String,
    },
    TaskStop {
        id: String,
    },
    ApprovalList,
    Approve {
        id: String,
    },
    TunnelStart {
        target: String,
        local: Option<String>,
        remote: Option<String>,
        dynamic: Option<u16>,
        confirm_public: bool,
    },
    TunnelList,
    TunnelStop {
        id: String,
    },
}

impl Drop for RpcRequest {
    fn drop(&mut self) {
        zeroize_request(self);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RpcPayload {
    Ack,
    Status(StatusReport),
    Report(OperationReport),
    Tasks(Vec<TaskSummary>),
    Task(TaskSummary),
    Logs { stdout: String, stderr: String },
    Approvals(Vec<Approval>),
    Approval(Approval),
    Tunnels(Vec<TunnelSummary>),
    Tunnel(TunnelSummary),
    Secret { kind: String, value: String },
}

#[cfg(unix)]
pub fn daemonize_broker(paths: &AppPaths) -> Result<AppPaths> {
    let root = std::fs::canonicalize(&paths.root)
        .map_err(|error| AppError::io("resolve broker working directory", error))?;
    let filename = paths
        .config
        .file_name()
        .ok_or_else(|| AppError::invalid_argument("broker config must be a file path"))?;
    let paths = AppPaths {
        config: root.join(filename),
        root: root.clone(),
    };
    daemonize::Daemonize::new()
        .working_directory(&root)
        .umask(0o077)
        .start()
        .map_err(|error| AppError::internal(format!("detach local broker: {error}")))?;
    Ok(paths)
}

pub async fn serve(paths: AppPaths) -> Result<()> {
    let broker = Broker::new(paths.clone())?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| AppError::io("bind local broker", e))?;
    let address = listener
        .local_addr()
        .map_err(|e| AppError::io("inspect broker address", e))?;
    let mut random = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
    let endpoint = BrokerEndpoint {
        address: address.to_string(),
        token: hex::encode(random),
        pid: std::process::id(),
    };
    let bytes = serde_json::to_vec(&endpoint)
        .map_err(|e| AppError::internal(format!("serialize broker endpoint: {e}")))?;
    crate::store::atomic_write(&paths.broker(), &bytes)?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| AppError::io("accept broker connection", e))?;
        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, broker).await {
                eprintln!("Remxo broker request failed: {}", error.message);
            }
        });
    }
}

const MAX_BROKER_REQUEST_BYTES: usize = 8 * 1_048_576;

async fn read_broker_request<R>(reader: R) -> Result<zeroize::Zeroizing<String>>
where
    R: AsyncRead + Unpin,
{
    let mut line = zeroize::Zeroizing::new(String::new());
    tokio::time::timeout(
        Duration::from_secs(10),
        BufReader::new(reader)
            .take((MAX_BROKER_REQUEST_BYTES + 1) as u64)
            .read_line(&mut line),
    )
    .await
    .map_err(|_| AppError::new(ErrorCode::Timeout, "broker request timed out"))?
    .map_err(|e| AppError::io("read broker request", e))?;
    if line.is_empty() || line.len() > MAX_BROKER_REQUEST_BYTES {
        return Err(AppError::invalid_argument(
            "empty or oversized broker request",
        ));
    }
    Ok(line)
}

async fn handle_connection(stream: TcpStream, broker: Arc<Broker>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let line = read_broker_request(read).await?;
    let mut call: Call = serde_json::from_str(&line)
        .map_err(|e| AppError::invalid_argument(format!("invalid broker request: {e}")))?;
    drop(line);
    let endpoint = read_endpoint(&broker.paths)?;
    let authenticated = call.token == endpoint.token;
    call.token.zeroize();
    if !authenticated {
        return Err(AppError::new(
            ErrorCode::PolicyDenied,
            "broker authentication failed",
        ));
    }
    let shutdown = matches!(&call.request, RpcRequest::Shutdown);
    let result = dispatch(&broker, &call.request)
        .await
        .map_err(|error| error.detail());
    zeroize_request(&mut call.request);
    let response = RpcResponse { result };
    let serialized = serde_json::to_vec(&response)
        .map_err(|e| AppError::internal(format!("serialize broker response: {e}")));
    let mut response = response;
    if let Ok(RpcPayload::Secret { value, .. }) = &mut response.result {
        value.zeroize();
    }
    let response = zeroize::Zeroizing::new(serialized?);
    write
        .write_all(&response)
        .await
        .map_err(|e| AppError::io("write broker response", e))?;
    write
        .write_all(b"\n")
        .await
        .map_err(|e| AppError::io("write broker response", e))?;
    if shutdown {
        let _ = write.shutdown().await;
        let _ = std::fs::remove_file(broker.paths.broker());
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            std::process::exit(0);
        });
    }
    Ok(())
}

fn zeroize_request(request: &mut RpcRequest) {
    match request {
        RpcRequest::Unlock { password } => password.zeroize(),
        RpcRequest::ChangePassword { old, new } => {
            old.zeroize();
            new.zeroize();
        }
        RpcRequest::SetCredential { value, .. } => value.zeroize(),
        _ => {}
    }
}

async fn dispatch(broker: &Arc<Broker>, request: &RpcRequest) -> Result<RpcPayload> {
    match request {
        RpcRequest::Ping => Ok(RpcPayload::Ack),
        RpcRequest::Shutdown => Ok(RpcPayload::Ack),
        RpcRequest::Status => Ok(RpcPayload::Status(broker.status().await?)),
        RpcRequest::Unlock { password } => {
            broker.unlock(password).await?;
            Ok(RpcPayload::Ack)
        }
        RpcRequest::Lock => {
            broker.lock().await;
            Ok(RpcPayload::Ack)
        }
        RpcRequest::ChangePassword { old, new } => {
            broker.change_password(old, new).await?;
            Ok(RpcPayload::Ack)
        }
        RpcRequest::SetCredential { name, kind, value } => {
            broker.set_credential(name, kind, value).await?;
            Ok(RpcPayload::Ack)
        }
        RpcRequest::ImportPrivateKey { name, path } => {
            broker.import_private_key(name, path).await?;
            Ok(RpcPayload::Ack)
        }
        RpcRequest::SecretForAuth {
            target,
            pending_host,
            private_key,
        } => {
            let (kind, value) = broker
                .credential_for_authentication(target, pending_host.as_ref(), *private_key)
                .await?;
            Ok(RpcPayload::Secret { kind, value })
        }
        RpcRequest::Execute { spec } => Ok(RpcPayload::Report(broker.execute(spec.clone()).await)),
        RpcRequest::Transfer { spec } => {
            Ok(RpcPayload::Report(broker.transfer(spec.clone()).await))
        }
        RpcRequest::TaskStart { spec } => {
            Ok(RpcPayload::Task(broker.start_task(spec.clone()).await?))
        }
        RpcRequest::TaskList => Ok(RpcPayload::Tasks(broker.tasks()?)),
        RpcRequest::TaskStatus { id } => Ok(RpcPayload::Task(broker.task(id)?)),
        RpcRequest::TaskLogs { id } => {
            let (stdout, stderr) = broker.task_logs(id)?;
            Ok(RpcPayload::Logs { stdout, stderr })
        }
        RpcRequest::TaskStop { id } => Ok(RpcPayload::Task(broker.stop_task(id)?)),
        RpcRequest::ApprovalList => Ok(RpcPayload::Approvals(broker.approvals()?)),
        RpcRequest::Approve { id } => Ok(RpcPayload::Approval(broker.approve(id)?)),
        RpcRequest::TunnelStart {
            target,
            local,
            remote,
            dynamic,
            confirm_public,
        } => {
            let selected = [local.is_some(), remote.is_some(), dynamic.is_some()]
                .into_iter()
                .filter(|selected| *selected)
                .count();
            if selected != 1 {
                return Err(AppError::invalid_argument(
                    "choose exactly one of --local, --remote, or --dynamic",
                ));
            }
            let spec = match (local, remote, dynamic) {
                (Some(value), None, None) => TunnelSpec::local(value)?,
                (None, Some(value), None) => TunnelSpec::remote(value)?,
                (None, None, Some(port)) => TunnelSpec::dynamic(*port)?,
                _ => return Err(AppError::invalid_argument("invalid tunnel selection")),
            };
            Ok(RpcPayload::Tunnel(
                broker.start_tunnel(target, spec, *confirm_public).await?,
            ))
        }
        RpcRequest::TunnelList => Ok(RpcPayload::Tunnels(broker.tunnels().await?)),
        RpcRequest::TunnelStop { id } => Ok(RpcPayload::Tunnel(broker.stop_tunnel(id).await?)),
    }
}

pub struct BrokerClient {
    paths: AppPaths,
}

#[cfg(windows)]
const DETACHED_BROKER_CREATION_FLAGS: u32 = 0x00000008 | 0x00000200 | 0x08000000;

#[cfg(windows)]
fn detach_broker_from_terminal(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(DETACHED_BROKER_CREATION_FLAGS);
}

impl BrokerClient {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub async fn ensure_running(&self) -> Result<()> {
        if self.ping().await.is_ok() {
            return Ok(());
        }
        let executable =
            std::env::current_exe().map_err(|e| AppError::io("locate Remxo executable", e))?;
        let mut daemon = std::process::Command::new(executable);
        daemon
            .arg("--config")
            .arg(&self.paths.config)
            .arg("__broker-daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        detach_broker_from_terminal(&mut daemon);
        daemon
            .spawn()
            .map_err(|e| AppError::io("start local broker", e))?;
        for _ in 0..100 {
            if self.ping().await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(AppError::new(
            ErrorCode::ConnectionFailed,
            "local broker did not become ready",
        ))
    }

    pub async fn ping(&self) -> Result<()> {
        match self.call(RpcRequest::Ping).await {
            Ok(RpcPayload::Ack) => Ok(()),
            Ok(_) => Err(AppError::internal("unexpected broker ping response")),
            Err(error) => Err(error),
        }
    }

    pub async fn call(&self, request: RpcRequest) -> Result<RpcPayload> {
        let endpoint = read_endpoint(&self.paths)?;
        let mut stream = tokio::time::timeout(
            Duration::from_millis(500),
            TcpStream::connect(&endpoint.address),
        )
        .await
        .map_err(|_| AppError::new(ErrorCode::ConnectionFailed, "broker connection timed out"))?
        .map_err(|e| {
            AppError::new(
                ErrorCode::ConnectionFailed,
                format!("connect to broker: {e}"),
            )
        })?;
        let call = zeroize::Zeroizing::new(
            serde_json::to_vec(&Call {
                token: endpoint.token,
                request,
            })
            .map_err(|e| AppError::internal(format!("serialize broker call: {e}")))?,
        );
        stream
            .write_all(&call)
            .await
            .map_err(|e| AppError::io("send broker request", e))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|e| AppError::io("send broker request", e))?;
        let (read, _) = stream.into_split();
        let mut line = String::new();
        BufReader::new(read)
            .read_line(&mut line)
            .await
            .map_err(|e| AppError::io("read broker response", e))?;
        if line.is_empty() || line.len() > 16 * 1024 * 1024 {
            return Err(AppError::new(
                ErrorCode::ConnectionFailed,
                "invalid broker response",
            ));
        }
        let response: RpcResponse = serde_json::from_str(&line)
            .map_err(|e| AppError::internal(format!("invalid broker response: {e}")))?;
        response.result.map_err(|detail| {
            let mut error = AppError::new(detail.code, detail.message);
            error.approval_id = detail.approval_id;
            error
        })
    }
}

fn read_endpoint(paths: &AppPaths) -> Result<BrokerEndpoint> {
    crate::store::require_private_file(&paths.broker())?;
    let bytes =
        std::fs::read(paths.broker()).map_err(|e| AppError::io("read broker endpoint", e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::invalid_argument(format!("invalid broker endpoint: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn broker_reader_enforces_its_limit_before_accepting_a_line() {
        let oversized = vec![b'x'; MAX_BROKER_REQUEST_BYTES + 1];
        let error = read_broker_request(oversized.as_slice()).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(!error.message.contains('x'));

        let error = read_broker_request(&b""[..]).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);

        let accepted = read_broker_request(&b"{\"method\":\"ping\"}\n"[..])
            .await
            .unwrap_or_else(|error| panic!("read: {error}"));
        assert_eq!(accepted.as_str(), "{\"method\":\"ping\"}\n");
    }

    #[cfg(windows)]
    #[test]
    fn broker_detaches_windows_console_and_process_group() {
        assert_eq!(DETACHED_BROKER_CREATION_FLAGS, 0x08000208);
    }
}
