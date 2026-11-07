use super::{
    Capabilities, ExecutionOutcome, ExecutionRequest, ProcessTermination, RawProcessOutput,
    Transport, check_agent_available, run_process, validate_auth,
};
use crate::config::{AuthMode, Host, TransportKind};
use crate::error::{AppError, ErrorCode, Result};
use crate::output::process_with_secrets;
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;
use tokio::process::Command;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone)]
pub struct OpensshTransport {
    ssh_binary: PathBuf,
}

impl Default for OpensshTransport {
    fn default() -> Self {
        Self {
            ssh_binary: std::env::var_os("REMXO_SSH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("ssh")),
        }
    }
}

const ASKPASS_CONFIG_ENV: &str = "REMXO_ASKPASS_CONFIG";
const ASKPASS_TARGET_ENV: &str = "REMXO_ASKPASS_TARGET";
const ASKPASS_PENDING_ENV: &str = "REMXO_ASKPASS_PENDING_HOST";

#[derive(Debug)]
pub(crate) struct ProcessAuthentication {
    arguments: Vec<String>,
    askpass: Option<AskpassEnvironment>,
    _managed_key: Option<crate::credential::TemporaryPrivateKey>,
}

#[derive(Debug)]
struct AskpassEnvironment {
    executable: PathBuf,
    config: PathBuf,
    target: String,
    pending_host: Option<String>,
}

impl ProcessAuthentication {
    pub fn apply(&self, command: &mut Command) {
        command.args(&self.arguments);
        if let Some(askpass) = &self.askpass {
            command
                .env("SSH_ASKPASS", &askpass.executable)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env(ASKPASS_CONFIG_ENV, &askpass.config)
                .env(ASKPASS_TARGET_ENV, &askpass.target)
                .env_remove(ASKPASS_PENDING_ENV);
            if let Some(pending_host) = &askpass.pending_host {
                command.env(ASKPASS_PENDING_ENV, pending_host);
            }
        }
    }

    pub fn apply_std(&self, command: &mut StdCommand) {
        command.args(&self.arguments);
        if let Some(askpass) = &self.askpass {
            command
                .env("SSH_ASKPASS", &askpass.executable)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env(ASKPASS_CONFIG_ENV, &askpass.config)
                .env(ASKPASS_TARGET_ENV, &askpass.target)
                .env_remove(ASKPASS_PENDING_ENV);
            if let Some(pending_host) = &askpass.pending_host {
                command.env(ASKPASS_PENDING_ENV, pending_host);
            }
        }
    }
}

pub(crate) async fn prepare_authentication(
    host: &Host,
    context: Option<&super::AuthenticationContext>,
    interactive: bool,
) -> Result<ProcessAuthentication> {
    let mut arguments = Vec::new();
    if matches!(host.auth, AuthMode::OpensshConfig | AuthMode::ExternalAgent) {
        if !interactive {
            arguments.extend(["-o".into(), "BatchMode=yes".into()]);
        }
        return Ok(ProcessAuthentication {
            arguments,
            askpass: None,
            _managed_key: None,
        });
    }
    let context = context.ok_or_else(|| {
        AppError::new(
            ErrorCode::UnsupportedOperation,
            "vault-managed SSH authentication requires an active Broker and an unlocked Vault",
        )
    })?;
    if context
        .pending_host
        .as_ref()
        .is_some_and(|pending| pending.auth != host.auth)
    {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "SSH authentication context does not match the host authentication mode",
        ));
    }
    let pending_host = context
        .pending_host
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| {
            AppError::internal(format!("serialize pending authentication host: {error}"))
        })?;
    let executable = std::env::current_exe()
        .map_err(|error| AppError::io("locate Remxo askpass helper", error))?;
    let askpass = AskpassEnvironment {
        executable,
        config: context.paths.config.clone(),
        target: context.alias.clone(),
        pending_host,
    };
    arguments.extend([
        "-o".into(),
        "BatchMode=no".into(),
        "-o".into(),
        "NumberOfPasswordPrompts=1".into(),
    ]);
    let mut managed_key = None;
    match host.auth {
        AuthMode::VaultPassword => arguments.extend([
            "-o".into(),
            "PreferredAuthentications=password".into(),
            "-o".into(),
            "PubkeyAuthentication=no".into(),
            "-o".into(),
            "PasswordAuthentication=yes".into(),
            "-o".into(),
            "KbdInteractiveAuthentication=no".into(),
        ]),
        AuthMode::VaultKey => {
            let key = materialize_key(context).await?;
            arguments.extend([
                "-i".into(),
                key.path().to_string_lossy().into_owned(),
                "-o".into(),
                "IdentitiesOnly=yes".into(),
                "-o".into(),
                "IdentityAgent=none".into(),
                "-o".into(),
                "PreferredAuthentications=publickey".into(),
                "-o".into(),
                "PubkeyAuthentication=yes".into(),
                "-o".into(),
                "PasswordAuthentication=no".into(),
                "-o".into(),
                "KbdInteractiveAuthentication=no".into(),
            ]);
            managed_key = Some(key);
        }
        AuthMode::OpensshConfig | AuthMode::ExternalAgent => {
            return Err(AppError::internal(
                "unreachable external authentication branch",
            ));
        }
    }
    Ok(ProcessAuthentication {
        arguments,
        askpass: Some(askpass),
        _managed_key: managed_key,
    })
}

impl OpensshTransport {
    pub fn with_binary(binary: PathBuf) -> Self {
        Self { ssh_binary: binary }
    }

    pub fn binary(&self) -> &PathBuf {
        &self.ssh_binary
    }

    pub fn base_arguments(
        &self,
        host: &Host,
        batch: bool,
        timeout: Duration,
    ) -> Result<Vec<String>> {
        host.validate("connection")?;
        if host.transport != TransportKind::Ssh {
            return Err(AppError::invalid_argument(
                "OpenSSH transport requires an SSH host",
            ));
        }
        let mut arguments = Vec::new();
        if batch {
            arguments.extend([
                "-o".into(),
                format!("ConnectTimeout={}", timeout.as_secs().max(1)),
                "-T".into(),
            ]);
        }
        if host.ssh_alias.is_none() {
            arguments.extend(["-p".into(), host.port.to_string()]);
        }
        arguments.push(host.destination());
        Ok(arguments)
    }

    async fn execute(
        &self,
        request: ExecutionRequest,
        agent_available: bool,
        cancellation: Option<tokio_util::sync::CancellationToken>,
    ) -> Result<ExecutionOutcome> {
        if matches!(
            request.host.auth,
            crate::config::AuthMode::VaultPassword | crate::config::AuthMode::VaultKey
        ) {
            if request.host.shell != crate::config::ShellKind::Posix {
                return Err(AppError::new(
                    ErrorCode::UnsupportedShell,
                    "Vault-managed authentication currently requires POSIX shell",
                ));
            }
            if request.auth_context.is_none() {
                return Err(AppError::new(
                    ErrorCode::UnsupportedOperation,
                    "vault-managed SSH authentication requires an active Broker and an unlocked Vault",
                ));
            }
        }
        validate_auth(&request.host)?;
        if request.host.auth == crate::config::AuthMode::ExternalAgent && !agent_available {
            return Err(AppError::new(
                ErrorCode::AgentIdentityUnavailable,
                "external SSH agent is unavailable or has no usable socket; a human must unlock/configure it",
            ));
        }
        let mut arguments = self.base_arguments(&request.host, true, request.timeout)?;
        let destination = arguments
            .pop()
            .ok_or_else(|| AppError::internal("missing SSH destination"))?;
        let mut command = Command::new(&self.ssh_binary);
        let authentication =
            prepare_authentication(&request.host, request.auth_context.as_ref(), false).await?;
        authentication.apply(&mut command);
        arguments.push(destination);
        command.args(arguments).arg(request.script);
        let raw_limit = request.max_output.saturating_mul(4).min(64 * 1024 * 1024);
        let stdin_password = request.sudo_password.map(Zeroizing::new);
        let stdin = stdin_password.as_ref().map(|password| {
            let mut bytes = password.as_bytes().to_vec();
            bytes.push(b'\n');
            Zeroizing::new(bytes)
        });
        let raw = run_process(
            &mut command,
            request.timeout,
            raw_limit,
            stdin,
            cancellation,
        )
        .await?;
        self.convert_output(
            raw,
            request.max_output,
            stdin_password.as_ref().map(|password| password.as_str()),
        )
    }

    fn convert_output(
        &self,
        raw: RawProcessOutput,
        max_output: usize,
        sudo_password: Option<&str>,
    ) -> Result<ExecutionOutcome> {
        match raw.termination {
            ProcessTermination::TimedOut => {
                return Err(AppError::new(
                    ErrorCode::Timeout,
                    "remote operation exceeded its timeout; no automatic retry was attempted",
                ));
            }
            ProcessTermination::Cancelled => {
                return Err(AppError::new(
                    ErrorCode::ConnectionFailed,
                    "local SSH was stopped; remote execution state is unknown and must be verified",
                ));
            }
            ProcessTermination::Exited => {}
        }
        let secrets = sudo_password.into_iter().collect::<Vec<_>>();
        let stdout = process_with_secrets(&raw.stdout, max_output, raw.stdout_truncated, &secrets);
        let stderr = process_with_secrets(&raw.stderr, max_output, raw.stderr_truncated, &secrets);
        let truncated = stdout.truncated || stderr.truncated;
        if raw.stdout_truncated || raw.stderr_truncated {
            return Err(AppError::new(
                ErrorCode::OutputLimit,
                "raw command output exceeded the configured safety limit",
            ));
        }
        if raw.exit_code == Some(255) {
            return Err(classify_ssh_failure(&stderr.text));
        }
        if sudo_password.is_some() && raw.exit_code.is_some_and(|code| code != 0) {
            let lower = stderr.text.to_ascii_lowercase();
            if lower.contains("not in the sudoers")
                || lower.contains("not allowed to execute")
                || lower.contains("a terminal is required")
                || lower.contains("no tty present")
                || lower.contains("a password is required")
                || lower.contains("sorry, try again")
            {
                return Err(AppError::new(
                    ErrorCode::SudoNotPermitted,
                    "remote sudo was not permitted; check least-privilege sudoers, authentication, and requiretty policy. No password retry was attempted",
                ));
            }
        }
        Ok(ExecutionOutcome {
            exit_code: raw.exit_code,
            stdout,
            stderr,
            truncated,
        })
    }

    pub async fn exec_with_agent_check(
        &self,
        request: ExecutionRequest,
        agent_available: bool,
    ) -> Result<ExecutionOutcome> {
        self.execute(request, agent_available, None).await
    }

    pub async fn exec_cancellable(
        &self,
        request: ExecutionRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<ExecutionOutcome> {
        let agent_available = check_agent_available(&request.host);
        self.execute(request, agent_available, Some(cancellation))
            .await
    }
    pub async fn interactive_authenticated(
        &self,
        host: &Host,
        context: Option<&super::AuthenticationContext>,
    ) -> Result<i32> {
        if host.auth == crate::config::AuthMode::ExternalAgent && !check_agent_available(host) {
            return Err(AppError::new(
                ErrorCode::AgentUnavailable,
                "external SSH agent is unavailable",
            ));
        }
        let authentication = prepare_authentication(host, context, true).await?;
        let arguments = self.base_arguments(host, false, Duration::from_secs(30))?;
        let mut command = StdCommand::new(&self.ssh_binary);
        authentication.apply_std(&mut command);
        let status = command
            .args(arguments)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| AppError::io("start interactive OpenSSH", e))?;
        Ok(status.code().unwrap_or(1))
    }
}

#[async_trait]
impl Transport for OpensshTransport {
    fn capabilities(&self, _host: &Host) -> Capabilities {
        Capabilities {
            exec: true,
            interactive: true,
            transfer: true,
            tunnel: true,
            encrypted: true,
        }
    }

    async fn exec(&self, request: ExecutionRequest) -> Result<ExecutionOutcome> {
        let agent_available = check_agent_available(&request.host);
        self.execute(request, agent_available, None).await
    }

    fn interactive(&self, host: &Host) -> Result<i32> {
        if matches!(
            host.auth,
            crate::config::AuthMode::VaultKey | crate::config::AuthMode::VaultPassword
        ) {
            return Err(AppError::new(
                ErrorCode::UnsupportedOperation,
                "Vault authentication requires interactive_authenticated with a Broker authentication context",
            ));
        }
        if host.auth == crate::config::AuthMode::ExternalAgent && !check_agent_available(host) {
            return Err(AppError::new(
                ErrorCode::AgentUnavailable,
                "external SSH agent is unavailable",
            ));
        }
        let arguments = self.base_arguments(host, false, Duration::from_secs(30))?;
        let status = StdCommand::new(&self.ssh_binary)
            .args(arguments)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| AppError::io("start interactive OpenSSH", e))?;
        Ok(status.code().unwrap_or(1))
    }
}

async fn materialize_key(
    context: &super::AuthenticationContext,
) -> Result<crate::credential::TemporaryPrivateKey> {
    let client = crate::broker::BrokerClient::new(context.paths.clone());
    let payload = client
        .call(crate::broker::RpcRequest::SecretForAuth {
            target: context.alias.clone(),
            pending_host: context.pending_host.clone(),
            private_key: true,
        })
        .await?;
    let crate::broker::RpcPayload::Secret { kind, mut value } = payload else {
        return Err(AppError::new(
            ErrorCode::InternalError,
            "unexpected response while obtaining vault private key",
        ));
    };
    if kind != crate::credential::SSH_PRIVATE_KEY_KIND {
        value.zeroize();
        return Err(AppError::new(
            ErrorCode::AuthenticationFailed,
            "the selected credential is not a Vault-managed OpenSSH private key",
        ));
    }
    crate::credential::TemporaryPrivateKey::create(
        context.paths.root.join("runtime").as_path(),
        Zeroizing::new(value).as_str(),
    )
}

fn classify_ssh_failure(stderr: &str) -> AppError {
    let lower = stderr.to_ascii_lowercase();
    let code = if lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
        || lower.contains("no hostkey alg")
    {
        ErrorCode::HostKeyFailed
    } else if lower.contains("permission denied") || lower.contains("authentication failed") {
        ErrorCode::AuthenticationFailed
    } else {
        ErrorCode::ConnectionFailed
    };
    let message = match code {
        ErrorCode::HostKeyFailed => {
            "OpenSSH host key verification failed. Remxo never disables host key checks; a human must verify the host key."
                .to_string()
        }
        ErrorCode::AuthenticationFailed => {
            "OpenSSH authentication failed. Remxo does not retry or request credentials from an agent."
                .to_string()
        }
        _ => format!("OpenSSH connection failed: {}", stderr.trim()),
    };
    AppError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, Host};
    #[cfg(unix)]
    use std::fs;

    fn host(auth: AuthMode) -> Host {
        Host {
            number: Some(2),
            transport: TransportKind::Ssh,
            ssh_alias: Some("test-alias".into()),
            hostname: None,
            port: 22,
            username: None,
            platform: crate::config::Platform::Linux,
            shell: crate::config::ShellKind::Posix,
            auth,
            environment: "test".into(),
            tags: Vec::new(),
            raw_mode: crate::config::RawMode::Allow,
            approval: crate::config::ApprovalMode::Never,
            insecure_acknowledged: false,
            sudo_credential: None,
            credential: None,
            prompt: None,
        }
    }

    #[cfg(unix)]
    fn fake_ssh(script: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("fake-ssh");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap_or_else(|e| panic!("fake: {e}"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
        (directory, path)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_ssh_receives_safe_argv_and_no_host_key_bypass() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let log = directory.path().join("argv");
        let binary = directory.path().join("fake-ssh");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'stdout'\nprintf 'stderr' >&2\n",
                log.display()
            ),
        )
        .unwrap_or_else(|e| panic!("fake: {e}"));
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
        let transport = OpensshTransport::with_binary(binary);
        let output = transport
            .exec_with_agent_check(
                ExecutionRequest {
                    host: host(AuthMode::OpensshConfig),
                    script: "'printf' '%s' 'x; touch /tmp/nope'".into(),
                    timeout: Duration::from_secs(2),
                    max_output: 1024,
                    sudo_password: None,
                    auth_context: None,
                },
                true,
            )
            .await
            .unwrap_or_else(|e| panic!("exec: {e}"));
        assert_eq!(output.stdout.text, "stdout");
        assert_eq!(output.stderr.text, "stderr");
        let argv = fs::read_to_string(log).unwrap_or_default();
        assert!(argv.contains("BatchMode=yes"));
        assert!(argv.contains("test-alias"));
        assert!(argv.contains("'printf' '%s' 'x; touch /tmp/nope'"));
        assert!(!argv.contains("StrictHostKeyChecking=no"));
        assert!(!argv.contains("UserKnownHostsFile=/dev/null"));
        assert!(!argv.contains("ForwardAgent=yes"));
        assert!(!argv.contains(" -c\n"));
    }

    #[tokio::test]
    async fn unavailable_external_agent_has_a_distinct_error() {
        let transport = OpensshTransport::with_binary(PathBuf::from("not-started"));
        let error = transport
            .exec_with_agent_check(
                ExecutionRequest {
                    host: host(AuthMode::ExternalAgent),
                    script: "true".into(),
                    timeout: Duration::from_secs(1),
                    max_output: 1024,
                    sudo_password: None,
                    auth_context: None,
                },
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::AgentIdentityUnavailable);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_timeout_kills_the_local_process() {
        let (_guard, binary) = fake_ssh("sleep 5");
        let transport = OpensshTransport::with_binary(binary);
        let error = transport
            .exec_with_agent_check(
                ExecutionRequest {
                    host: host(AuthMode::OpensshConfig),
                    script: "sleep 5".into(),
                    timeout: Duration::from_millis(100),
                    max_output: 1024,
                    sudo_password: None,
                    auth_context: None,
                },
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Timeout);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sudo_secret_uses_stdin_and_is_scrubbed_from_all_returned_output() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let argv_log = directory.path().join("argv");
        let binary = directory.path().join("fake-sudo-ssh");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nIFS= read -r secret\nprintf 'display:%s\\n' \"$secret\"\nprintf 'error:%s\\n' \"$secret\" >&2\n",
                argv_log.display()
            ),
        )
        .unwrap_or_else(|e| panic!("fake: {e}"));
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
        let transport = OpensshTransport::with_binary(binary);
        let output = transport
            .exec_with_agent_check(
                ExecutionRequest {
                    host: host(AuthMode::OpensshConfig),
                    script: "sudo -S -p '' -- /bin/sh -c 'id'".into(),
                    timeout: Duration::from_secs(2),
                    max_output: 4096,
                    sudo_password: Some("test-only-sudo-secret-value".into()),
                    auth_context: None,
                },
                true,
            )
            .await
            .unwrap_or_else(|e| panic!("exec: {e}"));
        for returned in [&output.stdout.text, &output.stderr.text] {
            assert!(!returned.contains("test-only-sudo-secret-value"));
            assert!(returned.contains("REDACTED SUDO PASSWORD"));
        }
        let argv = fs::read_to_string(argv_log).unwrap_or_default();
        assert!(!argv.contains("test-only-sudo-secret-value"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sudo_policy_failure_has_a_stable_error_and_no_retry() {
        let (_guard, binary) =
            fake_ssh("IFS= read -r secret\nprintf 'user is not in the sudoers file' >&2\nexit 1");
        let transport = OpensshTransport::with_binary(binary);
        let error = transport
            .exec_with_agent_check(
                ExecutionRequest {
                    host: host(AuthMode::OpensshConfig),
                    script: "sudo -S -p '' -- /bin/sh -c 'id'".into(),
                    timeout: Duration::from_secs(2),
                    max_output: 1024,
                    sudo_password: Some("test-only-sudo-password".into()),
                    auth_context: None,
                },
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::SudoNotPermitted);
        assert!(!error.message.contains("test-only-sudo-password"));
    }

    #[test]
    fn host_key_failure_is_not_downgraded() {
        assert_eq!(
            classify_ssh_failure("Host key verification failed.").code,
            ErrorCode::HostKeyFailed
        );
    }
}
