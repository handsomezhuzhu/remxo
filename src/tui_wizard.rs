use crate::audit::{AuditEvent, AuditLog, request_digest};
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{
    AppPaths, ApprovalMode, AuthMode, Host, Platform, RawMode, ShellKind, TransportKind,
};
use crate::error::{AppError, Result};
use crate::transport::openssh::OpensshTransport;
use crate::transport::{ExecutionRequest, Transport as _, check_agent_available};
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use std::io::{Stdout, stdout};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionMode {
    OpenSshAlias,
    DirectSsh,
    Telnet,
}

impl ConnectionMode {
    fn next(self, direction: i32) -> Self {
        match (self, direction) {
            (Self::OpenSshAlias, 1) | (Self::Telnet, -1) => Self::DirectSsh,
            (Self::DirectSsh, 1) | (Self::OpenSshAlias, -1) => Self::Telnet,
            (Self::Telnet, 1) | (Self::DirectSsh, -1) => Self::OpenSshAlias,
            _ => self,
        }
    }

    fn transport(self) -> TransportKind {
        match self {
            Self::OpenSshAlias | Self::DirectSsh => TransportKind::Ssh,
            Self::Telnet => TransportKind::Telnet,
        }
    }

    fn label(self, language: crate::config::UiLanguage) -> &'static str {
        match self {
            Self::OpenSshAlias => language.text("OpenSSH Host alias", "OpenSSH 主机别名"),
            Self::DirectSsh => language.text("Direct hostname / IP", "直接主机名 / IP"),
            Self::Telnet => language.text("Telnet (INSECURE)", "Telnet（不安全）"),
        }
    }
}

struct Draft {
    alias: String,
    mode: ConnectionMode,
    address: String,
    username: String,
    port: String,
    number: String,
    auth: AuthMode,
    ssh_password: Option<Zeroizing<String>>,
    private_key_path: String,
    environment: String,
    tags: Vec<String>,
    platform: Platform,
    raw_mode: RawMode,
    approval: ApprovalMode,
    configure_sudo: bool,
    insecure_acknowledged: bool,
}

impl Draft {
    fn new(alias: Option<String>, initial: Option<Host>, config: &crate::config::Config) -> Self {
        let next_number = config
            .hosts
            .values()
            .filter_map(|host| host.number)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1);
        let initial = initial.unwrap_or_default();
        let tags = initial.tags.clone();
        let mode = match initial.transport {
            TransportKind::Ssh if initial.ssh_alias.is_some() => ConnectionMode::OpenSshAlias,
            TransportKind::Ssh => ConnectionMode::DirectSsh,
            TransportKind::Telnet => ConnectionMode::Telnet,
        };
        Self {
            alias: alias.unwrap_or_else(|| "prod-01".into()),
            mode,
            address: initial.ssh_alias.or(initial.hostname).unwrap_or_default(),
            username: initial.username.unwrap_or_default(),
            port: initial.port.to_string(),
            number: initial.number.unwrap_or(next_number).to_string(),
            auth: initial.auth,
            ssh_password: None,
            private_key_path: String::new(),
            environment: if initial.environment.is_empty() {
                "development".into()
            } else {
                initial.environment
            },
            tags,
            platform: initial.platform,
            raw_mode: initial.raw_mode,
            approval: initial.approval,
            configure_sudo: initial.sudo_credential.is_some(),
            insecure_acknowledged: initial.insecure_acknowledged,
        }
    }

    fn host(&self) -> Result<(String, Host)> {
        let alias = self.alias.trim();
        if alias.is_empty() {
            return Err(AppError::invalid_argument("alias is required"));
        }
        if self.address.trim().is_empty() {
            return Err(AppError::invalid_argument(
                "an OpenSSH alias or hostname is required before testing or saving",
            ));
        }
        match self.auth {
            AuthMode::VaultPassword => {
                if self
                    .ssh_password
                    .as_ref()
                    .is_none_or(|value| value.is_empty())
                {
                    return Err(AppError::invalid_argument(
                        "selecting Vault SSH password requires a non-empty password entered through the hidden field",
                    ));
                }
            }
            AuthMode::VaultKey => {
                if self.private_key_path.trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "selecting Vault private key requires a private key file path (not the .pub file)",
                    ));
                }
            }
            AuthMode::OpensshConfig | AuthMode::ExternalAgent => {
                if self.ssh_password.is_some() || !self.private_key_path.trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "choose Vault SSH password or Vault private key before importing credentials; no secret was saved",
                    ));
                }
            }
        }
        if self.mode == ConnectionMode::Telnet
            && (self.ssh_password.is_some() || !self.private_key_path.trim().is_empty())
        {
            return Err(AppError::invalid_argument(
                "SSH password/private-key import is available only for SSH hosts, not Telnet",
            ));
        }
        let port = self
            .port
            .parse::<u16>()
            .map_err(|_| AppError::invalid_argument("port must be an integer from 1 to 65535"))?;
        let number = self
            .number
            .parse::<u32>()
            .map_err(|_| AppError::invalid_argument("host number must be a positive integer"))?;
        let (ssh_alias, hostname, shell) = match self.mode {
            ConnectionMode::OpenSshAlias => {
                (Some(self.address.trim().to_string()), None, self.shell())
            }
            ConnectionMode::DirectSsh | ConnectionMode::Telnet => {
                (None, Some(self.address.trim().to_string()), self.shell())
            }
        };
        let host = Host {
            number: Some(number),
            transport: self.mode.transport(),
            ssh_alias,
            hostname,
            port,
            username: (!self.username.trim().is_empty()).then(|| self.username.trim().to_string()),
            platform: self.platform,
            shell,
            auth: self.auth,
            environment: self.environment.trim().to_string(),
            tags: self.tags.clone(),
            raw_mode: self.raw_mode,
            approval: self.approval,
            insecure_acknowledged: self.insecure_acknowledged,
            sudo_credential: self
                .configure_sudo
                .then(|| crate::credential::sudo_credential_name(alias)),
            credential: matches!(self.auth, AuthMode::VaultPassword | AuthMode::VaultKey)
                .then(|| alias.to_string()),
            prompt: None,
        };
        host.validate(alias)?;
        if host.transport == TransportKind::Telnet && !host.insecure_acknowledged {
            return Err(AppError::invalid_argument(
                "Telnet sends credentials and commands without encryption. Enable 'Acknowledge insecure Telnet' only if you accept that risk",
            ));
        }
        Ok((alias.to_string(), host))
    }

    fn shell(&self) -> ShellKind {
        match self.platform {
            Platform::Windows => ShellKind::Powershell,
            Platform::Other => ShellKind::Custom,
            _ => ShellKind::Posix,
        }
    }

    fn value(&self, index: usize, language: crate::config::UiLanguage) -> String {
        match index {
            0 => self.alias.clone(),
            1 => self.mode.label(language).into(),
            2 => self.address.clone(),
            3 => self.username.clone(),
            4 => self.port.clone(),
            5 => match self.auth {
                AuthMode::OpensshConfig => language
                    .text(
                        "OpenSSH config / interactive login",
                        "OpenSSH 配置 / 交互登录",
                    )
                    .into(),
                AuthMode::ExternalAgent => {
                    language.text("External SSH agent", "外部 SSH Agent").into()
                }
                AuthMode::VaultPassword => {
                    language.text("Vault SSH password", "Vault SSH 密码").into()
                }
                AuthMode::VaultKey => language
                    .text("Vault-managed private key", "Vault 管理的私钥")
                    .into(),
            },
            6 => self.number.clone(),
            7 => self.environment.clone(),
            8 => format!("{:?}", self.platform).to_ascii_lowercase(),
            9 => match self.raw_mode {
                RawMode::Allow => language.text("allow raw commands", "允许原始命令").into(),
                RawMode::ReadOnly => language.text("read-only profiles", "只读配置").into(),
                RawMode::Deny => language.text("deny execution", "拒绝执行").into(),
            },
            10 => match self.approval {
                ApprovalMode::Never => language.text("never", "从不").into(),
                ApprovalMode::Writes => language
                    .text("writes and unknown commands", "写入及未知命令")
                    .into(),
                ApprovalMode::Always => language.text("always", "总是").into(),
            },
            11 => yes_no(self.configure_sudo, language),
            12 => yes_no(self.insecure_acknowledged, language),
            13 => self
                .ssh_password
                .as_ref()
                .filter(|password| !password.is_empty())
                .map(|_| language.text("entered (hidden)", "已输入（隐藏）").into())
                .unwrap_or_else(|| language.text("not set", "未输入").into()),
            14 => self.private_key_path.clone(),
            _ => String::new(),
        }
    }

    fn change(&mut self, index: usize, direction: i32) {
        match index {
            1 => self.mode = self.mode.next(direction),
            5 => {
                self.auth = match self.auth {
                    AuthMode::OpensshConfig => AuthMode::ExternalAgent,
                    AuthMode::ExternalAgent => AuthMode::VaultPassword,
                    AuthMode::VaultPassword => AuthMode::VaultKey,
                    AuthMode::VaultKey => AuthMode::OpensshConfig,
                };
            }
            8 => {
                self.platform = match (self.platform, direction) {
                    (Platform::Linux, 1) | (Platform::Windows, -1) => Platform::Macos,
                    (Platform::Macos, 1) | (Platform::Linux, -1) => Platform::Windows,
                    (Platform::Windows, 1) | (Platform::Macos, -1) => Platform::Linux,
                    _ => Platform::Linux,
                }
            }
            9 => {
                self.raw_mode = match (self.raw_mode, direction) {
                    (RawMode::Allow, 1) | (RawMode::Deny, -1) => RawMode::ReadOnly,
                    (RawMode::ReadOnly, 1) | (RawMode::Allow, -1) => RawMode::Deny,
                    (RawMode::Deny, 1) | (RawMode::ReadOnly, -1) => RawMode::Allow,
                    _ => RawMode::Allow,
                }
            }
            10 => {
                self.approval = match (self.approval, direction) {
                    (ApprovalMode::Never, 1) | (ApprovalMode::Always, -1) => ApprovalMode::Writes,
                    (ApprovalMode::Writes, 1) | (ApprovalMode::Never, -1) => ApprovalMode::Always,
                    (ApprovalMode::Always, 1) | (ApprovalMode::Writes, -1) => ApprovalMode::Never,
                    _ => ApprovalMode::Never,
                }
            }
            11 => self.configure_sudo = !self.configure_sudo,
            12 => self.insecure_acknowledged = !self.insecure_acknowledged,
            _ => {}
        }
    }

    fn type_character(&mut self, index: usize, character: char) {
        if index == 13 {
            if self.ssh_password.is_none() {
                self.ssh_password = Some(Zeroizing::new(String::new()));
            }
            if let Some(password) = self.ssh_password.as_mut()
                && password.len() + character.len_utf8() <= 4096
            {
                password.push(character);
            }
            return;
        }
        if index == 14 {
            if self.private_key_path.chars().count() < 512 {
                self.private_key_path.push(character);
            }
            return;
        }
        let target = match index {
            0 => &mut self.alias,
            2 => &mut self.address,
            3 => &mut self.username,
            4 if character.is_ascii_digit() => &mut self.port,
            6 if character.is_ascii_digit() => &mut self.number,
            7 => &mut self.environment,
            4 | 6 => return,
            _ => return,
        };
        if target.chars().count() < 256 {
            target.push(character);
        }
    }

    fn backspace(&mut self, index: usize) {
        if index == 13 {
            if let Some(password) = self.ssh_password.as_mut() {
                password.pop();
            }
            return;
        }
        if index == 14 {
            self.private_key_path.pop();
            return;
        }
        let target = match index {
            0 => &mut self.alias,
            2 => &mut self.address,
            3 => &mut self.username,
            4 => &mut self.port,
            6 => &mut self.number,
            7 => &mut self.environment,
            _ => return,
        };
        target.pop();
    }

    fn clear(&mut self, index: usize) {
        if index == 13 {
            self.ssh_password = None;
            return;
        }
        if index == 14 {
            self.private_key_path.clear();
            return;
        }
        let target = match index {
            0 => &mut self.alias,
            2 => &mut self.address,
            3 => &mut self.username,
            4 => &mut self.port,
            6 => &mut self.number,
            7 => &mut self.environment,
            _ => return,
        };
        target.clear();
    }
}

fn yes_no(value: bool, language: crate::config::UiLanguage) -> String {
    language
        .text(
            if value { "yes" } else { "no" },
            if value { "是" } else { "否" },
        )
        .into()
}

#[derive(Debug)]
pub struct WizardResult {
    pub saved_alias: Option<String>,
    pub message: String,
}

struct Wizard {
    draft: Draft,
    focused: usize,
    message: String,
    failed: bool,
    tested: bool,
    no_color: bool,
    language: crate::config::UiLanguage,
    result: Option<WizardResult>,
    client: BrokerClient,
}

impl Wizard {
    fn new(
        paths: &AppPaths,
        alias: Option<String>,
        initial: Option<Host>,
        no_color: bool,
    ) -> Result<Self> {
        let config = crate::config::Config::load(&paths.config)?;
        let language = config.settings.language;
        Ok(Self {
            client: BrokerClient::new(paths.clone()),
            draft: Draft::new(alias, initial, &config),
            focused: 0,
            message: language
                .text(
                    "Complete fields. Enter moves through Connection → Policy → Review; Esc discards changes.",
                    "请填写字段。Enter 依次进入连接、策略和复核；Esc 放弃更改。",
                )
                .into(),
            failed: false,
            tested: false,
            no_color,
            language,
            result: None,
        })
    }

    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => {
                self.result = Some(WizardResult {
                    saved_alias: None,
                    message: self
                        .language
                        .text(
                            "Host creation cancelled. No host configuration was saved; credentials imported during testing or saving remain encrypted in Vault.",
                            "已取消添加主机，未保存主机配置；测试或保存过程中已导入的凭据仍以密文保留在 Vault 中。",
                        )
                        .into(),
                });
            }
            KeyCode::Up => self.focused = self.focused.saturating_sub(1),
            KeyCode::Down => self.focused = (self.focused + 1).min(16),
            KeyCode::Left => self.draft.change(self.focused, -1),
            KeyCode::Right => self.draft.change(self.focused, 1),
            KeyCode::Char(' ') if matches!(self.focused, 1 | 5 | 8 | 9 | 10 | 11 | 12) => {
                self.draft.change(self.focused, 1)
            }
            KeyCode::Backspace => self.draft.backspace(self.focused),
            KeyCode::Delete => self.draft.clear(self.focused),
            KeyCode::Char(character) => self.draft.type_character(self.focused, character),
            KeyCode::Tab => self.focused = (self.focused + 1).min(16),
            KeyCode::BackTab => self.focused = self.focused.saturating_sub(1),
            KeyCode::Enter => {
                if self.focused < 6 {
                    self.focused = 6;
                } else if self.focused < 15 {
                    self.focused = 15;
                }
            }
            _ => {}
        }
    }

    fn action(&mut self) -> Action {
        match self.focused {
            15 => Action::Test,
            16 => Action::Save,
            _ => Action::None,
        }
    }
}

enum Action {
    None,
    Test,
    Save,
}

/// Run the wizard inside an existing TUI. The caller restores its terminal mode afterwards.
pub async fn attach(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    paths: &AppPaths,
    alias: Option<String>,
    initial: Option<Host>,
    no_color: bool,
) -> Result<WizardResult> {
    let mut wizard = Wizard::new(paths, alias, initial, no_color)?;
    loop {
        terminal
            .draw(|frame| draw(frame, &wizard))
            .map_err(|error| AppError::io("draw host wizard", error))?;
        if !event::poll(Duration::from_millis(200))
            .map_err(|error| AppError::io("poll host wizard input", error))?
        {
            continue;
        }
        let Event::Key(key) =
            event::read().map_err(|error| AppError::io("read host wizard input", error))?
        else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Enter if wizard.focused >= 15 => match wizard.action() {
                Action::Test => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        let precondition = crate::host::check_can_add(paths, &alias, &host);
                        if let Err(error) = precondition {
                            wizard.message = crate::redact::sanitize(&error.message);
                            wizard.failed = true;
                            continue;
                        }
                        if let Err(error) =
                            configure_ssh_credentials(&mut wizard, &alias, &host).await
                        {
                            wizard.message = crate::redact::sanitize(&error.message);
                            wizard.failed = true;
                            continue;
                        }
                        match test_connection(paths, &alias, &host, wizard.language).await {
                            Ok((message, passed)) => {
                                wizard.message = message;
                                wizard.failed = !passed;
                                wizard.tested = passed;
                            }
                            Err(error) => {
                                wizard.message = crate::redact::sanitize(&error.message);
                                wizard.failed = true;
                                wizard.tested = false;
                            }
                        }
                    }
                    Err(error) => {
                        wizard.message = crate::redact::sanitize(&error.message);
                        wizard.failed = true;
                    }
                },
                Action::Save => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        let warning = match crate::host::check_can_add(paths, &alias, &host) {
                            Err(error) => Some(error),
                            Ok(()) => configure_ssh_credentials(&mut wizard, &alias, &host)
                                .await
                                .err(),
                        };
                        if let Some(error) = warning {
                            wizard.message = crate::redact::sanitize(&error.message);
                            wizard.failed = true;
                        } else if let Err(error) =
                            crate::host::add_host(paths, &alias, host.clone())
                        {
                            wizard.message = crate::redact::sanitize(&error.message);
                            wizard.failed = true;
                        } else {
                            let warning = match configure_sudo_if_requested(
                                &mut wizard,
                                terminal,
                                &alias,
                                &host,
                            )
                            .await
                            {
                                Ok(message) => message,
                                Err(error) => Some(match wizard.language {
                                    crate::config::UiLanguage::ZhCn => format!(
                                        "主机 '{alias}' 已保存，但 sudo 配置失败：{}。请继续运行 'remxo vault set-sudo {alias}'。",
                                        crate::redact::sanitize(&error.message)
                                    ),
                                    crate::config::UiLanguage::En => format!(
                                        "Host '{alias}' was saved, but sudo configuration failed: {}. Continue with 'remxo vault set-sudo {alias}'.",
                                        crate::redact::sanitize(&error.message)
                                    ),
                                }),
                            };
                            wizard.result = Some(WizardResult {
                                message: match warning {
                                    Some(message) => message,
                                    None => match wizard.language {
                                        crate::config::UiLanguage::ZhCn => format!(
                                            "主机 '{alias}' 已保存。可运行 'remxo {alias} <command...>'，或在主机列表中按 Enter。"
                                        ),
                                        crate::config::UiLanguage::En => format!(
                                            "Host '{alias}' saved. Use 'remxo {alias} <command...>' or Enter on the host list."
                                        ),
                                    },
                                },
                                saved_alias: Some(alias),
                            });
                        }
                    }
                    Err(error) => {
                        wizard.message = crate::redact::sanitize(&error.message);
                        wizard.failed = true;
                    }
                },
                Action::None => {}
            },
            KeyCode::Char('t') if wizard.focused == 15 => {
                if wizard.focused < 16 {
                    wizard.focused += 1;
                }
            }
            other => wizard.handle_key(other),
        }
        if wizard.result.is_some() {
            return Ok(wizard.result.take().unwrap_or_else(|| WizardResult {
                saved_alias: None,
                message: "Host wizard closed.".into(),
            }));
        }
    }
}

/// Standalone host wizard for `remxo host add [alias]`.
pub async fn run(
    paths: &AppPaths,
    alias: Option<String>,
    initial: Option<Host>,
    no_color: bool,
) -> Result<WizardResult> {
    enable_raw_mode().map_err(|error| AppError::io("enable wizard terminal", error))?;
    execute!(stdout(), EnterAlternateScreen)
        .map_err(|error| AppError::io("enter host wizard", error))?;
    let backend = CrosstermBackend::new(stdout());
    let result = match Terminal::new(backend) {
        Ok(mut terminal) => attach(&mut terminal, paths, alias, initial, no_color).await,
        Err(error) => Err(AppError::io("create wizard terminal", error)),
    };
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
    result
}

async fn test_connection(
    paths: &AppPaths,
    alias: &str,
    host: &Host,
    language: crate::config::UiLanguage,
) -> Result<(String, bool)> {
    if host.raw_mode != RawMode::Allow {
        return Err(AppError::new(
            crate::error::ErrorCode::PolicyDenied,
            "connection test requires raw_mode=allow for a POSIX true handshake probe; other modes were not executed",
        ));
    }
    if host.shell != ShellKind::Posix {
        return Err(AppError::new(
            crate::error::ErrorCode::UnsupportedShell,
            "connection testing currently requires a POSIX shell; no unsupported command was attempted",
        ));
    }
    if host.transport == TransportKind::Telnet {
        return Err(AppError::new(
            crate::error::ErrorCode::UnsupportedOperation,
            "Telnet has no encrypted connection test in this version. Its plaintext automation is not implemented.",
        ));
    }
    let started = std::time::Instant::now();
    let outcome = OpensshTransport::default()
        .exec(ExecutionRequest {
            host: host.clone(),
            script: "true".into(),
            timeout: Duration::from_secs(8),
            max_output: 2048,
            sudo_password: None,
            auth_context: crate::transport::AuthenticationContext::pending(
                paths.clone(),
                alias,
                host,
            ),
        })
        .await;
    let digest = request_digest(&[alias, "connection_test", &host.destination()]);
    let (status, exit_code, error, message) = match outcome {
        Ok(outcome) => {
            let message = if outcome.exit_code == Some(0) {
                if language == crate::config::UiLanguage::ZhCn {
                    format!(
                        "主机 '{alias}' 连接测试通过。主机密钥检查保持启用，未执行写入命令或自动重试。"
                    )
                } else {
                    format!(
                        "Connection test passed for '{alias}'. Host key checks remained enabled; no write command was executed or retried."
                    )
                }
            } else {
                format!(
                    "Connection test reached the remote process but exited: {:?}",
                    outcome.exit_code
                )
            };
            (
                if outcome.exit_code == Some(0) {
                    "success"
                } else {
                    "failed"
                },
                outcome.exit_code,
                if outcome.exit_code == Some(0) {
                    None
                } else {
                    Some("remote_exit_code".into())
                },
                message,
            )
        }
        Err(error) => (
            "failed",
            None,
            Some(format!("{:?}", error.code)),
            crate::redact::sanitize(&error.message),
        ),
    };
    if let Ok(log) = AuditLog::new(&paths.audit()) {
        let event = AuditEvent {
            time: Utc::now(),
            request_id: uuid::Uuid::new_v4().to_string(),
            host: alias.into(),
            operation: "connection_test".into(),
            request_digest: digest,
            decision: "allowed".into(),
            approval_id: None,
            status: status.into(),
            exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
            truncated: false,
            error,
            transport: format!("{:?}", host.transport).to_ascii_lowercase(),
        };
        let _ = log.append(&event);
    }
    Ok((message, status == "success"))
}

async fn configure_ssh_credentials(wizard: &mut Wizard, alias: &str, host: &Host) -> Result<()> {
    if host.auth != AuthMode::VaultPassword && host.auth != AuthMode::VaultKey {
        return Ok(());
    }
    if !wizard.client.ping().await.is_ok() {
        wizard.client.ensure_running().await?;
    }
    let stem = host.credential.as_deref().unwrap_or(alias);
    if host.auth == AuthMode::VaultPassword {
        let password = wizard.draft.ssh_password.as_ref().ok_or_else(|| {
            AppError::invalid_argument("an SSH password is required for this authentication mode")
        })?;
        expect_secret_ack(
            wizard
                .client
                .call(RpcRequest::SetCredential {
                    name: crate::credential::ssh_credential_name(stem),
                    kind: "ssh-password".into(),
                    value: password.to_string(),
                })
                .await?,
        )?;
    } else {
        let name = crate::credential::key_credential_name(stem);
        let path = std::path::absolute(&wizard.draft.private_key_path)
            .map_err(|error| AppError::io("resolve private key import path", error))?;
        expect_secret_ack(
            wizard
                .client
                .call(RpcRequest::ImportPrivateKey { name, path })
                .await?,
        )?;
        if let Some(password) = wizard
            .draft
            .ssh_password
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            expect_secret_ack(
                wizard
                    .client
                    .call(RpcRequest::SetCredential {
                        name: crate::credential::ssh_credential_name(stem),
                        kind: "ssh-password".into(),
                        value: password.to_string(),
                    })
                    .await?,
            )?;
        }
    }
    Ok(())
}

fn expect_secret_ack(payload: RpcPayload) -> Result<()> {
    if matches!(payload, RpcPayload::Ack) {
        Ok(())
    } else {
        Err(AppError::internal(
            "unexpected credential write acknowledgement",
        ))
    }
}

async fn configure_sudo_if_requested(
    wizard: &mut Wizard,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    alias: &str,
    host: &Host,
) -> Result<Option<String>> {
    if !wizard.draft.configure_sudo {
        return Ok(None);
    }
    if !wizard.client.ping().await.is_ok() {
        wizard.client.ensure_running().await?;
    }
    let status = match wizard.client.call(RpcRequest::Status).await {
        Ok(RpcPayload::Status(status)) => status,
        _ => return Err(AppError::internal("unexpected Vault status")),
    };
    if status.vault_locked {
        return Ok(Some(match wizard.language {
            crate::config::UiLanguage::ZhCn => format!(
                "主机 '{alias}' 已保存，但 Vault 处于锁定状态，尚未配置 sudo。请解锁后运行 'remxo vault set-sudo {alias}'，无需重新创建主机。"
            ),
            crate::config::UiLanguage::En => format!(
                "Host '{alias}' saved, but sudo was NOT configured because Vault is locked. Unlock and run 'remxo vault set-sudo {alias}' to finish without recreating the host."
            ),
        }));
    }
    crate::tui::suspend(terminal)?;
    let password = rpassword::prompt_password(wizard.language.text(
        "Independent sudo password (input hidden): ",
        "独立的 sudo 密码（隐藏输入）：",
    ));
    crate::tui::resume(terminal)?;
    let password = password.map_err(|error| AppError::io("read hidden sudo password", error))?;
    let value = Zeroizing::new(password);
    if host.auth == AuthMode::ExternalAgent && !check_agent_available(host) {
        // Agent state is informational here; no unsupported automatic privilege path is attempted.
    }
    wizard
        .client
        .call(RpcRequest::SetCredential {
            name: host
                .sudo_credential
                .clone()
                .unwrap_or_else(|| alias.to_string()),
            kind: "sudo-password".into(),
            value: value.to_string(),
        })
        .await?;
    Ok(None)
}

fn label(index: usize, language: crate::config::UiLanguage) -> &'static str {
    match index {
        0 => language.text("Alias", "主机别名"),
        1 => language.text("Connection", "连接方式"),
        2 => language.text("OpenSSH alias / hostname", "OpenSSH 别名 / 主机名"),
        3 => language.text("Username (optional)", "用户名（可选）"),
        4 => language.text("Port", "端口"),
        5 => language.text("Authentication", "认证方式"),
        6 => language.text("Host number", "主机编号"),
        7 => language.text("Environment", "环境"),
        8 => language.text("Platform", "平台"),
        9 => language.text("Raw commands", "原始命令"),
        10 => language.text("Approval", "审批策略"),
        11 => language.text("Configure sudo in Vault", "在 Vault 中配置 sudo"),
        12 => language.text("Acknowledge insecure Telnet", "确认 Telnet 不加密风险"),
        13 => language.text("SSH password / key passphrase", "SSH 密码 / 私钥口令"),
        14 => language.text("Private key file (not .pub)", "私钥文件（不是 .pub）"),
        15 => language.text("[ Test connection ]", "[ 测试连接 ]"),
        16 => language.text("[ Save host ]", "[ 保存主机 ]"),
        _ => "",
    }
}

fn color(no_color: bool, color: Color) -> Style {
    if no_color || std::env::var_os("NO_COLOR").is_some() {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

fn draw(frame: &mut ratatui::Frame, wizard: &Wizard) {
    let columns = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(5),
    ])
    .split(frame.area());
    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "Remxo",
            color(wizard.no_color, Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(wizard.language.text(
            "Add host · connection → policy → review",
            "添加主机 · 连接 → 策略 → 复核",
        )),
        Line::from(Span::styled(
            wizard.language.text(
                "Remote execution for humans and agents · L1 local broker",
                "面向人类与 Agent 的远程执行 · L1 本地 Broker",
            ),
            color(wizard.no_color, Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(wizard.language.text("Interactive setup", "交互式配置")),
    );
    frame.render_widget(header, columns[0]);

    let body = if columns[1].width >= 84 {
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(columns[1])
    } else {
        Layout::horizontal([Constraint::Percentage(100)]).split(columns[1])
    };
    let visible = body[0].height.saturating_sub(2) as usize;
    let start = wizard
        .focused
        .saturating_sub(visible.saturating_sub(1))
        .min(16usize.saturating_sub(visible.saturating_sub(1)));
    let items = (start..=16.min(start + visible.saturating_sub(1)))
        .map(|index| {
            let selected = index == wizard.focused;
            let indicator = if selected { " > " } else { "   " };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{indicator}{:<27}", label(index, wizard.language)),
                    color(
                        wizard.no_color,
                        if selected { Color::Cyan } else { Color::Gray },
                    )
                    .add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                Span::styled(
                    crate::redact::escape_controls(&wizard.draft.value(index, wizard.language)),
                    color(
                        wizard.no_color,
                        if selected { Color::White } else { Color::Gray },
                    ),
                ),
            ]))
            .style(if selected {
                color(wizard.no_color, Color::DarkGray)
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(
        wizard.language.text(
            "Fields · type to edit, ←/→ to change",
            "字段 · 输入编辑，←/→ 切换选项",
        ),
    ));
    frame.render_widget(list, body[0]);
    if body.len() > 1 {
        draw_preview(frame, wizard, body[1]);
    }

    let message_style = color(
        wizard.no_color,
        if wizard.failed {
            Color::Red
        } else if wizard.tested {
            Color::Green
        } else {
            Color::Yellow
        },
    );
    let footer = Paragraph::new(vec![
        Line::from(Span::styled(wizard.message.clone(), message_style)),
        Line::from(Span::styled(
            wizard.language.text(
                "↑/↓ navigate · ←/→ change · Backspace/Delete edit · Enter next/test/save · Esc cancel",
                "↑/↓ 导航 · ←/→ 切换 · Backspace/Delete 编辑 · Enter 下一步/测试/保存 · Esc 取消",
            ),
            color(wizard.no_color, Color::Gray),
        )),
        Line::from(Span::styled(
            wizard.language.text(
                "OpenSSH auth belongs to OpenSSH. Secrets stay out of preview, argv, logs and audit.",
                "认证由 OpenSSH 执行。秘密不会进入预览、argv、日志或审计。",
            ),
            color(wizard.no_color, Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(wizard.language.text("Help & status", "帮助与状态")),
    );
    frame.render_widget(footer, columns[2]);
}

fn draw_preview(frame: &mut ratatui::Frame, wizard: &Wizard, area: ratatui::layout::Rect) {
    let wizard_error = wizard.draft.host().err();
    let error_text = wizard_error.map(|error| error.message).unwrap_or_else(|| {
        wizard
            .language
            .text("configuration ready for review", "配置已可复核")
            .into()
    });
    let auth = match wizard.draft.mode {
        ConnectionMode::Telnet => wizard.language.text("INSECURE transport", "不加密传输"),
        _ if wizard.draft.auth == AuthMode::ExternalAgent
            && !check_agent_available(&Host {
                auth: wizard.draft.auth,
                ..Host::default()
            }) =>
        {
            wizard
                .language
                .text("external agent unavailable", "外部 Agent 不可用")
        }
        _ => wizard.language.text("secure SSH", "加密 SSH"),
    };
    let lines = vec![
        Line::from(Span::styled(
            wizard.language.text("Review", "复核"),
            color(wizard.no_color, Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "alias: {}",
            crate::redact::escape_controls(&wizard.draft.alias)
        )),
        Line::from(format!(
            "connection: {}",
            wizard.draft.mode.label(wizard.language)
        )),
        Line::from(format!(
            "address: {}",
            if wizard.draft.address.is_empty() {
                "(required)".into()
            } else {
                crate::redact::escape_controls(&wizard.draft.address)
            }
        )),
        Line::from(format!(
            "port: {} · host number: {}",
            wizard.draft.port, wizard.draft.number
        )),
        Line::from(format!(
            "environment: {} · platform: {:?}",
            crate::redact::escape_controls(&wizard.draft.environment),
            wizard.draft.platform
        )),
        Line::from(Span::styled(auth, color(wizard.no_color, Color::Yellow))),
        Line::from(Span::styled(
            crate::redact::sanitize(&error_text),
            color(wizard.no_color, Color::Green),
        )),
        Line::from(""),
        Line::from(Span::styled(
            if wizard.draft.platform == Platform::Windows {
                wizard.language.text(
                    "Windows is registered, but non-interactive PowerShell execution is not implemented in this version.",
                    "可以登记 Windows 主机，但此版本尚未实现非交互 PowerShell 执行。"
                )
            } else {
                wizard.language.text(
                    "Non-interactive execution currently supports POSIX shells.",
                    "当前非交互执行支持 POSIX shell。",
                )
            },
            color(wizard.no_color, Color::Gray),
        )),
        Line::from(Span::styled(
            if wizard.draft.configure_sudo {
                wizard.language.text(
                    "sudo: independent hidden Vault secret required",
                    "sudo：需要独立的隐藏 Vault 秘密",
                )
            } else {
                wizard.language.text(
                    "sudo: not configured (safe default)",
                    "sudo：未配置（安全默认值）",
                )
            },
            color(wizard.no_color, Color::Yellow),
        )),
        Line::from(Span::styled(
            wizard.language.text(
                "Never auto-accept host keys, weaken SSH checks, or expose secrets in previews.",
                "不会自动接受主机密钥、削弱 SSH 检查，或在预览中暴露秘密。",
            ),
            color(wizard.no_color, Color::DarkGray),
        )),
    ];
    let preview = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(wizard.language.text("Configuration preview", "配置预览")),
    );
    frame.render_widget(preview, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn choices_preserve_posix_and_security_defaults() {
        let mut config = Config::default();
        config.hosts.insert(
            "existing".into(),
            Host {
                number: Some(4),
                hostname: Some("192.0.2.1".into()),
                ..Host::default()
            },
        );
        let mut draft = Draft::new(Some("prod".into()), None, &config);
        draft.address = "real-prod".into();
        let (alias, host) = draft
            .host()
            .unwrap_or_else(|error| panic!("draft: {error}"));
        assert_eq!(alias, "prod");
        assert_eq!(host.number, Some(5));
        assert_eq!(host.approval, ApprovalMode::Writes);
        assert_eq!(host.shell, ShellKind::Posix);
        assert!(!host.insecure_acknowledged);
        assert!(!draft.configure_sudo);
        draft.mode = ConnectionMode::Telnet;
        draft.insecure_acknowledged = false;
        assert!(draft.host().is_err());
    }

    #[test]
    fn text_editing_keeps_numeric_fields_bounded_and_not_secret() {
        let mut draft = Draft::new(None, None, &Config::default());
        draft.type_character(4, '2');
        draft.type_character(4, '2');
        draft.type_character(4, 'x');
        assert_eq!(draft.port, "2222");
        draft.backspace(4);
        assert_eq!(draft.port, "222");
        draft.clear(2);
        assert!(draft.host().is_err());
    }

    #[test]
    fn text_fields_accept_spaces_without_changing_choices() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        crate::config::Config::initialize(&paths.config)
            .unwrap_or_else(|error| panic!("config: {error}"));
        let mut wizard = Wizard::new(&paths, None, None, false)
            .unwrap_or_else(|error| panic!("wizard: {error}"));
        wizard.focused = 13;
        wizard.draft.ssh_password = Some(Zeroizing::new("two".into()));
        let auth = wizard.draft.auth;
        wizard.handle_key(KeyCode::Char(' '));
        wizard.handle_key(KeyCode::Char('x'));
        assert_eq!(
            wizard
                .draft
                .ssh_password
                .as_ref()
                .map(|value| value.as_str()),
            Some("two x"),
            "space must stay in a password rather than cycling authentication"
        );
        assert_eq!(wizard.draft.auth, auth);
        wizard.focused = 14;
        wizard.draft.private_key_path = "with".into();
        wizard.handle_key(KeyCode::Char(' '));
        wizard.handle_key(KeyCode::Char('k'));
        assert_eq!(wizard.draft.private_key_path, "with k");
    }

    #[test]
    fn secret_values_are_never_rendered() {
        let mut draft = Draft::new(None, None, &Config::default());
        draft.auth = AuthMode::VaultPassword;
        draft.ssh_password = Some(Zeroizing::new("test-only-never-render-this".into()));
        assert_eq!(
            draft.value(13, crate::config::UiLanguage::En),
            "entered (hidden)"
        );
        assert_eq!(
            draft.value(13, crate::config::UiLanguage::ZhCn),
            "已输入（隐藏）"
        );
        assert!(
            !draft
                .value(13, crate::config::UiLanguage::En)
                .contains("test-only-never-render-this")
        );
    }

    #[test]
    fn chinese_language_changes_wizard_controls() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        crate::config::Config::initialize_with_language(
            &paths.config,
            crate::config::UiLanguage::ZhCn,
        )
        .unwrap_or_else(|error| panic!("config: {error}"));
        let mut wizard = Wizard::new(&paths, Some("prod-01".into()), None, false)
            .unwrap_or_else(|error| panic!("wizard: {error}"));
        wizard.focused = 16;
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(120, 36))
            .unwrap_or_else(|error| panic!("terminal: {error}"));
        terminal
            .draw(|frame| draw(frame, &wizard))
            .unwrap_or_else(|error| panic!("draw: {error}"));
        let content = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        let compact = content.replace(' ', "");
        assert!(compact.contains("测试连接"));
        assert!(compact.contains("保存主机"));
        assert!(compact.contains("认证方式"));
    }

    #[test]
    fn wizard_renders_fields_and_review_actions_inside_the_viewport() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        crate::config::Config::initialize(&paths.config)
            .unwrap_or_else(|error| panic!("config: {error}"));
        let mut wizard = Wizard::new(&paths, Some("prod-01".into()), None, false)
            .unwrap_or_else(|error| panic!("wizard: {error}"));
        wizard.draft.address = "example.invalid".into();
        wizard.focused = 16;
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(96, 24))
            .unwrap_or_else(|error| panic!("terminal: {error}"));
        terminal
            .draw(|frame| draw(frame, &wizard))
            .unwrap_or_else(|error| panic!("draw: {error}"));
        let content = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(content.contains("prod-01"));
        assert!(content.contains("Connection"));
        assert!(content.contains("Test connection"));
        assert!(content.contains("Save host"));
        assert!(!content.contains('\u{1b}'));
    }
}
