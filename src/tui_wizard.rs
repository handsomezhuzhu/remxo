use crate::audit::{AuditEvent, AuditLog, request_digest};
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{
    AppPaths, ApprovalMode, AuthMode, Host, Platform, RawMode, ShellKind, TransportKind,
};
use crate::error::{AppError, Result};
use crate::text_input::{TextInput, display_width};
use crate::transport::openssh::OpensshTransport;
use crate::transport::{ExecutionRequest, Transport as _, check_agent_available};
use chrono::Utc;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::io::{Stdout, stdout};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

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

const ACTION_FETCH_HOST_KEY: usize = 15;
const ACTION_TRUST_HOST_KEY: usize = 16;
const ACTION_TEST_OR_SAVE_TEST: usize = 17;
const ACTION_SAVE: usize = 18;
const ACTION_SAVE_EXIT: usize = 19;
const ACTION_EXIT: usize = 20;
const LAST_FOCUS: usize = ACTION_EXIT;

#[derive(Debug, Clone)]
struct Draft {
    alias: TextInput,
    mode: ConnectionMode,
    address: TextInput,
    username: TextInput,
    port: TextInput,
    number: TextInput,
    auth: AuthMode,
    ssh_password: Option<TextInput>,
    private_key_path: TextInput,
    environment: TextInput,
    tags: Vec<String>,
    platform: Platform,
    raw_mode: RawMode,
    approval: ApprovalMode,
    configure_sudo: bool,
    insecure_acknowledged: bool,
    editing: bool,
    original_auth: Option<AuthMode>,
    original_credential: Option<String>,
    original_sudo_credential: Option<String>,
    replace_credentials: bool,
    rotation_id: uuid::Uuid,
}

impl Draft {
    fn new(
        alias: Option<String>,
        initial: Option<Host>,
        config: &crate::config::Config,
        editing: bool,
    ) -> Result<Self> {
        fn input(value: String, max_chars: usize) -> Result<TextInput> {
            TextInput::with_value(&value, max_chars).map_err(|error| {
                AppError::invalid_argument(format!("invalid initial host form value: {error}"))
            })
        }
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
        let original_auth = editing.then_some(initial.auth);
        let original_credential = editing.then(|| initial.credential.clone()).flatten();
        let original_sudo_credential = editing.then(|| initial.sudo_credential.clone()).flatten();
        let mode = match initial.transport {
            TransportKind::Ssh if initial.ssh_alias.is_some() => ConnectionMode::OpenSshAlias,
            TransportKind::Ssh => ConnectionMode::DirectSsh,
            TransportKind::Telnet => ConnectionMode::Telnet,
        };
        Ok(Self {
            alias: input(alias.unwrap_or_else(|| "prod-01".into()), 256)?,
            mode,
            address: input(
                initial.ssh_alias.or(initial.hostname).unwrap_or_default(),
                256,
            )?,
            username: input(initial.username.unwrap_or_default(), 256)?,
            port: input(initial.port.to_string(), 5)?,
            number: input(initial.number.unwrap_or(next_number).to_string(), 10)?,
            auth: initial.auth,
            ssh_password: None,
            private_key_path: TextInput::new(512),
            environment: input(
                if initial.environment.is_empty() {
                    "development".into()
                } else {
                    initial.environment
                },
                256,
            )?,
            tags,
            platform: initial.platform,
            raw_mode: initial.raw_mode,
            approval: initial.approval,
            configure_sudo: !editing && initial.sudo_credential.is_some(),
            insecure_acknowledged: initial.insecure_acknowledged,
            editing,
            original_auth,
            original_credential,
            original_sudo_credential,
            replace_credentials: false,
            rotation_id: uuid::Uuid::new_v4(),
        })
    }

    fn reuse_credentials(&self) -> bool {
        self.editing && self.original_auth == Some(self.auth) && !self.replace_credentials
    }

    fn private_key_path(&self) -> String {
        let value = self.private_key_path.value().trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            return value[1..value.len() - 1].to_string();
        }
        value.to_string()
    }

    fn host(&self) -> Result<(String, Host)> {
        let alias = self.alias.value().trim();
        if alias.is_empty() {
            return Err(AppError::invalid_argument("alias is required"));
        }
        if self.address.value().trim().is_empty() {
            return Err(AppError::invalid_argument(
                "an OpenSSH alias or hostname is required before testing or saving",
            ));
        }
        match self.auth {
            AuthMode::VaultPassword => {
                if !self.reuse_credentials()
                    && self
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
                if !self.reuse_credentials() && self.private_key_path.value().trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "selecting Vault private key requires a private key file path (not the .pub file)",
                    ));
                }
            }
            AuthMode::OpensshConfig | AuthMode::ExternalAgent => {
                if self.ssh_password.is_some() || !self.private_key_path.value().trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "choose Vault SSH password or Vault private key before importing credentials; no secret was saved",
                    ));
                }
            }
        }
        if self.mode == ConnectionMode::Telnet
            && (self.ssh_password.is_some() || !self.private_key_path.value().trim().is_empty())
        {
            return Err(AppError::invalid_argument(
                "SSH password/private-key import is available only for SSH hosts, not Telnet",
            ));
        }
        let port =
            self.port.value().parse::<u16>().map_err(|_| {
                AppError::invalid_argument("port must be an integer from 1 to 65535")
            })?;
        let number =
            self.number.value().parse::<u32>().map_err(|_| {
                AppError::invalid_argument("host number must be a positive integer")
            })?;
        let (ssh_alias, hostname, shell) = match self.mode {
            ConnectionMode::OpenSshAlias => (
                Some(self.address.value().trim().to_string()),
                None,
                self.shell(),
            ),
            ConnectionMode::DirectSsh | ConnectionMode::Telnet => (
                None,
                Some(self.address.value().trim().to_string()),
                self.shell(),
            ),
        };
        let host = Host {
            number: Some(number),
            transport: self.mode.transport(),
            ssh_alias,
            hostname,
            port,
            username: (!self.username.value().trim().is_empty())
                .then(|| self.username.value().trim().to_string()),
            platform: self.platform,
            shell,
            auth: self.auth,
            environment: self.environment.value().trim().to_string(),
            tags: self.tags.clone(),
            raw_mode: self.raw_mode,
            approval: self.approval,
            insecure_acknowledged: self.insecure_acknowledged,
            sudo_credential: if self.configure_sudo {
                Some(crate::credential::sudo_credential_name(alias))
            } else {
                self.original_sudo_credential.clone()
            },
            credential: match self.auth {
                AuthMode::VaultPassword | AuthMode::VaultKey if !self.editing => {
                    Some(alias.to_string())
                }
                AuthMode::VaultPassword | AuthMode::VaultKey if self.reuse_credentials() => self
                    .original_credential
                    .clone()
                    .or_else(|| Some(alias.to_string())),
                AuthMode::VaultPassword | AuthMode::VaultKey => {
                    Some(format!("{alias}:rotation:{}", self.rotation_id.simple()))
                }
                AuthMode::OpensshConfig | AuthMode::ExternalAgent => None,
            },
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
            0 => self.alias.value().to_string(),
            1 => self.mode.label(language).into(),
            2 => self.address.value().to_string(),
            3 => self.username.value().to_string(),
            4 => self.port.value().to_string(),
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
            6 => self.number.value().to_string(),
            7 => self.environment.value().to_string(),
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
            13 => {
                if self.reuse_credentials() {
                    language
                        .text(
                            "keep current (type to replace)",
                            "保留当前凭据（输入即更换）",
                        )
                        .into()
                } else {
                    self.ssh_password
                        .as_ref()
                        .filter(|password| !password.is_empty())
                        .map(|password| password.masked_value('*'))
                        .unwrap_or_else(|| language.text("not set", "未输入").into())
                }
            }
            14 => {
                if self.reuse_credentials() && self.auth == AuthMode::VaultKey {
                    language
                        .text(
                            "keep current key (enter a path to replace)",
                            "保留当前私钥（输入路径即更换）",
                        )
                        .into()
                } else {
                    self.private_key_path.value().to_string()
                }
            }
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

    fn input(&self, index: usize) -> Option<&TextInput> {
        if self.editing && index == 0 {
            return None;
        }
        match index {
            0 => Some(&self.alias),
            2 => Some(&self.address),
            3 => Some(&self.username),
            4 => Some(&self.port),
            6 => Some(&self.number),
            7 => Some(&self.environment),
            13 => self.ssh_password.as_ref(),
            14 => Some(&self.private_key_path),
            _ => None,
        }
    }

    fn input_mut(&mut self, index: usize) -> Option<&mut TextInput> {
        if self.editing && index == 0 {
            return None;
        }
        match index {
            0 => Some(&mut self.alias),
            2 => Some(&mut self.address),
            3 => Some(&mut self.username),
            4 => Some(&mut self.port),
            6 => Some(&mut self.number),
            7 => Some(&mut self.environment),
            13 => self.ssh_password.as_mut(),
            14 => Some(&mut self.private_key_path),
            _ => None,
        }
    }

    fn type_character(&mut self, index: usize, character: char) {
        if matches!(index, 4 | 6) && !character.is_ascii_digit() {
            return;
        }
        if index == 13 && self.ssh_password.is_none() {
            self.ssh_password = Some(TextInput::new(4096));
        }
        let changed = if let Some(input) = self.input_mut(index) {
            input.insert_char(character).is_ok()
        } else {
            false
        };
        if changed && self.editing && matches!(index, 13 | 14) {
            self.replace_credentials = true;
        }
    }

    fn paste(&mut self, index: usize, text: &str) {
        if matches!(index, 4 | 6) && !text.chars().all(|character| character.is_ascii_digit()) {
            return;
        }
        if index == 13 && self.ssh_password.is_none() {
            self.ssh_password = Some(TextInput::new(4096));
        }
        let changed = if let Some(input) = self.input_mut(index) {
            input.paste(text).is_ok()
        } else {
            false
        };
        if changed && self.editing && matches!(index, 13 | 14) {
            self.replace_credentials = true;
        }
    }

    fn move_left(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.move_left();
        }
    }

    fn move_right(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.move_right();
        }
    }

    fn move_home(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.move_home();
        }
    }

    fn move_end(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.move_end();
        }
    }

    fn backspace(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.backspace();
        }
    }

    fn delete(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.delete();
        }
    }

    fn delete_word_before(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.delete_word_before();
        }
    }

    fn delete_to_start(&mut self, index: usize) {
        if let Some(input) = self.input_mut(index) {
            input.delete_to_start();
        }
    }

    fn clear(&mut self, index: usize) {
        if self.editing && matches!(index, 13 | 14) {
            self.replace_credentials = true;
        }
        if let Some(input) = self.input_mut(index) {
            input.clear();
        }
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
    paths: AppPaths,
    message: String,
    failed: bool,
    tested: bool,
    no_color: bool,
    language: crate::config::UiLanguage,
    result: Option<WizardResult>,
    exit_prompt: bool,
    host_keys: Vec<crate::hostkey::FetchedHostKey>,
    host_key_trusted: bool,
    host_key_confirm_pending: bool,
    host_key_job: Option<HostKeyJob>,
    action_job: Option<ActionJob>,
    pending_sudo: Option<(ActionJobKind, String, Host)>,
    retry_attempts: u32,
    client: BrokerClient,
    original: Option<Host>,
}

impl Wizard {
    #[cfg(test)]
    fn new(
        paths: &AppPaths,
        alias: Option<String>,
        initial: Option<Host>,
        no_color: bool,
    ) -> Result<Self> {
        Self::with_original(paths, alias, initial, None, no_color)
    }

    fn with_original(
        paths: &AppPaths,
        alias: Option<String>,
        initial: Option<Host>,
        original: Option<Host>,
        no_color: bool,
    ) -> Result<Self> {
        let config = crate::config::Config::load(&paths.config)?;
        let language = config.settings.language;
        let editing = original.is_some();
        let draft = Draft::new(alias, initial, &config, editing)?;
        Ok(Self {
            client: BrokerClient::new(paths.clone()),
            draft,
            focused: 0,
            paths: paths.clone(),
            message: if editing {
                language.text(
                    "Edit connection fields; unchanged credentials are preserved. Enter moves to save or save-and-test.",
                    "编辑连接字段；未更换的凭据会保留。Enter 前往保存或保存并测试。",
                )
            } else {
                language.text(
                    "Complete fields. Enter moves through Connection → Policy → Review; Esc discards changes.",
                    "请填写字段。Enter 依次进入连接、策略和复核；Esc 放弃更改。",
                )
            }
            .into(),
            failed: false,
            tested: false,
            no_color,
            language,
            result: None,
            exit_prompt: false,
            host_keys: Vec::new(),
            host_key_trusted: false,
            host_key_confirm_pending: false,
            host_key_job: None,
            action_job: None,
            pending_sudo: None,
            retry_attempts: config.settings.retry_attempts.clamp(1, 10),
            original,
        })
    }

    #[cfg(test)]
    fn handle_key(&mut self, code: KeyCode) {
        self.handle_key_event(KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('u') => self.draft.delete_to_start(self.focused),
                KeyCode::Char('w') => self.draft.delete_word_before(self.focused),
                KeyCode::Char('l') => self.draft.clear(self.focused),
                KeyCode::Left | KeyCode::Home => self.draft.move_home(self.focused),
                KeyCode::Right | KeyCode::End => self.draft.move_end(self.focused),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc if self.host_key_confirm_pending => {
                self.host_key_confirm_pending = false;
                self.failed = false;
                self.tested = false;
                self.message = self
                    .language
                    .text(
                        "Host key trust cancelled. Continue editing or choose another action.",
                        "已取消信任主机密钥。可继续编辑或选择其他操作。",
                    )
                    .into();
            }
            KeyCode::Esc => {
                self.exit_prompt = true;
                self.failed = false;
                self.tested = false;
                self.message = self
                    .language
                    .text(
                        "Exit: press S to save & exit, Enter to exit without saving, Esc to cancel.",
                        "退出：按 S 保存并退出，Enter 不保存退出，Esc 取消。",
                    )
                    .into();
            }
            KeyCode::Up => self.focused = self.focused.saturating_sub(1),
            KeyCode::Down => self.focused = (self.focused + 1).min(LAST_FOCUS),
            KeyCode::Left if self.draft.input(self.focused).is_some() => {
                self.draft.move_left(self.focused)
            }
            KeyCode::Right if self.draft.input(self.focused).is_some() => {
                self.draft.move_right(self.focused)
            }
            KeyCode::Left => self.draft.change(self.focused, -1),
            KeyCode::Right => self.draft.change(self.focused, 1),
            KeyCode::Home | KeyCode::PageUp => self.draft.move_home(self.focused),
            KeyCode::End | KeyCode::PageDown => self.draft.move_end(self.focused),
            KeyCode::Char(' ') if matches!(self.focused, 1 | 5 | 8 | 9 | 10 | 11 | 12) => {
                self.draft.change(self.focused, 1)
            }
            KeyCode::Backspace => self.draft.backspace(self.focused),
            KeyCode::Delete => self.draft.delete(self.focused),
            KeyCode::Char(character) => self.draft.type_character(self.focused, character),
            KeyCode::Tab => self.focused = (self.focused + 1).min(LAST_FOCUS),
            KeyCode::BackTab => self.focused = self.focused.saturating_sub(1),
            KeyCode::Enter => {
                if self.focused < 6 {
                    self.focused = 6;
                } else if self.focused < ACTION_FETCH_HOST_KEY {
                    self.focused = ACTION_FETCH_HOST_KEY;
                }
            }
            _ => {}
        }
    }

    fn action(&mut self) -> Action {
        match self.focused {
            ACTION_FETCH_HOST_KEY => Action::FetchHostKey,
            ACTION_TRUST_HOST_KEY => Action::TrustHostKey,
            ACTION_TEST_OR_SAVE_TEST if self.original.is_some() => Action::SaveTest,
            ACTION_TEST_OR_SAVE_TEST => Action::Test,
            ACTION_SAVE => Action::Save,
            ACTION_SAVE_EXIT => Action::SaveExit,
            ACTION_EXIT => Action::Exit,
            _ => Action::None,
        }
    }
}

enum Action {
    None,
    Test,
    Save,
    SaveTest,
    SaveExit,
    Exit,
    FetchHostKey,
    TrustHostKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyJobKind {
    Fetch,
    Trust,
}

enum HostKeyJobOutput {
    Keys(Vec<crate::hostkey::FetchedHostKey>),
    Trusted(crate::hostkey::HostKeyTrustResult),
}

struct HostKeyJob {
    kind: HostKeyJobKind,
    alias: String,
    host: Host,
    started: Instant,
    attempt: u32,
    retries: u32,
    retry_at: Option<Instant>,
    receiver: Option<oneshot::Receiver<Result<HostKeyJobOutput>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionJobKind {
    Test,
    Save,
    SaveTest,
    SaveExit,
}

struct ActionJob {
    kind: ActionJobKind,
    paths: AppPaths,
    alias: String,
    host: Host,
    original: Option<Host>,
    draft: Draft,
    language: crate::config::UiLanguage,
    pending: bool,
    started: Instant,
    attempt: u32,
    retries: u32,
    retry_at: Option<Instant>,
    receiver: Option<oneshot::Receiver<Result<ActionJobOutput>>>,
}

enum ActionJobOutput {
    Tested((String, bool)),
    Saved,
}

fn action_retryable(error: &AppError) -> bool {
    matches!(
        error.code,
        crate::error::ErrorCode::ConnectionFailed | crate::error::ErrorCode::Timeout
    )
}

fn host_key_spinner(elapsed: Duration) -> &'static str {
    match (elapsed.as_millis() / 150) % 4 {
        0 => "|",
        1 => "/",
        2 => "-",
        _ => "\\",
    }
}

fn saved_message(wizard: &Wizard, alias: &str) -> String {
    match wizard.language {
        crate::config::UiLanguage::ZhCn => {
            format!("主机 '{alias}' 已覆盖保存。可继续修改，或选择“保存并退出”。")
        }
        crate::config::UiLanguage::En => {
            format!(
                "Host '{alias}' overwritten in config. Continue editing, or choose Save & exit."
            )
        }
    }
}

fn combine_message(warning: Option<String>, message: String) -> String {
    match warning {
        Some(warning) if !warning.trim().is_empty() => format!("{warning} {message}"),
        _ => message,
    }
}

impl Wizard {
    fn host_key_busy_message(
        &self,
        kind: HostKeyJobKind,
        started: Instant,
        attempt: u32,
        retries: u32,
    ) -> String {
        let elapsed = started.elapsed().as_secs_f32();
        let label = match kind {
            HostKeyJobKind::Fetch => self.language.text("获取主机密钥", "Fetch host key"),
            HostKeyJobKind::Trust => self.language.text("信任主机密钥", "Trust host key"),
        };
        match self.language {
            crate::config::UiLanguage::ZhCn => format!(
                "{} {} 正在{}... {:.1}s 第 {}/{} 次",
                host_key_spinner(started.elapsed()),
                label,
                label,
                elapsed,
                attempt,
                retries
            ),
            crate::config::UiLanguage::En => format!(
                "{} {}... {:.1}s attempt {}/{}",
                host_key_spinner(started.elapsed()),
                label,
                elapsed,
                attempt,
                retries
            ),
        }
    }

    fn spawn_host_key_attempt(&mut self) {
        let Some(job) = self.host_key_job.as_mut() else {
            return;
        };
        let (sender, receiver) = oneshot::channel();
        let kind = job.kind;
        let alias = job.alias.clone();
        let host = job.host.clone();
        tokio::spawn(async move {
            let result = match kind {
                HostKeyJobKind::Fetch => {
                    crate::hostkey::fetch_once(&host).map(HostKeyJobOutput::Keys)
                }
                HostKeyJobKind::Trust => crate::hostkey::trust_with_retries(&alias, &host, None, 1)
                    .map(HostKeyJobOutput::Trusted),
            };
            let _ = sender.send(result);
        });
        job.receiver = Some(receiver);
        job.retry_at = None;
    }

    fn start_host_key_job(&mut self, kind: HostKeyJobKind, alias: String, host: Host) {
        let retries = self.retry_attempts.max(1);
        self.host_key_job = Some(HostKeyJob {
            kind,
            alias,
            host,
            started: Instant::now(),
            attempt: 1,
            retries,
            retry_at: None,
            receiver: None,
        });
        self.spawn_host_key_attempt();
        if let Some(job) = self.host_key_job.as_ref() {
            self.message =
                self.host_key_busy_message(job.kind, job.started, job.attempt, job.retries);
        }
        self.failed = false;
        self.tested = false;
    }

    fn update_host_key_job(&mut self) {
        let Some(job) = self.host_key_job.as_mut() else {
            return;
        };
        if job.receiver.is_none() {
            if let Some(retry_at) = job.retry_at
                && Instant::now() >= retry_at
            {
                let attempt = job.attempt;
                let retries = job.retries;
                self.spawn_host_key_attempt();
                self.message = match self.language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("正在重试 第 {attempt}/{retries} 次...")
                    }
                    crate::config::UiLanguage::En => {
                        format!("Retrying attempt {attempt}/{retries}...")
                    }
                };
            }
            return;
        }
        let received = job
            .receiver
            .as_mut()
            .map(|receiver| receiver.try_recv())
            .unwrap_or(Err(oneshot::error::TryRecvError::Closed));
        match received {
            Ok(Ok(output)) => {
                self.host_key_job = None;
                match output {
                    HostKeyJobOutput::Keys(keys) => {
                        self.host_keys = keys.clone();
                        self.host_key_trusted = false;
                        self.host_key_confirm_pending = false;
                        let fingerprints = keys
                            .iter()
                            .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                            .collect::<Vec<_>>()
                            .join("\n  ");
                        self.message = match self.language {
                            crate::config::UiLanguage::ZhCn => format!(
                                "服务器主机密钥指纹：\n  {fingerprints}\n请人工核对。确认后选择“信任主机密钥”，并再次按 Enter。"
                            ),
                            crate::config::UiLanguage::En => format!(
                                "Server host key fingerprints:\n  {fingerprints}\nVerify manually. Then choose Trust host key and press Enter again."
                            ),
                        };
                        self.failed = false;
                        self.tested = false;
                    }
                    HostKeyJobOutput::Trusted(result) => {
                        self.host_key_trusted = true;
                        self.host_key_confirm_pending = false;
                        self.message = match self.language {
                            crate::config::UiLanguage::ZhCn => {
                                if result.added.is_empty() {
                                    format!(
                                        "主机 '{}' 的主机密钥已在 known_hosts 中。",
                                        result.host
                                    )
                                } else {
                                    format!("主机 '{}' 的主机密钥已信任。", result.host)
                                }
                            }
                            crate::config::UiLanguage::En => {
                                if result.added.is_empty() {
                                    format!("Host '{}' key is already in known_hosts.", result.host)
                                } else {
                                    format!("Host '{}' key trusted.", result.host)
                                }
                            }
                        };
                        self.failed = false;
                        self.tested = false;
                    }
                }
            }
            Ok(Err(error)) => {
                let attempt = job.attempt;
                let retries = job.retries;
                if attempt < retries {
                    job.attempt = attempt + 1;
                    job.receiver = None;
                    job.retry_at = Some(Instant::now() + Duration::from_millis(250));
                    let detail = crate::i18n::error_message(&error, self.language);
                    self.message = match self.language {
                        crate::config::UiLanguage::ZhCn => {
                            format!("第 {attempt}/{retries} 次失败：{detail}\n正在重试...")
                        }
                        crate::config::UiLanguage::En => {
                            format!("Attempt {attempt}/{retries} failed: {detail}\nRetrying...")
                        }
                    };
                    self.failed = true;
                    self.tested = false;
                } else {
                    self.host_key_job = None;
                    self.message = match self.language {
                        crate::config::UiLanguage::ZhCn => format!(
                            "主机密钥操作在 {retries} 次尝试后仍失败：{}",
                            crate::i18n::error_message(&error, self.language)
                        ),
                        crate::config::UiLanguage::En => format!(
                            "Host key operation failed after {retries} attempts: {}",
                            crate::i18n::error_message(&error, self.language)
                        ),
                    };
                    self.failed = true;
                    self.tested = false;
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                if let Some(job) = self.host_key_job.as_ref() {
                    self.message =
                        self.host_key_busy_message(job.kind, job.started, job.attempt, job.retries);
                }
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.host_key_job = None;
                self.message = self
                    .language
                    .text(
                        "Host key worker stopped unexpectedly.",
                        "主机密钥后台工作意外停止。",
                    )
                    .into();
                self.failed = true;
                self.tested = false;
            }
        }
    }
    fn action_busy_message(&self, job: &ActionJob) -> String {
        let elapsed = job.started.elapsed().as_secs_f32();
        let label = match job.kind {
            ActionJobKind::Test => self.language.text("测试连接", "Test connection"),
            ActionJobKind::Save => self.language.text("保存主机", "Save host"),
            ActionJobKind::SaveTest => self.language.text("保存并测试", "Save & test"),
            ActionJobKind::SaveExit => self.language.text("保存并退出", "Save & exit"),
        };
        match self.language {
            crate::config::UiLanguage::ZhCn => format!(
                "{} 正在{}... {:.1}s 第 {}/{} 次",
                host_key_spinner(job.started.elapsed()),
                label,
                elapsed,
                job.attempt,
                job.retries
            ),
            crate::config::UiLanguage::En => format!(
                "{} {}... {:.1}s attempt {}/{}",
                host_key_spinner(job.started.elapsed()),
                label,
                elapsed,
                job.attempt,
                job.retries
            ),
        }
    }

    fn spawn_action_attempt(&mut self) {
        let Some(job) = self.action_job.as_ref() else {
            return;
        };
        let (sender, receiver) = oneshot::channel();
        let kind = job.kind;
        let paths = job.paths.clone();
        let alias = job.alias.clone();
        let host = job.host.clone();
        let original = job.original.clone();
        let draft = job.draft.clone();
        let language = job.language;
        let pending = job.pending;
        tokio::task::spawn_blocking(move || {
            let handle = tokio::runtime::Handle::current();
            let result = match kind {
                ActionJobKind::Test => handle
                    .block_on(test_connection(&paths, &alias, &host, language, pending))
                    .map(ActionJobOutput::Tested),
                ActionJobKind::Save | ActionJobKind::SaveExit | ActionJobKind::SaveTest => handle
                    .block_on(persist_host_data(
                        &paths,
                        &alias,
                        &host,
                        original.as_ref(),
                        &draft,
                    ))
                    .map(|()| ActionJobOutput::Saved),
            };
            let _ = sender.send(result);
        });
        if let Some(job) = self.action_job.as_mut() {
            job.receiver = Some(receiver);
            job.retry_at = None;
        }
    }

    fn start_action_job(&mut self, kind: ActionJobKind, alias: String, host: Host) {
        let retries = if matches!(kind, ActionJobKind::Test) {
            self.retry_attempts.max(1)
        } else {
            1
        };
        self.action_job = Some(ActionJob {
            kind,
            paths: self.self_action_paths(),
            alias,
            host,
            original: self.original.clone(),
            draft: self.draft.clone(),
            language: self.language,
            pending: self.original.is_none(),
            started: Instant::now(),
            attempt: 1,
            retries,
            retry_at: None,
            receiver: None,
        });
        self.spawn_action_attempt();
        if let Some(job) = self.action_job.as_ref() {
            self.message = self.action_busy_message(job);
        }
        self.failed = false;
        self.tested = false;
    }

    fn self_action_paths(&self) -> AppPaths {
        self.paths.clone()
    }

    fn finish_saved(&mut self, kind: ActionJobKind, alias: String, warning: Option<String>) {
        match kind {
            ActionJobKind::Save => {
                let default_message = saved_message(self, &alias);
                self.message = combine_message(warning, default_message);
                self.failed = false;
                self.tested = false;
            }
            ActionJobKind::SaveExit => {
                let default_message = match self.language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("主机 '{alias}' 已覆盖保存并退出。")
                    }
                    crate::config::UiLanguage::En => {
                        format!("Host '{alias}' overwritten and exited.")
                    }
                };
                let message = combine_message(warning, default_message);
                self.result = Some(WizardResult {
                    saved_alias: Some(alias),
                    message,
                });
            }
            ActionJobKind::SaveTest => {
                let default_message = match self.language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("主机 '{alias}' 已覆盖保存，正在测试连接...", alias = alias)
                    }
                    crate::config::UiLanguage::En => {
                        format!(
                            "Host '{alias}' overwritten; testing connection...",
                            alias = alias
                        )
                    }
                };
                self.message = combine_message(warning, default_message);
                self.start_action_job(
                    ActionJobKind::Test,
                    alias,
                    self.draft.host().map(|(_, host)| host).unwrap_or_default(),
                );
            }
            ActionJobKind::Test => {}
        }
    }

    fn update_action_job(&mut self) {
        let Some(job) = self.action_job.as_mut() else {
            return;
        };
        if job.receiver.is_none() {
            if let Some(retry_at) = job.retry_at
                && Instant::now() >= retry_at
            {
                let attempt = job.attempt;
                let retries = job.retries;
                self.spawn_action_attempt();
                self.message = match self.language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("正在重试 第 {attempt}/{retries} 次...")
                    }
                    crate::config::UiLanguage::En => {
                        format!("Retrying attempt {attempt}/{retries}...")
                    }
                };
            }
            return;
        }
        let received = job
            .receiver
            .as_mut()
            .map(|receiver| receiver.try_recv())
            .unwrap_or(Err(oneshot::error::TryRecvError::Closed));
        match received {
            Ok(Ok(output)) => match output {
                ActionJobOutput::Tested((message, passed)) => {
                    self.action_job = None;
                    self.message = message;
                    self.failed = !passed;
                    self.tested = passed;
                }
                ActionJobOutput::Saved => {
                    let kind = job.kind;
                    let alias = job.alias.clone();
                    let host = job.host.clone();
                    self.action_job = None;
                    if self.draft.configure_sudo {
                        self.pending_sudo = Some((kind, alias, host));
                        self.message = match self.language {
                            crate::config::UiLanguage::ZhCn => {
                                "主机已保存，正在准备 sudo 配置...".to_string()
                            }
                            crate::config::UiLanguage::En => {
                                "Host saved; preparing sudo configuration...".to_string()
                            }
                        };
                        self.failed = false;
                        self.tested = false;
                    } else {
                        self.finish_saved(kind, alias, None);
                    }
                }
            },
            Ok(Err(error)) => {
                let attempt = job.attempt;
                let retries = job.retries;
                let kind = job.kind;
                if attempt < retries && action_retryable(&error) {
                    job.attempt = attempt + 1;
                    job.receiver = None;
                    job.retry_at = Some(Instant::now() + Duration::from_millis(250));
                    let detail = crate::i18n::error_message(&error, self.language);
                    self.message = match self.language {
                        crate::config::UiLanguage::ZhCn => {
                            format!("第 {attempt}/{retries} 次失败：{detail}\n正在重试...")
                        }
                        crate::config::UiLanguage::En => {
                            format!("Attempt {attempt}/{retries} failed: {detail}\nRetrying...")
                        }
                    };
                    self.failed = true;
                    self.tested = false;
                } else {
                    self.action_job = None;
                    self.message = match self.language {
                        crate::config::UiLanguage::ZhCn => format!(
                            "操作失败：{}",
                            crate::i18n::error_message(&error, self.language)
                        ),
                        crate::config::UiLanguage::En => format!(
                            "Operation failed: {}",
                            crate::i18n::error_message(&error, self.language)
                        ),
                    };
                    self.failed = true;
                    self.tested = false;
                    let _ = kind;
                }
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                if let Some(job) = self.action_job.as_ref() {
                    self.message = self.action_busy_message(job);
                }
            }
            Err(oneshot::error::TryRecvError::Closed) => {
                self.action_job = None;
                self.message = self
                    .language
                    .text(
                        "Background worker stopped unexpectedly.",
                        "后台工作意外停止。",
                    )
                    .into();
                self.failed = true;
                self.tested = false;
            }
        }
    }
}

async fn persist_host_data(
    paths: &AppPaths,
    alias: &str,
    host: &Host,
    original: Option<&Host>,
    draft: &Draft,
) -> Result<()> {
    if let Some(original) = original {
        crate::host::check_can_edit(paths, alias, original, host)?;
    } else {
        crate::host::check_can_add(paths, alias, host)?;
    }
    configure_ssh_credentials_data(paths, alias, host, draft).await?;
    if let Some(original) = original {
        crate::host::edit_host(paths, alias, original, host.clone())
    } else {
        crate::host::add_host(paths, alias, host.clone())
    }
}

async fn configure_ssh_credentials_data(
    paths: &AppPaths,
    alias: &str,
    host: &Host,
    draft: &Draft,
) -> Result<()> {
    if draft.reuse_credentials()
        || (host.auth != AuthMode::VaultPassword && host.auth != AuthMode::VaultKey)
    {
        return Ok(());
    }
    let client = BrokerClient::new(paths.clone());
    if !client.ping().await.is_ok() {
        client.ensure_running().await?;
    }
    let stem = host.credential.as_deref().unwrap_or(alias);
    if host.auth == AuthMode::VaultPassword {
        let password = draft.ssh_password.as_ref().ok_or_else(|| {
            AppError::invalid_argument("an SSH password is required for this authentication mode")
        })?;
        expect_secret_ack(
            client
                .call(RpcRequest::SetCredential {
                    name: crate::credential::ssh_credential_name(stem),
                    kind: "ssh-password".into(),
                    value: password.value().to_string(),
                })
                .await?,
        )?;
    } else {
        let name = crate::credential::key_credential_name(stem);
        let path = std::path::absolute(draft.private_key_path())
            .map_err(|error| AppError::io("resolve private key import path", error))?;
        expect_secret_ack(
            client
                .call(RpcRequest::ImportPrivateKey { name, path })
                .await?,
        )?;
        if let Some(password) = draft
            .ssh_password
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            expect_secret_ack(
                client
                    .call(RpcRequest::SetCredential {
                        name: crate::credential::ssh_credential_name(stem),
                        kind: "ssh-password".into(),
                        value: password.value().to_string(),
                    })
                    .await?,
            )?;
        }
    }
    Ok(())
}

/// Run the wizard inside an existing TUI. The caller restores its terminal mode afterwards.
pub async fn attach(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    paths: &AppPaths,
    alias: Option<String>,
    initial: Option<Host>,
    no_color: bool,
    original: Option<Host>,
) -> Result<WizardResult> {
    let mut wizard = Wizard::with_original(paths, alias, initial, original, no_color)?;
    loop {
        wizard.update_host_key_job();
        wizard.update_action_job();
        if let Some((kind, alias, host)) = wizard.pending_sudo.take() {
            match configure_sudo_if_requested(&mut wizard, terminal, &alias, &host).await {
                Ok(warning) => wizard.finish_saved(kind, alias, warning),
                Err(error) => {
                    wizard.message = crate::i18n::error_message(&error, wizard.language);
                    wizard.failed = true;
                    wizard.tested = false;
                }
            }
        }
        terminal
            .draw(|frame| draw(frame, &wizard))
            .map_err(|error| AppError::io("draw host wizard", error))?;
        if !event::poll(Duration::from_millis(200))
            .map_err(|error| AppError::io("poll host wizard input", error))?
        {
            continue;
        }
        let incoming =
            event::read().map_err(|error| AppError::io("read host wizard input", error))?;
        if let Event::Paste(text) = incoming {
            wizard.draft.paste(wizard.focused, &text);
            continue;
        }
        let Event::Key(key) = incoming else {
            continue;
        };
        if wizard.host_key_job.is_some() || wizard.action_job.is_some() {
            continue;
        }
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if wizard.exit_prompt {
            match key.code {
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    wizard.exit_prompt = false;
                    match wizard.draft.host() {
                        Ok((alias, host)) => {
                            wizard.start_action_job(ActionJobKind::SaveExit, alias, host);
                        }
                        Err(error) => {
                            wizard.message = crate::i18n::error_message(&error, wizard.language);
                            wizard.failed = true;
                        }
                    }
                }
                KeyCode::Enter => {
                    return Ok(WizardResult {
                        saved_alias: None,
                        message: wizard
                            .language
                            .text(
                                "Exited without saving. Credentials imported during testing or saving remain encrypted in Vault.",
                                "已退出，未保存主机配置；测试或保存过程中已导入的凭据仍以密文保留在 Vault 中。",
                            )
                            .into(),
                    });
                }
                KeyCode::Esc => {
                    wizard.exit_prompt = false;
                    wizard.failed = false;
                    wizard.tested = false;
                    wizard.message = wizard
                        .language
                        .text(
                            "Exit cancelled. Continue editing or choose an action.",
                            "已取消退出。可继续编辑或选择操作。",
                        )
                        .into();
                }
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Enter if wizard.focused >= ACTION_FETCH_HOST_KEY => match wizard.action() {
                Action::FetchHostKey => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        wizard.start_host_key_job(HostKeyJobKind::Fetch, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                        wizard.tested = false;
                    }
                },
                Action::TrustHostKey => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        if wizard.host_keys.is_empty() {
                            wizard.message = match wizard.language {
                                crate::config::UiLanguage::ZhCn => {
                                    "请先选择“获取主机密钥”。".to_string()
                                }
                                crate::config::UiLanguage::En => {
                                    "Choose Fetch host key first.".to_string()
                                }
                            };
                            wizard.failed = true;
                            wizard.tested = false;
                            continue;
                        }
                        if !wizard.host_key_confirm_pending {
                            wizard.host_key_confirm_pending = true;
                            let fingerprints = wizard
                                .host_keys
                                .iter()
                                .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                                .collect::<Vec<_>>()
                                .join("\n  ");
                            wizard.message = match wizard.language {
                                crate::config::UiLanguage::ZhCn => format!(
                                    "请确认你已人工核对以下主机密钥：\n  {fingerprints}\n再次按 Enter 信任，Esc 取消。"
                                ),
                                crate::config::UiLanguage::En => format!(
                                    "Confirm you manually verified these host keys:\n  {fingerprints}\nPress Enter again to trust, Esc to cancel."
                                ),
                            };
                            wizard.failed = false;
                            wizard.tested = false;
                            continue;
                        }
                        wizard.start_host_key_job(HostKeyJobKind::Trust, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                        wizard.tested = false;
                    }
                },
                Action::Test => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        let precondition = crate::host::check_can_add(paths, &alias, &host);
                        if let Err(error) = precondition {
                            wizard.message = crate::i18n::error_message(&error, wizard.language);
                            wizard.failed = true;
                            continue;
                        }
                        wizard.start_action_job(ActionJobKind::Test, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                    }
                },
                Action::Save => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        wizard.start_action_job(ActionJobKind::Save, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                    }
                },
                Action::SaveTest => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        wizard.start_action_job(ActionJobKind::SaveTest, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                    }
                },
                Action::SaveExit => match wizard.draft.host() {
                    Ok((alias, host)) => {
                        wizard.start_action_job(ActionJobKind::SaveExit, alias, host);
                    }
                    Err(error) => {
                        wizard.message = crate::i18n::error_message(&error, wizard.language);
                        wizard.failed = true;
                    }
                },
                Action::Exit => {
                    wizard.exit_prompt = true;
                    wizard.failed = false;
                    wizard.tested = false;
                    wizard.message = wizard
                            .language
                            .text(
                                "Exit: press S to save & exit, Enter to exit without saving, Esc to cancel.",
                                "退出：按 S 保存并退出，Enter 不保存退出，Esc 取消。",
                            )
                            .into();
                }
                Action::None => {}
            },
            other => wizard.handle_key_event(KeyEvent::new(other, key.modifiers)),
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
    run_inner(paths, alias, initial, no_color, None).await
}

/// Edit an existing registered Host without silently changing its credentials.
pub async fn run_edit(paths: &AppPaths, alias: String, no_color: bool) -> Result<WizardResult> {
    let config = crate::config::Config::load(&paths.config)?;
    let original = config.hosts.get(&alias).cloned().ok_or_else(|| {
        AppError::new(
            crate::error::ErrorCode::NotFound,
            format!("host '{alias}' was not found"),
        )
    })?;
    run_inner(
        paths,
        Some(alias),
        Some(original.clone()),
        no_color,
        Some(original),
    )
    .await
}

async fn run_inner(
    paths: &AppPaths,
    alias: Option<String>,
    initial: Option<Host>,
    no_color: bool,
    original: Option<Host>,
) -> Result<WizardResult> {
    enable_raw_mode().map_err(|error| AppError::io("enable wizard terminal", error))?;
    if let Err(error) = execute!(stdout(), EnableBracketedPaste, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(AppError::io("enter host wizard", error));
    }
    let backend = CrosstermBackend::new(stdout());
    let result = match Terminal::new(backend) {
        Ok(mut terminal) => attach(&mut terminal, paths, alias, initial, no_color, original).await,
        Err(error) => Err(AppError::io("create wizard terminal", error)),
    };
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), DisableBracketedPaste, LeaveAlternateScreen);
    result
}

pub(crate) async fn test_registered_connection(
    paths: &AppPaths,
    alias: &str,
    host: &Host,
    language: crate::config::UiLanguage,
) -> Result<(String, bool)> {
    test_connection(paths, alias, host, language, false).await
}

async fn test_connection(
    paths: &AppPaths,
    alias: &str,
    host: &Host,
    language: crate::config::UiLanguage,
    pending: bool,
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
    let auth_context = if pending {
        crate::transport::AuthenticationContext::pending(paths.clone(), alias, host)
    } else {
        crate::transport::AuthenticationContext::registered(paths.clone(), alias, host)
    };
    if auth_context.is_some() {
        let client = BrokerClient::new(paths.clone());
        if client.ping().await.is_err() {
            client.ensure_running().await?;
        }
    }
    let started = std::time::Instant::now();
    let outcome = OpensshTransport::default()
        .exec(ExecutionRequest {
            host: host.clone(),
            script: "true".into(),
            timeout: Duration::from_secs(8),
            max_output: 2048,
            sudo_password: None,
            auth_context,
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
            crate::i18n::error_message(&error, language),
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
    let password = crate::masked_prompt::prompt(wizard.language.text(
        "Independent sudo password (masked with *): ",
        "独立的 sudo 密码（以 * 掩码）：",
    ));
    crate::tui::resume(terminal)?;
    let value = password?;
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
        15 => language.text("[ Fetch host key ]", "[ 获取主机密钥 ]"),
        16 => language.text("[ Trust host key ]", "[ 信任主机密钥 ]"),
        17 => language.text("[ Test connection ]", "[ 测试连接 ]"),
        18 => language.text("[ Save ]", "[ 保存 ]"),
        19 => language.text("[ Save & exit ]", "[ 保存并退出 ]"),
        20 => language.text("[ Exit ]", "[ 退出 ]"),
        _ => "",
    }
}

fn field_label(wizard: &Wizard, index: usize) -> &'static str {
    match (wizard.original.is_some(), index, wizard.language) {
        (true, 0, crate::config::UiLanguage::En) => "Alias (fixed)",
        (true, 0, crate::config::UiLanguage::ZhCn) => "主机别名（固定）",
        (true, 17, crate::config::UiLanguage::En) => "[ Save & test ]",
        (true, 17, crate::config::UiLanguage::ZhCn) => "[ 保存并测试 ]",
        _ => label(index, wizard.language),
    }
}

fn pad_display(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(display_width(value));
    format!("{value}{}", " ".repeat(padding))
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
        Line::from(if wizard.original.is_some() {
            wizard.language.text(
                "Edit host · connection → credentials → review",
                "编辑主机 · 连接 → 凭据 → 复核",
            )
        } else {
            wizard.language.text(
                "Add host · connection → policy → review",
                "添加主机 · 连接 → 策略 → 复核",
            )
        }),
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
        .min(LAST_FOCUS.saturating_sub(visible.saturating_sub(1)));
    let label_width = body[0].width.saturating_sub(11).min(27) as usize;
    let value_offset = 4 + label_width as u16;
    let value_width = body[0].width.saturating_sub(value_offset + 1).max(1) as usize;
    let mut cursor_position = None;
    let items = (start..=LAST_FOCUS.min(start + visible.saturating_sub(1)))
        .map(|index| {
            let selected = index == wizard.focused;
            let indicator = if selected { " > " } else { "   " };
            let value = if selected && let Some(input) = wizard.draft.input(index) {
                let (window, cursor_column) =
                    input.window(value_width, (index == 13).then_some('*'));
                let x = (body[0].x + value_offset + cursor_column.min(value_width - 1) as u16)
                    .min(body[0].x + body[0].width.saturating_sub(2));
                let y = body[0].y + 1 + index.saturating_sub(start) as u16;
                cursor_position = Some((x, y));
                window
            } else {
                crate::redact::escape_controls(&wizard.draft.value(index, wizard.language))
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(
                        "{indicator}{}",
                        pad_display(field_label(wizard, index), label_width)
                    ),
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
                    value,
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
                "↑/↓ fields · ←/→ cursor/options · Home/End · Backspace/Delete · Ctrl+L clear · Enter action",
                "↑/↓ 字段 · ←/→ 光标/选项 · Home/End · 退格/Delete · Ctrl+L 清空 · Enter 执行操作",
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
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(footer, columns[2]);
    if let Some(position) = cursor_position {
        frame.set_cursor_position(position);
    }
}

fn draw_preview(frame: &mut ratatui::Frame, wizard: &Wizard, area: ratatui::layout::Rect) {
    let wizard_error = wizard.draft.host().err();
    let error_text = wizard_error
        .map(|error| crate::i18n::error_message(&error, wizard.language))
        .unwrap_or_else(|| {
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
            crate::redact::escape_controls(wizard.draft.alias.value())
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
                crate::redact::escape_controls(wizard.draft.address.value())
            }
        )),
        Line::from(format!(
            "port: {} · host number: {}",
            wizard.draft.port.value(),
            wizard.draft.number.value()
        )),
        Line::from(format!(
            "host key: {}",
            if wizard.host_key_trusted {
                wizard.language.text("trusted", "已信任")
            } else if wizard.host_keys.is_empty() {
                wizard.language.text("not fetched", "未获取")
            } else {
                wizard
                    .language
                    .text("fetched; verify then trust", "已获取；请核对后信任")
            }
        )),
        Line::from(format!(
            "environment: {} · platform: {:?}",
            crate::redact::escape_controls(wizard.draft.environment.value()),
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
    let preview = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(wizard.language.text("Configuration preview", "配置预览")),
        )
        .wrap(Wrap { trim: true });
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
        let mut draft = Draft::new(Some("prod".into()), None, &config, false)
            .unwrap_or_else(|error| panic!("draft: {error}"));
        draft.address = TextInput::with_value("real-prod", 256)
            .unwrap_or_else(|error| panic!("address: {error}"));
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
        let mut draft = Draft::new(None, None, &Config::default(), false)
            .unwrap_or_else(|error| panic!("draft: {error}"));
        draft.type_character(4, '2');
        draft.type_character(4, '2');
        draft.type_character(4, 'x');
        assert_eq!(draft.port.value(), "2222");
        draft.backspace(4);
        assert_eq!(draft.port.value(), "222");
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
        wizard.draft.ssh_password = Some(
            TextInput::with_value("two", 4096).unwrap_or_else(|error| panic!("secret: {error}")),
        );
        let auth = wizard.draft.auth;
        wizard.handle_key(KeyCode::Char(' '));
        wizard.handle_key(KeyCode::Char('x'));
        assert_eq!(
            wizard
                .draft
                .ssh_password
                .as_ref()
                .map(|value| value.value()),
            Some("two x"),
            "space must stay in a password rather than cycling authentication"
        );
        assert_eq!(wizard.draft.auth, auth);
        wizard.focused = 14;
        wizard.draft.private_key_path =
            TextInput::with_value("with", 512).unwrap_or_else(|error| panic!("path: {error}"));
        wizard.handle_key(KeyCode::Char(' '));
        wizard.handle_key(KeyCode::Char('k'));
        assert_eq!(wizard.draft.private_key_path.value(), "with k");
    }

    #[test]
    fn secret_values_are_never_rendered() {
        let mut draft = Draft::new(None, None, &Config::default(), false)
            .unwrap_or_else(|error| panic!("draft: {error}"));
        draft.auth = AuthMode::VaultPassword;
        draft.ssh_password = Some(
            TextInput::with_value("test-only-never-render-this", 4096)
                .unwrap_or_else(|error| panic!("secret: {error}")),
        );
        let expected_mask = "*".repeat(
            draft
                .ssh_password
                .as_ref()
                .map(TextInput::len_chars)
                .unwrap_or_default(),
        );
        assert_eq!(
            draft.value(13, crate::config::UiLanguage::En),
            expected_mask
        );
        assert_eq!(
            draft.value(13, crate::config::UiLanguage::ZhCn),
            expected_mask
        );
        assert!(
            !draft
                .value(13, crate::config::UiLanguage::En)
                .contains("test-only-never-render-this")
        );
    }

    #[test]
    fn edit_reuses_credentials_and_rotates_only_when_explicitly_replaced() {
        let original = Host {
            hostname: Some("oracle.example".into()),
            username: Some("ubuntu".into()),
            auth: AuthMode::VaultKey,
            credential: Some("oracle-production".into()),
            ..Host::default()
        };
        let mut draft = Draft::new(
            Some("oracle".into()),
            Some(original.clone()),
            &Config::default(),
            true,
        )
        .unwrap_or_else(|error| panic!("draft: {error}"));
        let (_, unchanged) = draft
            .host()
            .unwrap_or_else(|error| panic!("unchanged: {error}"));
        assert_eq!(unchanged.credential, original.credential);
        assert!(draft.reuse_credentials());

        draft.move_home(0);
        draft.delete(0);
        assert_eq!(draft.alias.value(), "oracle");
        draft.paste(14, "\"C:\\test\\id_ed25519\"");
        let (_, rotated) = draft
            .host()
            .unwrap_or_else(|error| panic!("rotated: {error}"));
        assert_eq!(draft.private_key_path(), "C:\\test\\id_ed25519");
        assert!(!draft.reuse_credentials());
        assert_ne!(rotated.credential, original.credential);
        assert!(
            rotated
                .credential
                .as_deref()
                .is_some_and(|stem| stem.starts_with("oracle:rotation:"))
        );
    }

    #[tokio::test]
    async fn nonsecret_edit_does_not_require_a_running_broker_or_secret_reentry() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        crate::config::Config::initialize(&paths.config)
            .unwrap_or_else(|error| panic!("config: {error}"));
        let original = Host {
            hostname: Some("192.0.2.40".into()),
            username: Some("ubuntu".into()),
            auth: AuthMode::VaultPassword,
            credential: Some("oracle-original".into()),
            ..Host::default()
        };
        crate::host::add_host(&paths, "oracle", original.clone())
            .unwrap_or_else(|error| panic!("add: {error}"));
        let mut wizard = Wizard::with_original(
            &paths,
            Some("oracle".into()),
            Some(original.clone()),
            Some(original),
            true,
        )
        .unwrap_or_else(|error| panic!("wizard: {error}"));
        wizard.draft.clear(3);
        wizard.draft.paste(3, "opc");
        let (alias, host) = wizard
            .draft
            .host()
            .unwrap_or_else(|error| panic!("draft host: {error}"));
        persist_host_data(
            &paths,
            &alias,
            &host,
            wizard.original.as_ref(),
            &wizard.draft,
        )
        .await
        .unwrap_or_else(|error| panic!("persist: {error}"));
        let after = Config::load(&paths.config).unwrap_or_else(|error| panic!("load: {error}"));
        assert_eq!(after.hosts.get("oracle"), Some(&host));
        assert_eq!(host.username.as_deref(), Some("opc"));
        assert_eq!(host.credential.as_deref(), Some("oracle-original"));
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
        wizard.focused = 19;
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
        assert!(compact.contains("获取主机密钥"));
        assert!(compact.contains("信任主机密钥"));
        assert!(compact.contains("测试连接"));
        assert!(compact.contains("保存"));
        assert!(compact.contains("保存并退出"));
        assert!(compact.contains("退出"));
        assert!(compact.contains("认证方式"));
    }

    #[test]
    fn edit_actions_are_bios_style_and_save_test_stays_in_the_wizard() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        crate::config::Config::initialize(&paths.config)
            .unwrap_or_else(|error| panic!("config: {error}"));
        let host = Host {
            hostname: Some("192.0.2.10".into()),
            ..Host::default()
        };
        let mut wizard = Wizard::with_original(
            &paths,
            Some("prod-01".into()),
            Some(host.clone()),
            Some(host),
            false,
        )
        .unwrap_or_else(|error| panic!("wizard: {error}"));
        assert_eq!(field_label(&wizard, 15), "[ Fetch host key ]");
        assert_eq!(field_label(&wizard, 16), "[ Trust host key ]");
        assert_eq!(field_label(&wizard, 17), "[ Save & test ]");
        assert_eq!(field_label(&wizard, 18), "[ Save ]");
        assert_eq!(field_label(&wizard, 19), "[ Save & exit ]");
        assert_eq!(field_label(&wizard, 20), "[ Exit ]");

        wizard.focused = 15;
        assert!(matches!(wizard.action(), Action::FetchHostKey));
        wizard.focused = 16;
        assert!(matches!(wizard.action(), Action::TrustHostKey));
        wizard.focused = 17;
        assert!(matches!(wizard.action(), Action::SaveTest));
        wizard.focused = 18;
        assert!(matches!(wizard.action(), Action::Save));
        wizard.focused = 19;
        assert!(matches!(wizard.action(), Action::SaveExit));
        wizard.focused = 20;
        assert!(matches!(wizard.action(), Action::Exit));

        wizard.handle_key_event(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(wizard.exit_prompt);
        assert!(wizard.result.is_none());
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
        wizard.draft.address = TextInput::with_value("example.invalid", 256)
            .unwrap_or_else(|error| panic!("address: {error}"));
        wizard.focused = 19;
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(96, 36))
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
        assert!(content.contains("Fetch host key"));
        assert!(content.contains("Trust host key"));
        assert!(content.contains("Test connection"));
        assert!(content.contains("Save"));
        assert!(content.contains("Save & exit"));
        assert!(content.contains("Exit"));
        assert!(!content.contains('\u{1b}'));
    }
}
