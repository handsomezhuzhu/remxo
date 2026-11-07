use crate::error::{AppError, ErrorCode, Result};
use crate::store::{atomic_write, create_new, ensure_private_dir};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    Ssh,
    Telnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    ExternalAgent,
    OpensshConfig,
    VaultPassword,
    VaultKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    Macos,
    Windows,
    #[serde(rename = "network-device")]
    NetworkDevice,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    Posix,
    Powershell,
    Cmd,
    Device,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RawMode {
    Allow,
    ReadOnly,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    Never,
    Writes,
    Always,
}

fn default_transport() -> TransportKind {
    TransportKind::Ssh
}
fn default_auth() -> AuthMode {
    AuthMode::OpensshConfig
}
fn default_platform() -> Platform {
    Platform::Linux
}
fn default_shell() -> ShellKind {
    ShellKind::Posix
}
fn default_raw_mode() -> RawMode {
    RawMode::Allow
}
fn default_approval() -> ApprovalMode {
    ApprovalMode::Writes
}
fn default_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<u32>,
    #[serde(default = "default_transport")]
    pub transport: TransportKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default = "default_platform")]
    pub platform: Platform,
    #[serde(default = "default_shell")]
    pub shell: ShellKind,
    #[serde(default = "default_auth")]
    pub auth: AuthMode,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_raw_mode")]
    pub raw_mode: RawMode,
    #[serde(default = "default_approval")]
    pub approval: ApprovalMode,
    #[serde(default)]
    pub insecure_acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo_credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

impl Host {
    pub fn validate(&self, alias: &str) -> Result<()> {
        if alias.is_empty()
            || alias.chars().all(|c| c.is_ascii_digit())
            || alias.chars().any(|c| c.is_whitespace() || c == '\0')
        {
            return Err(AppError::new(
                ErrorCode::InvalidConfig,
                "host aliases must be non-empty, non-numeric, and contain no whitespace",
            ));
        }
        if self.number == Some(0) || self.port == 0 {
            return Err(AppError::new(
                ErrorCode::InvalidConfig,
                format!("host {alias}: numbers and ports must be greater than zero"),
            ));
        }
        match self.transport {
            TransportKind::Ssh => {
                if self.ssh_alias.is_none() && self.hostname.is_none() {
                    return Err(AppError::new(
                        ErrorCode::InvalidConfig,
                        format!("host {alias}: ssh_alias or hostname is required"),
                    ));
                }
            }
            TransportKind::Telnet => {
                if self.hostname.is_none() {
                    return Err(AppError::new(
                        ErrorCode::InvalidConfig,
                        format!("host {alias}: telnet requires hostname"),
                    ));
                }
            }
        }
        for value in [&self.ssh_alias, &self.hostname, &self.username]
            .into_iter()
            .flatten()
        {
            if value.is_empty()
                || value.starts_with('-')
                || value.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(AppError::new(
                    ErrorCode::InvalidConfig,
                    format!("host {alias}: invalid connection field"),
                ));
            }
        }
        Ok(())
    }

    pub fn destination(&self) -> String {
        if let Some(alias) = &self.ssh_alias {
            return alias.clone();
        }
        let hostname = self.hostname.as_deref().unwrap_or_default();
        match &self.username {
            Some(username) => format!("{username}@{hostname}"),
            None => hostname.to_string(),
        }
    }
}

impl Default for Host {
    fn default() -> Self {
        Self {
            number: None,
            transport: TransportKind::Ssh,
            ssh_alias: None,
            hostname: None,
            port: 22,
            username: None,
            platform: Platform::Linux,
            shell: ShellKind::Posix,
            auth: AuthMode::OpensshConfig,
            environment: String::new(),
            tags: Vec::new(),
            raw_mode: RawMode::Allow,
            approval: ApprovalMode::Writes,
            insecure_acknowledged: false,
            sudo_credential: None,
            credential: None,
            prompt: None,
        }
    }
}

fn default_timeout() -> u64 {
    30
}
fn default_max_output() -> usize {
    65_536
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UiLanguage {
    #[default]
    En,
    #[serde(rename = "zh-CN")]
    ZhCn,
}

impl UiLanguage {
    pub fn text(self, english: &'static str, chinese: &'static str) -> &'static str {
        match self {
            Self::En => english,
            Self::ZhCn => chinese,
        }
    }

    pub fn from_arg(arg: &str) -> Result<Self> {
        match arg.trim().to_ascii_lowercase().as_str() {
            "en" | "english" => Ok(Self::En),
            "zh" | "cn" | "zh-cn" | "zh_cn" | "chinese" | "中文" => Ok(Self::ZhCn),
            _ => Err(AppError::invalid_argument("language must be en or zh-CN")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub allow_ad_hoc: bool,
    pub timeout_seconds: u64,
    pub max_output: usize,
    pub allow_overwrite: bool,
    pub audit_output: bool,
    pub language: UiLanguage,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_ad_hoc: false,
            timeout_seconds: default_timeout(),
            max_output: default_max_output(),
            allow_overwrite: false,
            audit_output: false,
            language: UiLanguage::En,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub hosts: BTreeMap<String, Host>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            settings: Settings::default(),
            hosts: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AppError::new(
                ErrorCode::InvalidConfig,
                format!("unsupported config schema version: {}", self.version),
            ));
        }
        if self.settings.timeout_seconds == 0 || self.settings.max_output == 0 {
            return Err(AppError::new(
                ErrorCode::InvalidConfig,
                "timeout_seconds and max_output must be greater than zero",
            ));
        }
        let mut numbers = BTreeMap::new();
        for (alias, host) in &self.hosts {
            host.validate(alias)?;
            if let Some(number) = host.number
                && numbers.insert(number, alias).is_some()
            {
                return Err(AppError::new(
                    ErrorCode::InvalidConfig,
                    format!("duplicate host number: {number}"),
                ));
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|e| AppError::io("read configuration", e))?;
        let config: Self = toml::from_str(&text).map_err(|e| {
            AppError::new(
                ErrorCode::InvalidConfig,
                format!("invalid TOML configuration: {e}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn initialize(path: &Path) -> Result<Self> {
        Self::initialize_with_language(path, UiLanguage::En)
    }

    pub fn initialize_with_language(path: &Path, language: UiLanguage) -> Result<Self> {
        let mut config = Self::default();
        config.settings.language = language;
        let text = toml::to_string_pretty(&config)
            .map_err(|e| AppError::internal(format!("serialize default config: {e}")))?;
        create_new(path, text.as_bytes())?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if path.exists() {
            let old = std::fs::read(path).map_err(|e| AppError::io("back up config", e))?;
            let backup =
                path.with_extension(format!("toml.{}.bak", chrono::Utc::now().timestamp()));
            atomic_write(&backup, &old)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| AppError::internal(format!("serialize config: {e}")))?;
        atomic_write(path, text.as_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root: PathBuf,
    pub config: PathBuf,
}

impl AppPaths {
    pub fn new(config: Option<PathBuf>) -> Result<Self> {
        let config = match config {
            Some(path) => path,
            None => dirs::config_dir()
                .ok_or_else(|| AppError::internal("cannot determine user configuration directory"))?
                .join("remxo")
                .join("config.toml"),
        };
        let root = config
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        ensure_private_dir(&root)?;
        Ok(Self { root, config })
    }

    pub fn vault(&self) -> PathBuf {
        self.root.join("vault.json")
    }
    pub fn broker(&self) -> PathBuf {
        self.root.join("broker.json")
    }
    pub fn audit(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }
    pub fn tasks(&self) -> PathBuf {
        self.root.join("tasks.json")
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub alias: String,
    pub host: Host,
}

pub fn resolve_target(config: &Config, target: &str) -> Result<ResolvedTarget> {
    if let Some(host) = config.hosts.get(target) {
        return Ok(ResolvedTarget {
            alias: target.to_string(),
            host: host.clone(),
        });
    }
    if let Ok(number) = target.parse::<u32>()
        && let Some((alias, host)) = config
            .hosts
            .iter()
            .find(|(_, host)| host.number == Some(number))
    {
        return Ok(ResolvedTarget {
            alias: alias.clone(),
            host: host.clone(),
        });
    }
    if let Ok(ip) = target.parse::<IpAddr>() {
        if let Some((alias, host)) = config.hosts.iter().find(|(_, host)| {
            host.hostname
                .as_deref()
                .and_then(|value| value.parse::<IpAddr>().ok())
                == Some(ip)
        }) {
            return Ok(ResolvedTarget {
                alias: alias.clone(),
                host: host.clone(),
            });
        }
        if config.settings.allow_ad_hoc {
            let host = Host {
                number: None,
                transport: TransportKind::Ssh,
                ssh_alias: None,
                hostname: Some(target.to_string()),
                port: 22,
                username: None,
                platform: Platform::Linux,
                shell: ShellKind::Posix,
                auth: AuthMode::OpensshConfig,
                environment: "ad-hoc".to_string(),
                tags: Vec::new(),
                raw_mode: RawMode::Allow,
                approval: ApprovalMode::Writes,
                insecure_acknowledged: false,
                sudo_credential: None,
                credential: None,
                prompt: None,
            };
            return Ok(ResolvedTarget {
                alias: target.to_string(),
                host,
            });
        }
        return Err(AppError::new(
            ErrorCode::HostNotAllowed,
            "IP is not registered; ad-hoc targets are disabled by policy",
        ));
    }
    Err(AppError::new(
        ErrorCode::HostNotFound,
        format!("host not found: {target}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> Config {
        let mut config = Config::default();
        config.hosts.insert(
            "prod-01".into(),
            Host {
                number: Some(2),
                hostname: Some("10.0.0.8".into()),
                approval: ApprovalMode::Never,
                ..Host::default()
            },
        );
        config
    }

    #[test]
    fn language_is_persisted_and_old_configs_default_to_english() {
        let mut config = Config::default();
        assert_eq!(config.settings.language, UiLanguage::En);
        config.settings.language = UiLanguage::ZhCn;
        let serialized = toml::to_string(&config).unwrap_or_else(|error| panic!("toml: {error}"));
        assert!(serialized.contains("zh-CN"));
        let restored: Config =
            toml::from_str(&serialized).unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(restored.settings.language, UiLanguage::ZhCn);
        let legacy: Config = toml::from_str("version = 1\n")
            .unwrap_or_else(|error| panic!("legacy config: {error}"));
        assert_eq!(legacy.settings.language, UiLanguage::En);
    }

    #[test]
    fn resolves_alias_number_and_registered_ip_in_order() {
        let config = inventory();
        assert_eq!(
            resolve_target(&config, "prod-01")
                .map(|v| v.alias)
                .ok()
                .as_deref(),
            Some("prod-01")
        );
        assert_eq!(
            resolve_target(&config, "2")
                .map(|v| v.alias)
                .ok()
                .as_deref(),
            Some("prod-01")
        );
        assert_eq!(
            resolve_target(&config, "10.0.0.8")
                .map(|v| v.alias)
                .ok()
                .as_deref(),
            Some("prod-01")
        );
        assert_eq!(
            resolve_target(&config, "unknown").err().map(|e| e.code),
            Some(ErrorCode::HostNotFound)
        );
    }

    #[test]
    fn unregistered_ip_is_denied_unless_ad_hoc_is_explicit() {
        let mut config = inventory();
        assert_eq!(
            resolve_target(&config, "192.0.2.99").err().map(|e| e.code),
            Some(ErrorCode::HostNotAllowed)
        );
        config.settings.allow_ad_hoc = true;
        let target =
            resolve_target(&config, "192.0.2.99").unwrap_or_else(|e| panic!("resolve: {e}"));
        assert_eq!(target.alias, "192.0.2.99");
        assert_eq!(target.host.approval, ApprovalMode::Writes);
    }

    #[test]
    fn duplicate_numbers_and_numeric_aliases_are_rejected() {
        let mut config = inventory();
        config.hosts.insert(
            "second".into(),
            Host {
                number: Some(2),
                hostname: Some("10.0.0.9".into()),
                ..Host::default()
            },
        );
        assert!(config.validate().is_err());
        let mut config = inventory();
        config.hosts.insert(
            "3".into(),
            Host {
                hostname: Some("10.0.0.10".into()),
                ..Host::default()
            },
        );
        assert_eq!(
            config.validate().err().map(|e| e.code),
            Some(ErrorCode::InvalidConfig)
        );
    }

    #[test]
    fn unknown_toml_fields_fail_closed() {
        assert!(toml::from_str::<Config>("version = 1\n[settings]\nunknown = true\n").is_err());
        assert!(
            toml::from_str::<Config>(
                "version = 1\n[hosts.prod]\nhostname = '192.0.2.1'\nunknown = true\n"
            )
            .is_err()
        );
    }

    #[test]
    fn connection_fields_cannot_become_local_cli_options() {
        let host = Host {
            hostname: Some("-oProxyCommand=bad".into()),
            ..Host::default()
        };
        assert!(host.validate("example").is_err());
        let host = Host {
            username: Some("bad user".into()),
            hostname: Some("192.0.2.1".into()),
            ..Host::default()
        };
        assert!(host.validate("example").is_err());
        let host = Host {
            ssh_alias: Some("real-openssh-alias".into()),
            hostname: Some("192.0.2.1".into()),
            ..Host::default()
        };
        assert!(host.validate("example").is_ok());
        let paths = AppPaths::new(Some(PathBuf::from("relative-config.toml")))
            .unwrap_or_else(|e| panic!("relative paths: {e}"));
        assert_eq!(paths.root, PathBuf::from("."));
    }
}
