use crate::backup;
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{
    AppPaths, ApprovalMode, AuthMode, Config, Host, Platform, RawMode, ShellKind, TransportKind,
    resolve_target,
};
use crate::error::{AppError, ErrorCode, Result};
use crate::model::{OperationReport, OperationStatus, StatusReport};
use crate::transfer;
use crate::transport::openssh::OpensshTransport;
use crate::vault::VaultSession;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "remxo",
    version,
    about = "Remote execution for humans and agents",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub no_color: bool,
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<u64>,
    #[arg(long)]
    pub max_output: Option<usize>,
    #[arg(long)]
    pub cwd: Option<String>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub verbose: bool,
    #[arg(long)]
    pub sudo: bool,
    #[arg(long)]
    pub overwrite: bool,
    #[arg(long)]
    pub retries: Option<u32>,
    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Debug, Subcommand)]
enum Action {
    Init {
        #[arg(long)]
        lang: Option<String>,
    },
    Status,
    Unlock,
    Lock {
        #[arg(long)]
        stop_broker: bool,
    },
    Tui,
    Doctor {
        target: Option<String>,
    },
    Hosts,
    #[command(subcommand)]
    Host(HostAction),
    #[command(subcommand)]
    Vault(VaultAction),
    #[command(subcommand)]
    Backup(BackupAction),
    #[command(subcommand)]
    Task(TaskAction),
    #[command(subcommand)]
    Tunnel(TunnelAction),
    #[command(subcommand)]
    Approval(ApprovalAction),
    Put {
        local: PathBuf,
        remote: String,
    },
    Get {
        remote: String,
        local: PathBuf,
    },
    Sftp {
        target: String,
    },
    #[command(name = "__broker", hide = true)]
    Broker,
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Debug, Subcommand)]
enum HostAction {
    Add(Box<HostAdd>),
    Edit {
        alias: String,
    },
    Remove {
        alias: String,
        #[arg(long)]
        yes: bool,
    },
    #[command(subcommand)]
    Key(HostKeyAction),
}

#[derive(Debug, Subcommand)]
enum HostKeyAction {
    Status {
        target: String,
    },
    Fetch {
        target: String,
    },
    Trust {
        target: String,
        #[arg(long)]
        fingerprint: Option<String>,
    },
    List,
    Remove {
        target: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct HostAdd {
    alias: Option<String>,
    #[arg(long)]
    interactive: bool,
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    ssh_alias: Option<String>,
    #[arg(long)]
    number: Option<u32>,
    #[arg(long, default_value = "ssh")]
    transport: String,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long, default_value = "linux")]
    platform: String,
    #[arg(long, default_value = "posix")]
    shell: String,
    #[arg(long, default_value = "openssh-config")]
    auth: String,
    #[arg(long, default_value = "")]
    environment: String,
    #[arg(long, default_value = "allow")]
    raw_mode: String,
    #[arg(long, default_value = "writes")]
    approval: String,
    #[arg(long)]
    tags: Option<String>,
    #[arg(long)]
    ack_insecure: bool,
    #[arg(long)]
    configure_sudo: bool,
}

#[derive(Debug, Subcommand)]
enum VaultAction {
    ChangePassword,
    SetSudo {
        host: String,
    },
    SetSshPassword {
        host: String,
    },
    ImportKey {
        host: String,
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum BackupAction {
    Create {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
    },
    Restore {
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TaskAction {
    Start {
        target: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    List,
    Status {
        id: String,
    },
    Logs {
        id: String,
    },
    Stop {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum TunnelAction {
    Start {
        target: String,
        #[arg(long)]
        local: Option<String>,
        #[arg(long)]
        remote: Option<String>,
        #[arg(long)]
        dynamic: Option<u16>,
        #[arg(long)]
        yes: bool,
    },
    List,
    Stop {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalAction {
    List,
    Approve { id: String },
}

pub async fn askpass_entry(arguments: Vec<std::ffi::OsString>) -> ExitCode {
    match run_askpass(arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("remxo askpass [{:?}]: {}", error.code, error.message);
            ExitCode::from(2)
        }
    }
}

async fn run_askpass(arguments: Vec<std::ffi::OsString>) -> Result<()> {
    let prompt = match arguments.as_slice() {
        [prompt] => prompt.as_os_str(),
        _ => {
            return Err(AppError::invalid_argument(
                "the internal ASKPASS helper accepts exactly one OpenSSH prompt",
            ));
        }
    };
    validate_askpass_prompt(Some(prompt))?;
    let config = std::env::var_os("REMXO_ASKPASS_CONFIG")
        .map(PathBuf::from)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::InvalidConfig,
                "the internal ASKPASS helper was not launched by Remxo",
            )
        })?;
    let paths = AppPaths::new(Some(config))?;
    let target = required_askpass_environment("REMXO_ASKPASS_TARGET")?;
    let pending_host = std::env::var_os("REMXO_ASKPASS_PENDING_HOST")
        .map(|value| {
            let value = value.into_string().map_err(|_| {
                AppError::invalid_argument("invalid internal ASKPASS pending-host context")
            })?;
            serde_json::from_str::<Host>(&value).map_err(|_| {
                AppError::invalid_argument("invalid internal ASKPASS pending-host context")
            })
        })
        .transpose()?;
    let client = BrokerClient::new(paths);
    let response = client
        .call(RpcRequest::SecretForAuth {
            target,
            pending_host,
            private_key: false,
        })
        .await?;
    let RpcPayload::Secret { kind, value } = response else {
        return Err(AppError::internal("unexpected askpass response"));
    };
    let value = Zeroizing::new(value);
    if kind != crate::credential::SSH_PASSWORD_KIND {
        return Err(AppError::new(
            ErrorCode::AuthenticationFailed,
            "the requested credential is not an SSH password or private key passphrase",
        ));
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.as_bytes())
        .and_then(|_| stdout.write_all(b"\n"))
        .and_then(|_| stdout.flush())
        .map_err(|error| AppError::io("send secret to OpenSSH askpass", error))
}

pub async fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let config_path = cli.config.clone();
    match dispatch(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if json {
                let value = serde_json::json!({"error": error.detail()});
                println!("{}", serde_json::to_string(&value).unwrap_or_else(|_| "{\"error\":{\"code\":\"internal_error\",\"message\":\"JSON serialization failed\"}}".into()));
            } else {
                let language = AppPaths::new(config_path)
                    .map(|paths| human_language(&paths))
                    .unwrap_or_default();
                eprintln!(
                    "remxo [{:?}]: {}",
                    error.code,
                    crate::i18n::error_message(&error, language)
                );
            }
            ExitCode::from(2)
        }
    }
}

fn human_language(paths: &AppPaths) -> crate::config::UiLanguage {
    Config::load(&paths.config)
        .map(|config| config.settings.language)
        .unwrap_or_default()
}

async fn dispatch(mut cli: Cli) -> Result<u8> {
    let paths = AppPaths::new(cli.config.clone())?;
    let language = human_language(&paths);
    match cli.action.take() {
        Some(Action::Init { lang }) => {
            if paths.vault().exists() {
                return Err(AppError::new(
                    ErrorCode::AlreadyExists,
                    "Vault already exists; init will not overwrite it. Run 'remxo status' to inspect the current installation or choose a fresh --config path",
                ));
            }
            if paths.config.exists() {
                Config::load(&paths.config)?;
            }
            let language = choose_language(lang, cli.json)?;
            if !cli.json {
                eprintln!(
                    "{}",
                    if language == crate::config::UiLanguage::ZhCn {
                        "主密码至少需要 12 字节，重启后需要用它解锁；校验成功前不会写入配置或 Vault"
                    } else {
                        "Master password must contain at least 12 bytes. It is required to unlock after restarts; no configuration or Vault is written until both entries pass validation."
                    }
                );
            }
            let password = hidden_password_confirmed_with(
                language.text("New master password: ", "新主密码："),
                language.text("Confirm password: ", "确认主密码："),
            )?;
            let recovered = initialize_data_directory(&paths, &password, language)?;
            let message = match (recovered, language) {
                (true, crate::config::UiLanguage::ZhCn) => {
                    "已恢复初始化：保留了原配置并创建了新的 Locked Vault。下一步运行 remxo unlock"
                }
                (false, crate::config::UiLanguage::ZhCn) => {
                    "初始化完成，Vault 处于锁定状态。下一步运行 remxo unlock"
                }
                (true, crate::config::UiLanguage::En) => {
                    "Resumed incomplete initialization: existing configuration was preserved and a new Vault was created in the Locked state. Next: remxo unlock"
                }
                (false, crate::config::UiLanguage::En) => {
                    "Initialized config and locked Vault. Next: remxo unlock"
                }
            };
            emit(
                &serde_json::json!({"initialized": true, "recovered": recovered, "vault_locked": true}),
                cli.json,
                message,
            )?;
        }
        Some(Action::Broker) => crate::broker::serve(paths).await?,
        Some(Action::Status) => {
            let client = BrokerClient::new(paths.clone());
            let status = match client.call(RpcRequest::Status).await {
                Ok(RpcPayload::Status(status)) => status,
                Ok(_) => return Err(AppError::internal("unexpected status response")),
                Err(_) => StatusReport {
                    schema_version: 1,
                    vault_exists: paths.vault().exists(),
                    vault_locked: true,
                    broker_running: false,
                    hosts: if paths.config.exists() {
                        Config::load(&paths.config)?.hosts.len()
                    } else {
                        0
                    },
                    agent_available: None,
                },
            };
            emit(
                &status,
                cli.json,
                &status_report_text(&status, language, &paths),
            )?;
        }
        Some(Action::Unlock) => {
            let language = Config::load(&paths.config)
                .map(|config| config.settings.language)
                .unwrap_or_default();
            let password = hidden_password(language.text("Master password: ", "主密码："))?;
            let client = connected_client(paths).await?;
            expect_ack(
                client
                    .call(RpcRequest::Unlock {
                        password: password.to_string(),
                    })
                    .await?,
            )?;
            emit(
                &serde_json::json!({"vault_locked": false}),
                cli.json,
                language.text(
                    "Vault unlocked in the local Broker.",
                    "本地 Broker 中的 Vault 已解锁。",
                ),
            )?;
        }
        Some(Action::Lock { stop_broker }) => {
            let client = BrokerClient::new(paths);
            if client.ping().await.is_ok() {
                if stop_broker {
                    expect_ack(client.call(RpcRequest::Shutdown).await?)?;
                } else {
                    expect_ack(client.call(RpcRequest::Lock).await?)?;
                }
            }
            emit(
                &serde_json::json!({
                    "vault_locked": true,
                    "broker_shutdown_requested": stop_broker
                }),
                cli.json,
                if stop_broker {
                    language.text(
                        "Vault locked; Broker shutdown acknowledged.",
                        "Vault 已锁定；Broker 已确认关闭。",
                    )
                } else {
                    language.text("Vault locked.", "Vault 已锁定。")
                },
            )?;
        }
        Some(Action::Hosts) => {
            let config = Config::load(&paths.config)?;
            if cli.json {
                emit(&config.hosts, true, "")?;
            } else {
                println!(
                    "{}",
                    language.text(
                        "ALIAS\tNUMBER\tTRANSPORT\tENVIRONMENT\tAUTH\tSECURITY",
                        "别名\t编号\t传输\t环境\t认证\t安全性",
                    )
                );
                for (alias, host) in config.hosts {
                    let auth = match host.auth {
                        AuthMode::OpensshConfig => language.text("OpenSSH config", "OpenSSH 配置"),
                        AuthMode::ExternalAgent => language.text("External agent", "外部 Agent"),
                        AuthMode::VaultPassword => language.text("Vault password", "Vault 密码"),
                        AuthMode::VaultKey => language.text("Vault private key", "Vault 私钥"),
                    };
                    println!(
                        "{alias}\t{}\t{:?}\t{}\t{}\t{}",
                        host.number.map(|n| n.to_string()).unwrap_or_default(),
                        host.transport,
                        host.environment,
                        auth,
                        if host.transport == TransportKind::Telnet {
                            language.text("INSECURE", "不安全")
                        } else {
                            language.text("encrypted", "加密")
                        }
                    );
                }
            }
        }
        Some(Action::Host(HostAction::Add(add))) => host_add(&paths, &cli, *add).await?,
        Some(Action::Host(HostAction::Edit { alias })) => {
            if cli.json {
                return Err(AppError::invalid_argument(
                    "interactive host editing cannot be combined with --json",
                ));
            }
            require_tui_terminal()?;
            let result = crate::tui_wizard::run_edit(&paths, alias, cli.no_color).await?;
            emit(
                &serde_json::json!({"edited": result.saved_alias, "message": result.message}),
                false,
                &result.message,
            )?;
        }
        Some(Action::Host(HostAction::Remove { alias, yes })) => {
            if !yes {
                return Err(AppError::invalid_argument(
                    "host removal requires --yes; existing config is backed up before replacement",
                ));
            }
            let mut config = Config::load(&paths.config)?;
            if config.hosts.remove(&alias).is_none() {
                return Err(AppError::new(ErrorCode::NotFound, "host not found"));
            }
            config.save(&paths.config)?;
            emit(
                &serde_json::json!({"removed": alias}),
                cli.json,
                language.text(
                    "Host removed (previous config backed up).",
                    "主机已删除（原配置已备份）。",
                ),
            )?;
        }
        Some(Action::Host(HostAction::Key(action))) => {
            host_key_command(&paths, &cli, action, language)?
        }
        Some(Action::Vault(VaultAction::ChangePassword)) => {
            let old = hidden_password("Current master password: ")?;
            let new = hidden_password_confirmed("New master password: ")?;
            let client = connected_client(paths).await?;
            expect_ack(
                client
                    .call(RpcRequest::ChangePassword {
                        old: old.to_string(),
                        new: new.to_string(),
                    })
                    .await?,
            )?;
            emit(
                &serde_json::json!({"changed": true}),
                cli.json,
                "Master password changed; encrypted records were preserved.",
            )?;
        }
        Some(Action::Vault(VaultAction::SetSudo { host })) => {
            let config = Config::load(&paths.config)?;
            let target = resolve_target(&config, &host)?;
            let password = hidden_password("Sudo password (hidden): ")?;
            let name = target
                .host
                .sudo_credential
                .clone()
                .unwrap_or(target.alias.clone());
            let client = connected_client(paths).await?;
            expect_ack(
                client
                    .call(RpcRequest::SetCredential {
                        name,
                        kind: "sudo-password".into(),
                        value: password.to_string(),
                    })
                    .await?,
            )?;
            emit(
                &serde_json::json!({"configured": true}),
                cli.json,
                "Sudo credential stored in Vault; its value was not displayed.",
            )?;
        }
        Some(Action::Vault(VaultAction::SetSshPassword { host })) => {
            let config = Config::load(&paths.config)?;
            let target = resolve_target(&config, &host)?;
            if target.host.auth != crate::config::AuthMode::VaultPassword
                && target.host.auth != crate::config::AuthMode::VaultKey
            {
                return Err(AppError::new(
                    ErrorCode::InvalidConfig,
                    "set the host authentication mode to vault-password (SSH login password) or vault-key (key passphrase) before storing a password",
                ));
            }
            let stem = target.host.credential.as_deref().unwrap_or(&target.alias);
            let name = crate::credential::ssh_credential_name(stem);
            let password = hidden_password("SSH password or private key passphrase (hidden): ")?;
            let client = connected_client(paths.clone()).await?;
            expect_ack(
                client
                    .call(RpcRequest::SetCredential {
                        name,
                        kind: "ssh-password".into(),
                        value: password.to_string(),
                    })
                    .await?,
            )?;
            emit(
                &serde_json::json!({"configured": true}),
                cli.json,
                "SSH password or key passphrase encrypted in Vault; it was not displayed.",
            )?;
        }
        Some(Action::Vault(VaultAction::ImportKey { host, path })) => {
            let config = Config::load(&paths.config)?;
            let target = resolve_target(&config, &host)?;
            if target.host.auth != crate::config::AuthMode::VaultKey {
                return Err(AppError::new(
                    ErrorCode::InvalidConfig,
                    "set auth=vault-key for this host in the wizard or configuration before importing the key",
                ));
            }
            let path = match path {
                Some(path) => path,
                None => prompt_text("Private key file (PEM, not .pub): ")?,
            };
            let path = std::path::absolute(path)
                .map_err(|error| AppError::io("resolve private key import path", error))?;
            let stem = target.host.credential.as_deref().unwrap_or(&target.alias);
            let name = crate::credential::key_credential_name(stem);
            let client = connected_client(paths.clone()).await?;
            expect_ack(
                client
                    .call(RpcRequest::ImportPrivateKey { name, path })
                    .await?,
            )?;
            emit(
                &serde_json::json!({"imported": true}),
                cli.json,
                "Private key encrypted in Vault; only its location and format were validated, not its contents.",
            )?;
        }
        Some(Action::Backup(BackupAction::Create { path })) => {
            let password = hidden_password_confirmed("New backup password: ")?;
            backup::create(&paths.config, &paths.vault(), &path, &password)?;
            emit(
                &serde_json::json!({"created": path}),
                cli.json,
                "Encrypted backup created.",
            )?;
        }
        Some(Action::Backup(BackupAction::Verify { path })) => {
            let password = hidden_password("Backup password: ")?;
            let metadata = backup::verify(&path, &password)?;
            emit(
                &metadata,
                cli.json,
                &format!(
                    "Backup valid: {} host(s), created {}",
                    metadata.hosts, metadata.created_at
                ),
            )?;
        }
        Some(Action::Backup(BackupAction::Restore { path, force })) => {
            let password = hidden_password("Backup password: ")?;
            let metadata = backup::restore(&path, &paths.config, &paths.vault(), &password, force)?;
            emit(
                &metadata,
                cli.json,
                "Encrypted backup restored; Vault is locked until explicit unlock.",
            )?;
        }
        Some(Action::Task(task)) => {
            let client = connected_client(paths).await?;
            task_command(&cli, &client, task).await?;
        }
        Some(Action::Approval(action)) => {
            let client = connected_client(paths).await?;
            match action {
                ApprovalAction::List => match client.call(RpcRequest::ApprovalList).await? {
                    RpcPayload::Approvals(items) => {
                        emit(&items, cli.json, &format_approvals(&items))?
                    }
                    _ => return Err(AppError::internal("unexpected approvals response")),
                },
                ApprovalAction::Approve { id } => {
                    match client.call(RpcRequest::Approve { id }).await? {
                        RpcPayload::Approval(item) => emit(
                            &item,
                            cli.json,
                            &format!(
                                "Approved {} once; rerun the unchanged operation before {}.",
                                item.id, item.expires_at
                            ),
                        )?,
                        _ => return Err(AppError::internal("unexpected approval response")),
                    }
                }
            }
        }
        Some(Action::Tunnel(action)) => {
            let client = connected_client(paths).await?;
            tunnel_command(&cli, &client, action).await?;
        }
        Some(Action::Put { local, remote }) => {
            return transfer_command(paths, &cli, local, remote, true).await;
        }
        Some(Action::Get { remote, local }) => {
            return transfer_command(paths, &cli, local, remote, false).await;
        }
        Some(Action::Sftp { target }) => {
            require_terminal()?;
            let config = Config::load(&paths.config)?;
            let target = resolve_target(&config, &target)?;
            return Ok(transfer::sftp(
                &target.host,
                crate::transport::AuthenticationContext::registered(
                    paths.clone(),
                    &target.alias,
                    &target.host,
                )
                .as_ref(),
            )
            .await?
            .clamp(0, 255) as u8);
        }
        Some(Action::Doctor { target }) => {
            return doctor(&paths, cli.json, target, language).await;
        }
        Some(Action::Tui) => {
            require_tui_terminal()?;
            crate::tui::run_with_options(paths, cli.no_color).await?;
        }
        Some(Action::External(values)) => return external(paths, &cli, values).await,
        None => {
            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                crate::tui::run_with_options(paths, cli.no_color).await?;
            } else {
                let mut message = language
                    .text(
                        "no TTY detected; use remxo --help or provide <target> <command...> (TUI was not started)",
                        "未检测到 TTY；请使用 remxo --help，或提供 <目标> <命令...>（未启动 TUI）",
                    )
                    .to_string();
                // Only file-certain states are reported here; guessing the Vault
                // lock state would need a Broker round-trip on an error path.
                if let Some(hint) =
                    crate::onboarding::Onboarding::from_files(&paths).and_then(|s| s.hint(language))
                {
                    message.push('\n');
                    message.push_str(hint);
                }
                return Err(AppError::invalid_argument(message));
            }
        }
    }
    Ok(0)
}

async fn task_command(cli: &Cli, client: &BrokerClient, action: TaskAction) -> Result<()> {
    match action {
        TaskAction::Start { target, command } => {
            let spec = execute_spec(cli, target, command, None, BTreeMap::new());
            match client.call(RpcRequest::TaskStart { spec }).await? {
                RpcPayload::Task(summary) => emit(
                    &summary,
                    cli.json,
                    &format!("Task {} [{:?}]", summary.id, summary.state),
                )?,
                _ => return Err(AppError::internal("unexpected task response")),
            }
        }
        TaskAction::List => match client.call(RpcRequest::TaskList).await? {
            RpcPayload::Tasks(tasks) => emit(&tasks, cli.json, &format_tasks(&tasks))?,
            _ => return Err(AppError::internal("unexpected task list response")),
        },
        TaskAction::Status { id } => match client.call(RpcRequest::TaskStatus { id }).await? {
            RpcPayload::Task(summary) => emit(
                &summary,
                cli.json,
                &format!("{} {:?}", summary.id, summary.state),
            )?,
            _ => return Err(AppError::internal("unexpected task status response")),
        },
        TaskAction::Logs { id } => match client.call(RpcRequest::TaskLogs { id }).await? {
            RpcPayload::Logs { stdout, stderr } => {
                if cli.json {
                    emit(
                        &serde_json::json!({"stdout": stdout, "stderr": stderr}),
                        true,
                        "",
                    )?;
                } else {
                    print!("{stdout}");
                    eprint!("{stderr}");
                }
            }
            _ => return Err(AppError::internal("unexpected task logs response")),
        },
        TaskAction::Stop { id } => match client.call(RpcRequest::TaskStop { id }).await? {
            RpcPayload::Task(summary) => emit(
                &summary,
                cli.json,
                "Local SSH stop requested; remote state must be verified.",
            )?,
            _ => return Err(AppError::internal("unexpected task stop response")),
        },
    }
    Ok(())
}

async fn tunnel_command(cli: &Cli, client: &BrokerClient, action: TunnelAction) -> Result<()> {
    match action {
        TunnelAction::Start {
            target,
            local,
            remote,
            dynamic,
            yes,
        } => match client
            .call(RpcRequest::TunnelStart {
                target,
                local,
                remote,
                dynamic,
                confirm_public: yes,
            })
            .await?
        {
            RpcPayload::Tunnel(item) => emit(
                &item,
                cli.json,
                &format!("Tunnel {} started: {}", item.id, item.argument),
            )?,
            _ => return Err(AppError::internal("unexpected tunnel response")),
        },
        TunnelAction::List => match client.call(RpcRequest::TunnelList).await? {
            RpcPayload::Tunnels(items) => emit(&items, cli.json, &format_tunnels(&items))?,
            _ => return Err(AppError::internal("unexpected tunnels response")),
        },
        TunnelAction::Stop { id } => match client.call(RpcRequest::TunnelStop { id }).await? {
            RpcPayload::Tunnel(item) => {
                emit(&item, cli.json, &format!("Tunnel {} stopped.", item.id))?
            }
            _ => return Err(AppError::internal("unexpected tunnel stop response")),
        },
    }
    Ok(())
}

async fn external(paths: AppPaths, cli: &Cli, values: Vec<String>) -> Result<u8> {
    let Some(target) = values.first().cloned() else {
        return Err(AppError::invalid_argument("target is required"));
    };
    let mut arguments = values.into_iter().skip(1).collect::<Vec<_>>();
    if arguments.is_empty() {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(AppError::invalid_argument(
                "a remote command is required in a non-interactive session; no input was read",
            ));
        }
        if cli.json {
            return Err(AppError::invalid_argument(
                "--json cannot be mixed with interactive SSH output",
            ));
        }
        let config = Config::load(&paths.config)?;
        let target = resolve_target(&config, &target)?;
        let context = crate::transport::AuthenticationContext::registered(
            paths.clone(),
            &target.alias,
            &target.host,
        );
        if context.is_some() {
            connected_client(paths).await?;
        }
        return Ok(OpensshTransport::default()
            .interactive_authenticated(&target.host, context.as_ref())
            .await?
            .clamp(0, 255) as u8);
    }
    let mut sudo = cli.sudo;
    if arguments.first().is_some_and(|value| value == "sudo") {
        sudo = true;
        arguments.remove(0);
        if arguments.is_empty() {
            return Err(AppError::invalid_argument("sudo requires a remote command"));
        }
    }
    let (profile, profile_args) = parse_profile_arguments(&arguments)?;
    let command = if profile.is_some() {
        Vec::new()
    } else {
        arguments
    };
    let mut spec = execute_spec(cli, target, command, profile, profile_args);
    spec.sudo = sudo;
    let language = human_language(&paths);
    let client = connected_client(paths).await?;
    let report = match client.call(RpcRequest::Execute { spec }).await? {
        RpcPayload::Report(report) => report,
        _ => return Err(AppError::internal("unexpected execute response")),
    };
    let success = report.status == OperationStatus::Success && report.remote_exit_code == Some(0);
    print_operation(&report, cli.json, language)?;
    Ok(if success { 0 } else { 1 })
}

fn execute_spec(
    cli: &Cli,
    target: String,
    command: Vec<String>,
    profile: Option<String>,
    profile_args: BTreeMap<String, String>,
) -> crate::broker::ExecuteSpec {
    crate::broker::ExecuteSpec {
        target,
        command,
        cwd: cli.cwd.clone(),
        sudo: cli.sudo,
        profile,
        profile_args,
        timeout_seconds: cli.timeout,
        max_output: cli.max_output,
    }
}

fn parse_profile_arguments(
    arguments: &[String],
) -> Result<(Option<String>, BTreeMap<String, String>)> {
    if arguments.first().map(String::as_str) != Some("--profile") {
        return Ok((None, BTreeMap::new()));
    }
    let profile = arguments
        .get(1)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| AppError::invalid_argument("--profile requires a name"))?;
    let mut values = BTreeMap::new();
    let mut index = 2;
    while index < arguments.len() {
        if arguments[index] != "--arg" {
            return Err(AppError::invalid_argument(
                "profile options must be --profile NAME [--arg key=value ...]",
            ));
        }
        let pair = arguments
            .get(index + 1)
            .ok_or_else(|| AppError::invalid_argument("--arg requires key=value"))?;
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| AppError::invalid_argument("--arg requires key=value"))?;
        if key.is_empty() || values.insert(key.to_string(), value.to_string()).is_some() {
            return Err(AppError::invalid_argument(
                "profile arguments must be unique and named",
            ));
        }
        index += 2;
    }
    Ok((Some(profile), values))
}

fn host_key_command(
    paths: &AppPaths,
    cli: &Cli,
    action: HostKeyAction,
    language: crate::config::UiLanguage,
) -> Result<()> {
    let config = Config::load(&paths.config)?;
    let retries = cli
        .retries
        .unwrap_or(config.settings.retry_attempts)
        .clamp(1, 10);
    match action {
        HostKeyAction::Status { target } => {
            let status = crate::hostkey::status(&config, &target)?;
            let human = if status.fingerprints.is_empty() {
                match language {
                    crate::config::UiLanguage::ZhCn => format!(
                        "主机 '{}' 的主机密钥未登记：{}:{}。",
                        status.host, status.address, status.port
                    ),
                    crate::config::UiLanguage::En => format!(
                        "Host '{}' has no known_hosts entry: {}:{}.",
                        status.host, status.address, status.port
                    ),
                }
            } else {
                let fingerprints = status
                    .fingerprints
                    .iter()
                    .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                    .collect::<Vec<_>>()
                    .join("; ");
                match language {
                    crate::config::UiLanguage::ZhCn => format!(
                        "主机 '{}' 的主机密钥已登记：{}。",
                        status.host, fingerprints
                    ),
                    crate::config::UiLanguage::En => format!(
                        "Host '{}' host key is known: {}.",
                        status.host, fingerprints
                    ),
                }
            };
            emit(&status, cli.json, &human)?;
        }
        HostKeyAction::Fetch { target } => {
            let resolved = resolve_target(&config, &target)?;
            let keys = crate::hostkey::fetch_with_retries(&resolved.host, retries)?;
            let value = serde_json::json!({
                "host": resolved.alias,
                "address": resolved.host.hostname.clone().or(resolved.host.ssh_alias.clone()),
                "port": resolved.host.port,
                "keys": keys,
            });
            let human = if language == crate::config::UiLanguage::ZhCn {
                let lines = keys
                    .iter()
                    .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "服务器主机密钥指纹：\n{lines}\n请先人工核对，再执行 remxo host key trust {resolved_alias}。",
                    resolved_alias = resolved.alias
                )
            } else {
                let lines = keys
                    .iter()
                    .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "Server host key fingerprints:\n{lines}\nVerify out-of-band, then run: remxo host key trust {alias}",
                    alias = resolved.alias
                )
            };
            emit(&value, cli.json, &human)?;
        }
        HostKeyAction::Trust {
            target,
            fingerprint,
        } => {
            let resolved = resolve_target(&config, &target)?;
            let result = if let Some(fingerprint) = fingerprint.as_deref() {
                crate::hostkey::trust_with_retries(
                    &resolved.alias,
                    &resolved.host,
                    Some(fingerprint),
                    retries,
                )?
            } else {
                let keys = crate::hostkey::fetch_with_retries(&resolved.host, retries)?;
                crate::hostkey::confirm_trust_interactively(&keys)?;
                crate::hostkey::trust_confirmed(
                    &resolved.alias,
                    &resolved.host,
                    &keys,
                    None,
                    retries,
                )?
            };
            let human = if result.added.is_empty() {
                match language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("主机 '{}' 的主机密钥已在 known_hosts 中。", result.host)
                    }
                    crate::config::UiLanguage::En => {
                        format!("Host '{}' host key is already in known_hosts.", result.host)
                    }
                }
            } else {
                let added = result
                    .added
                    .iter()
                    .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                    .collect::<Vec<_>>()
                    .join("; ");
                if result.already_known.is_empty() {
                    match language {
                        crate::config::UiLanguage::ZhCn => {
                            format!("已信任主机 '{}' 的主机密钥：{}。", result.host, added)
                        }
                        crate::config::UiLanguage::En => {
                            format!("Trusted host '{}' key: {}.", result.host, added)
                        }
                    }
                } else {
                    let existing = result
                        .already_known
                        .iter()
                        .map(|key| format!("{} {}", key.key_type, key.fingerprint))
                        .collect::<Vec<_>>()
                        .join("; ");
                    match language {
                        crate::config::UiLanguage::ZhCn => format!(
                            "主机 '{}' 已新增密钥：{}；已有密钥：{}。",
                            result.host, added, existing
                        ),
                        crate::config::UiLanguage::En => format!(
                            "Host '{}' added keys: {}; already known: {}.",
                            result.host, added, existing
                        ),
                    }
                }
            };
            emit(&result, cli.json, &human)?;
        }
        HostKeyAction::List => {
            let statuses = crate::hostkey::list(&config)?;
            let human = if language == crate::config::UiLanguage::ZhCn {
                let mut lines = vec!["别名\t地址\t端口\t主机密钥".to_string()];
                for status in &statuses {
                    lines.push(format!(
                        "{}\t{}:{}\t{}",
                        status.host,
                        status.address,
                        status.port,
                        if status.known {
                            "已登记"
                        } else {
                            "未登记"
                        }
                    ));
                }
                lines.join("\n")
            } else {
                let mut lines = vec!["ALIAS\tADDRESS\tPORT\tHOST KEY".to_string()];
                for status in &statuses {
                    lines.push(format!(
                        "{}\t{}:{}\t{}",
                        status.host,
                        status.address,
                        status.port,
                        if status.known { "known" } else { "unknown" }
                    ));
                }
                lines.join("\n")
            };
            emit(&statuses, cli.json, &human)?;
        }
        HostKeyAction::Remove { target, yes } => {
            if !yes {
                return Err(AppError::invalid_argument(
                    "host key removal requires --yes; this changes OpenSSH known_hosts",
                ));
            }
            let resolved = resolve_target(&config, &target)?;
            crate::hostkey::remove(&resolved.host)?;
            emit(
                &serde_json::json!({"removed": resolved.alias}),
                cli.json,
                &match language {
                    crate::config::UiLanguage::ZhCn => {
                        format!("已从 known_hosts 移除主机 '{}' 的密钥。", resolved.alias)
                    }
                    crate::config::UiLanguage::En => format!(
                        "Removed host key for '{}' from known_hosts.",
                        resolved.alias
                    ),
                },
            )?;
        }
    }
    Ok(())
}

async fn host_add(paths: &AppPaths, cli: &Cli, add: HostAdd) -> Result<()> {
    let needs_form = add.interactive
        || add.alias.is_none()
        || (add.ssh_alias.is_none() && add.hostname.is_none());
    if needs_form {
        if cli.json {
            return Err(AppError::invalid_argument(
                "interactive host setup cannot be combined with --json; provide --ssh-alias or --hostname for automation",
            ));
        }
        require_tui_terminal()?;
        let alias = add.alias.clone();
        let initial = host_from_args(&add)?;
        let result = crate::tui_wizard::run(paths, alias, Some(initial), cli.no_color).await?;
        emit(
            &serde_json::json!({"added": result.saved_alias, "message": result.message}),
            false,
            &result.message,
        )
    } else {
        host_add_flags(paths, cli, add).await
    }
}

fn host_from_args(add: &HostAdd) -> Result<Host> {
    let transport = parse_transport(&add.transport)?;
    let alias = add.alias.clone().unwrap_or_default();
    let auth = parse_auth(&add.auth)?;
    Ok(Host {
        number: add.number,
        transport,
        ssh_alias: add.ssh_alias.clone(),
        hostname: add.hostname.clone(),
        port: add.port.unwrap_or(if transport == TransportKind::Telnet {
            23
        } else {
            22
        }),
        username: add.username.clone(),
        platform: parse_platform(&add.platform)?,
        shell: parse_shell(&add.shell)?,
        auth,
        environment: add.environment.clone(),
        tags: add
            .tags
            .clone()
            .unwrap_or_default()
            .split(',')
            .filter(|tag| !tag.is_empty())
            .map(str::to_string)
            .collect(),
        raw_mode: parse_raw_mode(&add.raw_mode)?,
        approval: parse_approval(&add.approval)?,
        insecure_acknowledged: add.ack_insecure,
        sudo_credential: add
            .configure_sudo
            .then(|| crate::credential::sudo_credential_name(&alias)),
        credential: matches!(
            auth,
            crate::config::AuthMode::VaultPassword | crate::config::AuthMode::VaultKey
        )
        .then_some(alias),
        prompt: None,
    })
}

async fn host_add_flags(paths: &AppPaths, cli: &Cli, add: HostAdd) -> Result<()> {
    let alias = add
        .alias
        .as_deref()
        .ok_or_else(|| AppError::invalid_argument("alias is required"))?;
    if parse_transport(&add.transport)? == TransportKind::Telnet && !add.ack_insecure {
        return Err(AppError::new(
            ErrorCode::InsecureTransport,
            "Telnet is plaintext; adding it requires explicit --ack-insecure",
        ));
    }
    let host = host_from_args(&add)?;
    let sudo_credential = host.sudo_credential.clone();
    crate::host::add_host(paths, alias, host)?;
    if add.configure_sudo {
        let password = hidden_password("Sudo password (hidden): ")?;
        let client = connected_client(paths.clone()).await?;
        expect_ack(
            client
                .call(RpcRequest::SetCredential {
                    name: sudo_credential.unwrap_or_else(|| alias.to_string()),
                    kind: "sudo-password".into(),
                    value: password.to_string(),
                })
                .await?,
        )?;
    }
    emit(
        &serde_json::json!({"added": alias}),
        cli.json,
        "Host saved (previous config backed up when present).",
    )
}

async fn connected_client(paths: AppPaths) -> Result<BrokerClient> {
    let client = BrokerClient::new(paths);
    client.ensure_running().await?;
    Ok(client)
}

fn expect_ack(payload: RpcPayload) -> Result<()> {
    if matches!(payload, RpcPayload::Ack) {
        Ok(())
    } else {
        Err(AppError::internal("unexpected broker acknowledgement"))
    }
}

async fn transfer_command(
    paths: AppPaths,
    cli: &Cli,
    local: PathBuf,
    remote: String,
    upload: bool,
) -> Result<u8> {
    let remote = transfer::parse_remote_path(&remote)?;
    let spec = crate::broker::TransferSpec {
        target: remote.target,
        local,
        remote: remote.path,
        upload,
        overwrite: cli.overwrite,
        timeout_seconds: cli.timeout,
        max_output: cli.max_output,
    };
    let language = human_language(&paths);
    let client = connected_client(paths).await?;
    let report = match client.call(RpcRequest::Transfer { spec }).await? {
        RpcPayload::Report(report) => report,
        _ => return Err(AppError::internal("unexpected transfer response")),
    };
    let success = report.status == OperationStatus::Success && report.remote_exit_code == Some(0);
    if cli.json || !success {
        print_operation(&report, cli.json, language)?;
    } else {
        let outcome: transfer::TransferOutcome = serde_json::from_str(&report.stdout)
            .map_err(|e| AppError::internal(format!("invalid transfer outcome: {e}")))?;
        println!(
            "Transferred {} byte(s) {} {}.",
            outcome.bytes,
            if upload { "to" } else { "from" },
            crate::redact::escape_controls(&outcome.remote)
        );
    }
    Ok(if success { 0 } else { 1 })
}

async fn doctor(
    paths: &AppPaths,
    json: bool,
    target: Option<String>,
    language: crate::config::UiLanguage,
) -> Result<u8> {
    let config = Config::load(&paths.config)?;
    let ssh = std::env::var_os("REMXO_SSH").unwrap_or_else(|| "ssh".into());
    let mut command = std::process::Command::new(ssh);
    command.arg("-V");
    crate::process::without_console_window(&mut command);
    let output = command.output();
    let (available, version) = match output {
        Ok(output) => {
            let bytes = if output.stdout.is_empty() {
                output.stderr
            } else {
                output.stdout
            };
            (
                true,
                crate::redact::sanitize(&String::from_utf8_lossy(&bytes))
                    .trim()
                    .to_string(),
            )
        }
        Err(_) => (false, String::new()),
    };
    let mut report = serde_json::json!({"config_valid": true, "hosts": config.hosts.len(), "vault_present": paths.vault().exists(), "ssh_available": available, "ssh_version": version, "host_key_check_disabled_by_remxo": false, "security_level": "L1"});
    let mut human = match language {
        crate::config::UiLanguage::ZhCn => format!(
            "配置有效，共 {} 台主机。OpenSSH 可用：{available}。Remxo 不会关闭主机密钥检查。",
            config.hosts.len()
        ),
        crate::config::UiLanguage::En => format!(
            "Config valid; {} host(s). OpenSSH available: {available}. Remxo never disables host key checks.",
            config.hosts.len()
        ),
    };
    let mut exit_code = 0;
    if let Some(target) = target {
        let resolved = resolve_target(&config, &target)?;
        match crate::tui_wizard::test_registered_connection(
            paths,
            &resolved.alias,
            &resolved.host,
            language,
        )
        .await
        {
            Ok((message, passed)) => {
                report["connection_test"] = serde_json::json!({
                    "host": resolved.alias,
                    "passed": passed,
                    "message": message,
                });
                human.push_str(&format!("\n{message}"));
                exit_code = if passed { 0 } else { 1 };
            }
            Err(error) => {
                let message = crate::i18n::error_message(&error, language);
                report["connection_test"] = serde_json::json!({
                    "host": resolved.alias,
                    "passed": false,
                    "error": error.detail(),
                    "message": message,
                });
                human.push_str(&format!("\n{message}"));
                exit_code = 1;
            }
        }
    }
    emit(&report, json, &human)?;
    Ok(exit_code)
}

fn print_operation(
    report: &OperationReport,
    json: bool,
    language: crate::config::UiLanguage,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(report)
                .map_err(|e| AppError::internal(format!("serialize result JSON: {e}")))?
        );
    } else {
        print!("{}", report.stdout);
        eprint!("{}", report.stderr);
        if let Some(error) = &report.error {
            let display = AppError::new(error.code, error.message.clone());
            eprintln!(
                "remxo [{:?}]: {}",
                error.code,
                crate::i18n::error_message(&display, language)
            );
            if let Some(id) = &error.approval_id {
                match language {
                    crate::config::UiLanguage::ZhCn => {
                        eprintln!("请人工审查后运行：remxo approval approve {id}");
                    }
                    crate::config::UiLanguage::En => {
                        eprintln!("A human may approve with: remxo approval approve {id}");
                    }
                }
            }
        }
        std::io::stdout()
            .flush()
            .map_err(|e| AppError::io("flush stdout", e))?;
    }
    Ok(())
}

fn status_report_text(
    status: &StatusReport,
    language: crate::config::UiLanguage,
    paths: &AppPaths,
) -> String {
    let summary = match language {
        crate::config::UiLanguage::ZhCn => format!(
            "Vault：{}\nBroker：{}\n主机：{}",
            if status.vault_locked {
                "已锁定"
            } else {
                "已解锁"
            },
            if status.broker_running {
                "运行中"
            } else {
                "已停止"
            },
            status.hosts
        ),
        crate::config::UiLanguage::En => format!(
            "Vault: {}\nBroker: {}\nHosts: {}",
            if status.vault_locked {
                "locked"
            } else {
                "unlocked"
            },
            if status.broker_running {
                "running"
            } else {
                "stopped"
            },
            status.hosts
        ),
    };
    match crate::onboarding::Onboarding::detect(paths, status.vault_locked, status.hosts)
        .hint(language)
    {
        Some(hint) => format!("{summary}\n{hint}"),
        None => summary,
    }
}

fn emit(value: &impl Serialize, json: bool, human: &str) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(value)
                .map_err(|e| AppError::internal(format!("serialize JSON: {e}")))?
        );
    } else {
        println!("{human}");
    }
    Ok(())
}

fn initialize_data_directory(
    paths: &AppPaths,
    master_password: &str,
    language: crate::config::UiLanguage,
) -> Result<bool> {
    if paths.vault().exists() {
        return Err(AppError::new(
            ErrorCode::AlreadyExists,
            "Vault already exists; init will not overwrite it. Run 'remxo status' to inspect the current installation or choose a fresh --config path",
        ));
    }
    if master_password.len() < 12 {
        return Err(AppError::invalid_argument(
            "master password must contain at least 12 bytes; no files were written, so you can retry remxo init",
        ));
    }
    let recovered = paths.config.exists();
    // A previous interrupted initialization can leave config without Vault.
    // Preserve any valid existing config and only finish the missing Vault half.
    if recovered {
        Config::load(&paths.config)?;
    } else {
        Config::initialize_with_language(&paths.config, language)?;
    }
    VaultSession::initialize(&paths.vault(), master_password)?;
    Ok(recovered)
}

fn require_terminal() -> Result<()> {
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(AppError::invalid_argument(
            "this operation requires an interactive hidden prompt; non-interactive input was not read",
        ))
    }
}

fn choose_language(request: Option<String>, json: bool) -> Result<crate::config::UiLanguage> {
    match request {
        Some(language) => crate::config::UiLanguage::from_arg(&language),
        None if json || !std::io::stdin().is_terminal() => Ok(crate::config::UiLanguage::En),
        None => {
            let input = prompt_text(
                "Language / UI 语言:\n  1. English\n  2. 简体中文\nSelect / 请选择 [1/2] (default 1): ",
            )?;
            parse_language_choice(input.to_string_lossy().trim())
        }
    }
}

fn parse_language_choice(input: &str) -> Result<crate::config::UiLanguage> {
    match input.trim() {
        "" | "1" => Ok(crate::config::UiLanguage::En),
        "2" => Ok(crate::config::UiLanguage::ZhCn),
        _ => crate::config::UiLanguage::from_arg(input),
    }
}

fn required_askpass_environment(name: &str) -> Result<String> {
    std::env::var_os(name)
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::InvalidConfig,
                "the internal ASKPASS helper is missing its Remxo launch context",
            )
        })?
        .into_string()
        .map_err(|_| AppError::invalid_argument("invalid internal ASKPASS launch context"))
}

fn validate_askpass_prompt(prompt: Option<&std::ffi::OsStr>) -> Result<()> {
    let prompt = prompt.ok_or_else(|| {
        AppError::invalid_argument("askpass requires a password or private-key passphrase prompt")
    })?;
    let prompt = prompt.to_string_lossy().to_ascii_lowercase();
    if prompt.len() > 512 {
        return Err(AppError::invalid_argument("askpass prompt is too long"));
    }
    if prompt.contains("yes/no")
        || prompt.contains("fingerprint")
        || prompt.contains("continue connecting")
        || prompt.contains("host key")
    {
        return Err(AppError::new(
            ErrorCode::HostKeyFailed,
            "host key confirmation requires a human through interactive OpenSSH; Remxo will not respond through askpass",
        ));
    }
    if prompt.contains("verification code")
        || prompt.contains("one-time password")
        || prompt.contains("otp")
        || prompt.contains("pin for")
        || prompt.contains("token")
    {
        return Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "MFA, OTP, or hardware PIN prompts are not supported by this ASKPASS broker",
        ));
    }
    if !prompt.contains("password") && !prompt.contains("passphrase") {
        return Err(AppError::new(
            ErrorCode::UnsupportedOperation,
            "unexpected ASKPASS prompt; only password or private-key passphrase prompts are accepted",
        ));
    }
    Ok(())
}

fn require_tui_terminal() -> Result<()> {
    require_terminal()?;
    if std::io::stdout().is_terminal() {
        Ok(())
    } else {
        Err(AppError::invalid_argument(
            "interactive TUI requires both stdin and stdout to be terminals; the TUI was not started",
        ))
    }
}

fn prompt_text(prompt: &str) -> Result<PathBuf> {
    require_terminal()?;
    eprint!("{prompt}");
    std::io::stderr()
        .flush()
        .map_err(|error| AppError::io("display prompt", error))?;
    let mut input = String::with_capacity(64);
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|error| AppError::io("read path input", error))?;
    if input.is_empty() || input.len() > 4096 {
        return Err(AppError::invalid_argument(
            "input path must be non-empty and at most 4096 bytes",
        ));
    }
    Ok(PathBuf::from(input.trim_end_matches(['\r', '\n'])))
}

fn hidden_password(prompt: &str) -> Result<Zeroizing<String>> {
    crate::masked_prompt::prompt(prompt)
}

fn hidden_password_confirmed(prompt: &str) -> Result<Zeroizing<String>> {
    hidden_password_confirmed_with(prompt, "Confirm password: ")
}

fn hidden_password_confirmed_with(
    prompt: &str,
    confirmation_prompt: &str,
) -> Result<Zeroizing<String>> {
    let password = hidden_password(prompt)?;
    if password.len() < 12 {
        return Err(AppError::invalid_argument(
            "password must contain at least 12 bytes; please retry with a longer password",
        ));
    }
    let confirmation = hidden_password(confirmation_prompt)?;
    if password.as_str() != confirmation.as_str() {
        return Err(AppError::invalid_argument("passwords do not match"));
    }
    Ok(password)
}

fn parse_duration(value: &str) -> std::result::Result<u64, String> {
    if value.len() < 2 {
        return Err("use a positive duration such as 30s, 500ms, 5m, or 1h".into());
    }
    let (amount, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 0.001)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1.0)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60.0)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3600.0)
    } else {
        return Err("duration must end in ms, s, m, or h".into());
    };
    let amount = amount
        .parse::<f64>()
        .map_err(|_| "duration has an invalid number".to_string())?;
    let seconds = amount * multiplier;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(seconds.ceil().min(u64::MAX as f64) as u64)
}
fn parse_transport(value: &str) -> Result<TransportKind> {
    match value {
        "ssh" => Ok(TransportKind::Ssh),
        "telnet" => Ok(TransportKind::Telnet),
        _ => Err(AppError::invalid_argument(
            "transport must be ssh or telnet",
        )),
    }
}
fn parse_auth(value: &str) -> Result<AuthMode> {
    match value {
        "external-agent" => Ok(AuthMode::ExternalAgent),
        "openssh-config" => Ok(AuthMode::OpensshConfig),
        "vault-password" => Ok(AuthMode::VaultPassword),
        "vault-key" => Ok(AuthMode::VaultKey),
        _ => Err(AppError::invalid_argument("unknown auth mode")),
    }
}
fn parse_platform(value: &str) -> Result<Platform> {
    match value {
        "linux" => Ok(Platform::Linux),
        "macos" => Ok(Platform::Macos),
        "windows" => Ok(Platform::Windows),
        "network-device" => Ok(Platform::NetworkDevice),
        "other" => Ok(Platform::Other),
        _ => Err(AppError::invalid_argument("unknown platform")),
    }
}
fn parse_shell(value: &str) -> Result<ShellKind> {
    match value {
        "posix" => Ok(ShellKind::Posix),
        "powershell" => Ok(ShellKind::Powershell),
        "cmd" => Ok(ShellKind::Cmd),
        "device" => Ok(ShellKind::Device),
        "custom" => Ok(ShellKind::Custom),
        _ => Err(AppError::invalid_argument("unknown shell")),
    }
}
fn parse_raw_mode(value: &str) -> Result<RawMode> {
    match value {
        "allow" => Ok(RawMode::Allow),
        "read-only" => Ok(RawMode::ReadOnly),
        "deny" => Ok(RawMode::Deny),
        _ => Err(AppError::invalid_argument(
            "raw mode must be allow, read-only, or deny",
        )),
    }
}
fn parse_approval(value: &str) -> Result<ApprovalMode> {
    match value {
        "never" => Ok(ApprovalMode::Never),
        "writes" => Ok(ApprovalMode::Writes),
        "always" => Ok(ApprovalMode::Always),
        _ => Err(AppError::invalid_argument(
            "approval must be never, writes, or always",
        )),
    }
}
fn format_tasks(tasks: &[crate::task::TaskSummary]) -> String {
    tasks
        .iter()
        .map(|task| {
            format!(
                "{}\t{}\t{:?}\t{}",
                task.id, task.host, task.state, task.request_digest
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn format_approvals(items: &[crate::approval::Approval]) -> String {
    items
        .iter()
        .map(|item| {
            format!(
                "{}\t{}\t{}\tapproved={}\texpires={}",
                item.id, item.host, item.request_digest, item.approved, item.expires_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn format_tunnels(items: &[crate::tunnel::TunnelSummary]) -> String {
    items
        .iter()
        .map(|item| {
            format!(
                "{}\t{}\t{:?}\t{}",
                item.id, item.host, item.kind, item.argument
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interactive_language_accepts_numbers_names_and_empty_default() {
        assert_eq!(
            parse_language_choice("").ok(),
            Some(crate::config::UiLanguage::En)
        );
        assert_eq!(
            parse_language_choice("1").ok(),
            Some(crate::config::UiLanguage::En)
        );
        assert_eq!(
            parse_language_choice("2").ok(),
            Some(crate::config::UiLanguage::ZhCn)
        );
        assert_eq!(
            parse_language_choice("zh-CN").ok(),
            Some(crate::config::UiLanguage::ZhCn)
        );
        assert!(parse_language_choice("3").is_err());
    }

    #[test]
    fn lock_defaults_to_preserving_broker_until_shutdown_is_explicit() {
        let cli = Cli::try_parse_from(["remxo", "lock"]).unwrap_or_else(|e| panic!("lock: {e}"));
        assert!(matches!(
            cli.action,
            Some(Action::Lock { stop_broker: false })
        ));

        let cli = Cli::try_parse_from(["remxo", "lock", "--stop-broker"])
            .unwrap_or_else(|e| panic!("stop broker: {e}"));
        assert!(matches!(
            cli.action,
            Some(Action::Lock { stop_broker: true })
        ));
    }

    #[test]
    fn everything_after_target_is_preserved_as_remote_arguments() {
        let cli = Cli::try_parse_from(["remxo", "--json", "prod", "ls", "-l", "--help"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        let Some(Action::External(values)) = cli.action else {
            panic!("expected external target")
        };
        assert_eq!(values, ["prod", "ls", "-l", "--help"]);
    }
    #[test]
    fn profiles_validate_typed_key_value_arguments() {
        let args = vec![
            "--profile".into(),
            "logs".into(),
            "--arg".into(),
            "service=nginx".into(),
            "--arg".into(),
            "lines=100".into(),
        ];
        let (profile, values) =
            parse_profile_arguments(&args).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(profile.as_deref(), Some("logs"));
        assert_eq!(values.get("lines").map(String::as_str), Some("100"));
        assert!(
            parse_profile_arguments(&[
                "--profile".into(),
                "logs".into(),
                "--arg".into(),
                "bad".into()
            ])
            .is_err()
        );
    }
    #[test]
    fn askpass_accepts_only_password_or_passphrase_prompts() {
        assert!(
            validate_askpass_prompt(Some(std::ffi::OsStr::new("user@host's password: "))).is_ok()
        );
        assert!(
            validate_askpass_prompt(Some(std::ffi::OsStr::new(
                "Enter passphrase for key '/tmp/test': "
            )))
            .is_ok()
        );
        for prompt in [
            "Are you sure you want to continue connecting (yes/no)?",
            "The fingerprint is SHA256:test",
            "Verification code:",
            "One-time password:",
            "OTP:",
            "PIN for test key:",
            "Token:",
            "Unexpected prompt:",
        ] {
            assert!(
                validate_askpass_prompt(Some(std::ffi::OsStr::new(prompt))).is_err(),
                "unexpected prompt category was accepted"
            );
        }
        assert!(validate_askpass_prompt(None).is_err());
    }

    #[test]
    fn status_report_adds_a_next_step_only_while_setup_is_incomplete() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));

        let fresh = StatusReport {
            schema_version: 1,
            vault_exists: false,
            vault_locked: true,
            broker_running: false,
            hosts: 0,
            agent_available: None,
        };
        let english = status_report_text(&fresh, crate::config::UiLanguage::En, &paths);
        assert!(english.contains("Vault: locked"), "{english}");
        assert!(english.contains("Next: remxo init"), "{english}");

        let chinese = status_report_text(&fresh, crate::config::UiLanguage::ZhCn, &paths);
        assert!(chinese.contains("下一步：remxo init"), "{chinese}");

        // A ready installation must not repeat advice.
        std::fs::write(&paths.config, "version = 1\n[settings]\nlanguage = 'en'\n")
            .unwrap_or_else(|error| panic!("write config: {error}"));
        std::fs::write(paths.vault(), "{}\n")
            .unwrap_or_else(|error| panic!("write vault: {error}"));
        let ready = StatusReport {
            vault_exists: true,
            vault_locked: false,
            hosts: 2,
            ..fresh
        };
        let quiet = status_report_text(&ready, crate::config::UiLanguage::En, &paths);
        assert!(!quiet.contains("Next:"), "{quiet}");
    }

    #[test]
    fn short_password_leaves_no_files_and_allows_retry() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        let error =
            initialize_data_directory(&paths, "short", crate::config::UiLanguage::En).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(!paths.config.exists());
        assert!(!paths.vault().exists());
        let recovered = initialize_data_directory(
            &paths,
            "a long test master password",
            crate::config::UiLanguage::En,
        )
        .unwrap_or_else(|error| panic!("initialize: {error}"));
        assert!(!recovered);
        assert!(paths.config.exists());
        assert!(paths.vault().exists());
        let duplicate = initialize_data_directory(
            &paths,
            "another long test password",
            crate::config::UiLanguage::En,
        )
        .unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::AlreadyExists);
    }

    #[test]
    fn interrupted_init_preserves_a_valid_config_and_recovers_only_the_vault() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        Config::initialize(&paths.config).unwrap_or_else(|error| panic!("config: {error}"));
        let mut config =
            Config::load(&paths.config).unwrap_or_else(|error| panic!("load: {error}"));
        config.hosts.insert(
            "preserved-host".to_string(),
            Host {
                hostname: Some("192.0.2.10".into()),
                ..Host::default()
            },
        );
        config
            .save(&paths.config)
            .unwrap_or_else(|error| panic!("save: {error}"));
        let original =
            std::fs::read(&paths.config).unwrap_or_else(|error| panic!("read config: {error}"));
        let recovered = initialize_data_directory(
            &paths,
            "a long test master password",
            crate::config::UiLanguage::En,
        )
        .unwrap_or_else(|error| panic!("recover: {error}"));
        assert!(recovered);
        let preserved =
            std::fs::read(&paths.config).unwrap_or_else(|error| panic!("read preserved: {error}"));
        assert_eq!(original, preserved);
        assert!(paths.vault().exists());
        let vault = VaultSession::load(&paths.vault())
            .unwrap_or_else(|error| panic!("load vault: {error}"));
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn recovery_never_overwrites_invalid_config_or_an_existing_vault() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        std::fs::write(&paths.config, "version = 1\nunknown = true\n")
            .unwrap_or_else(|error| panic!("write partial config: {error}"));
        let error = initialize_data_directory(
            &paths,
            "a long test master password",
            crate::config::UiLanguage::En,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert!(!paths.vault().exists());
    }

    #[test]
    fn duration_parser_is_bounded() {
        assert_eq!(parse_duration("500ms").ok(), Some(1));
        assert_eq!(parse_duration("2m").ok(), Some(120));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("30").is_err());
    }
}
