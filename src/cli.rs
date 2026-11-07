use crate::backup;
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{
    AppPaths, ApprovalMode, AuthMode, Config, Host, Platform, RawMode, ShellKind, TransportKind,
    resolve_target,
};
use crate::error::{AppError, ErrorCode, Result};
use crate::model::{OperationReport, OperationStatus, StatusReport};
use crate::transfer;
use crate::transport::Transport as _;
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
    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Debug, Subcommand)]
enum Action {
    Init,
    Status,
    Unlock,
    Lock,
    Tui,
    Doctor,
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
    Remove {
        alias: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct HostAdd {
    alias: String,
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
    SetSudo { host: String },
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

pub async fn main_entry() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match dispatch(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if json {
                let value = serde_json::json!({"error": error.detail()});
                println!("{}", serde_json::to_string(&value).unwrap_or_else(|_| "{\"error\":{\"code\":\"internal_error\",\"message\":\"JSON serialization failed\"}}".into()));
            } else {
                eprintln!("remxo [{:?}]: {}", error.code, error.message);
            }
            ExitCode::from(2)
        }
    }
}

async fn dispatch(mut cli: Cli) -> Result<u8> {
    let paths = AppPaths::new(cli.config.clone())?;
    match cli.action.take() {
        Some(Action::Init) => {
            if paths.config.exists() || paths.vault().exists() {
                return Err(AppError::new(
                    ErrorCode::AlreadyExists,
                    "configuration or vault already exists; init will not overwrite it",
                ));
            }
            let password = hidden_password_confirmed("New master password: ")?;
            Config::initialize(&paths.config)?;
            VaultSession::initialize(&paths.vault(), &password)?;
            emit(
                &serde_json::json!({"initialized": true, "vault_locked": true}),
                cli.json,
                "Initialized config and locked Vault. Host inventory is empty.",
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
                &format!(
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
            )?;
        }
        Some(Action::Unlock) => {
            let password = hidden_password("Master password: ")?;
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
                "Vault unlocked in the local Broker.",
            )?;
        }
        Some(Action::Lock) => {
            let client = BrokerClient::new(paths);
            if client.ping().await.is_ok() {
                expect_ack(client.call(RpcRequest::Lock).await?)?;
            }
            emit(
                &serde_json::json!({"vault_locked": true}),
                cli.json,
                "Vault locked.",
            )?;
        }
        Some(Action::Hosts) => {
            let config = Config::load(&paths.config)?;
            if cli.json {
                emit(&config.hosts, true, "")?;
            } else {
                println!("ALIAS\tNUMBER\tTRANSPORT\tENVIRONMENT\tAUTH\tSECURITY");
                for (alias, host) in config.hosts {
                    println!(
                        "{alias}\t{}\t{:?}\t{}\t{:?}\t{}",
                        host.number.map(|n| n.to_string()).unwrap_or_default(),
                        host.transport,
                        host.environment,
                        host.auth,
                        if host.transport == TransportKind::Telnet {
                            "INSECURE"
                        } else {
                            "encrypted"
                        }
                    );
                }
            }
        }
        Some(Action::Host(HostAction::Add(add))) => host_add(&paths, &cli, *add).await?,
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
                "Host removed (previous config backed up).",
            )?;
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
            return Ok(transfer::sftp(&target.host)?.clamp(0, 255) as u8);
        }
        Some(Action::Doctor) => doctor(&paths, cli.json)?,
        Some(Action::Tui) => {
            require_terminal()?;
            crate::tui::run(paths).await?;
        }
        Some(Action::External(values)) => return external(paths, &cli, values).await,
        None => {
            if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
                crate::tui::run(paths).await?;
            } else {
                return Err(AppError::invalid_argument(
                    "no TTY detected; use remxo --help or provide <target> <command...> (TUI was not started)",
                ));
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
        return Ok(OpensshTransport::default()
            .interactive(&target.host)?
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
    let client = connected_client(paths).await?;
    let report = match client.call(RpcRequest::Execute { spec }).await? {
        RpcPayload::Report(report) => report,
        _ => return Err(AppError::internal("unexpected execute response")),
    };
    let success = report.status == OperationStatus::Success && report.remote_exit_code == Some(0);
    print_operation(&report, cli.json)?;
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

async fn host_add(paths: &AppPaths, cli: &Cli, add: HostAdd) -> Result<()> {
    let mut config = Config::load(&paths.config)?;
    let transport = parse_transport(&add.transport)?;
    if transport == TransportKind::Telnet && !add.ack_insecure {
        return Err(AppError::new(
            ErrorCode::InsecureTransport,
            "Telnet is plaintext; adding it requires explicit --ack-insecure",
        ));
    }
    if config.hosts.contains_key(&add.alias) {
        return Err(AppError::new(
            ErrorCode::AlreadyExists,
            "host alias already exists",
        ));
    }
    let host = Host {
        number: add.number,
        transport,
        ssh_alias: add.ssh_alias,
        hostname: add.hostname,
        port: add.port.unwrap_or(if transport == TransportKind::Telnet {
            23
        } else {
            22
        }),
        username: add.username,
        platform: parse_platform(&add.platform)?,
        shell: parse_shell(&add.shell)?,
        auth: parse_auth(&add.auth)?,
        environment: add.environment,
        tags: add
            .tags
            .unwrap_or_default()
            .split(',')
            .filter(|tag| !tag.is_empty())
            .map(str::to_string)
            .collect(),
        raw_mode: parse_raw_mode(&add.raw_mode)?,
        approval: parse_approval(&add.approval)?,
        insecure_acknowledged: add.ack_insecure,
        sudo_credential: add.configure_sudo.then(|| add.alias.clone()),
        credential: None,
        prompt: None,
    };
    host.validate(&add.alias)?;
    config.hosts.insert(add.alias.clone(), host);
    config.save(&paths.config)?;
    if add.configure_sudo {
        let password = hidden_password("Sudo password (hidden): ")?;
        let client = connected_client(paths.clone()).await?;
        expect_ack(
            client
                .call(RpcRequest::SetCredential {
                    name: add.alias.clone(),
                    kind: "sudo-password".into(),
                    value: password.to_string(),
                })
                .await?,
        )?;
    }
    emit(
        &serde_json::json!({"added": add.alias}),
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
    let client = connected_client(paths).await?;
    let report = match client.call(RpcRequest::Transfer { spec }).await? {
        RpcPayload::Report(report) => report,
        _ => return Err(AppError::internal("unexpected transfer response")),
    };
    let success = report.status == OperationStatus::Success && report.remote_exit_code == Some(0);
    if cli.json || !success {
        print_operation(&report, cli.json)?;
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

fn doctor(paths: &AppPaths, json: bool) -> Result<()> {
    let config = Config::load(&paths.config)?;
    let ssh = std::env::var_os("REMXO_SSH").unwrap_or_else(|| "ssh".into());
    let output = std::process::Command::new(ssh).arg("-V").output();
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
    let report = serde_json::json!({"config_valid": true, "hosts": config.hosts.len(), "vault_present": paths.vault().exists(), "ssh_available": available, "ssh_version": version, "host_key_check_disabled_by_remxo": false, "security_level": "L1"});
    emit(
        &report,
        json,
        &format!(
            "Config valid; {} host(s). OpenSSH available: {available}. Remxo never disables host key checks.",
            config.hosts.len()
        ),
    )
}

fn print_operation(report: &OperationReport, json: bool) -> Result<()> {
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
            eprintln!("remxo [{:?}]: {}", error.code, error.message);
            if let Some(id) = &error.approval_id {
                eprintln!("A human may approve with: remxo approval approve {id}");
            }
        }
        std::io::stdout()
            .flush()
            .map_err(|e| AppError::io("flush stdout", e))?;
    }
    Ok(())
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

fn require_terminal() -> Result<()> {
    if std::io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(AppError::invalid_argument(
            "this operation requires an interactive hidden prompt; non-interactive input was not read",
        ))
    }
}

fn hidden_password(prompt: &str) -> Result<Zeroizing<String>> {
    require_terminal()?;
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| AppError::io("read hidden password", e))
}

fn hidden_password_confirmed(prompt: &str) -> Result<Zeroizing<String>> {
    let password = hidden_password(prompt)?;
    let confirmation = hidden_password("Confirm password: ")?;
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
    fn duration_parser_is_bounded() {
        assert_eq!(parse_duration("500ms").ok(), Some(1));
        assert_eq!(parse_duration("2m").ok(), Some(120));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("30").is_err());
    }
}
