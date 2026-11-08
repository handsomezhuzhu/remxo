use crate::approval::Approval;
use crate::audit::{AuditEvent, AuditLog};
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{AppPaths, Config, TransportKind};
use crate::error::{AppError, Result};
use crate::task::TaskSummary;
use crate::transport::openssh::OpensshTransport;
use crate::tunnel::TunnelSummary;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind, KeyModifiers,
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
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState};
use std::io::{Stdout, stdout};
use std::time::Duration;

const PAGES_EN: [&str; 7] = [
    "Hosts",
    "Sessions",
    "Tasks",
    "Approvals",
    "Audit",
    "Backup",
    "Settings",
];
const PAGES_ZH: [&str; 7] = ["主机", "会话", "任务", "审批", "审计", "备份", "设置"];

fn pages(language: crate::config::UiLanguage) -> &'static [&'static str; 7] {
    match language {
        crate::config::UiLanguage::En => &PAGES_EN,
        crate::config::UiLanguage::ZhCn => &PAGES_ZH,
    }
}

struct App {
    page: usize,
    page_flash_started: Option<std::time::Instant>,
    selected: usize,
    search: crate::text_input::TextInput,
    searching: bool,
    message: String,
    tasks: Vec<TaskSummary>,
    approvals: Vec<Approval>,
    tunnels: Vec<TunnelSummary>,
    audit: Vec<AuditEvent>,
    vault_locked: bool,
    no_color: bool,
    language: crate::config::UiLanguage,
}

impl Default for App {
    fn default() -> Self {
        Self {
            page: 0,
            page_flash_started: None,
            selected: 0,
            search: crate::text_input::TextInput::new(256),
            searching: false,
            message: "L1 development build — remote output is untrusted".into(),
            tasks: Vec::new(),
            approvals: Vec::new(),
            tunnels: Vec::new(),
            audit: Vec::new(),
            vault_locked: true,
            no_color: false,
            language: crate::config::UiLanguage::En,
        }
    }
}

enum SettingsAction {
    Language,
    Timeout(i64),
    MaxOutput(i64),
}

fn switch_page(app: &mut App, page: usize) {
    app.page = page.min(PAGES_EN.len() - 1);
    app.selected = 0;
    app.page_flash_started = Some(std::time::Instant::now());
}

fn page_flash_frame(app: &App) -> Option<usize> {
    let started = app.page_flash_started?;
    let elapsed = started.elapsed();
    if elapsed >= Duration::from_millis(900) {
        return None;
    }
    Some((elapsed.as_millis() / 150) as usize % 3)
}

fn change_settings(paths: &AppPaths, app: &mut App, action: SettingsAction) -> Result<String> {
    let mut config = Config::load(&paths.config)?;
    match action {
        SettingsAction::Language => {
            config.settings.language = match config.settings.language {
                crate::config::UiLanguage::En => crate::config::UiLanguage::ZhCn,
                crate::config::UiLanguage::ZhCn => crate::config::UiLanguage::En,
            };
        }
        SettingsAction::Timeout(delta) => {
            let current = config.settings.timeout_seconds.min(i64::MAX as u64) as i64;
            config.settings.timeout_seconds = current.saturating_add(delta).clamp(5, 3600) as u64;
        }
        SettingsAction::MaxOutput(delta) => {
            let current = config.settings.max_output.min(i64::MAX as usize) as i64;
            config.settings.max_output =
                current.saturating_add(delta).clamp(1024, 64 * 1024 * 1024) as usize;
        }
    }
    config.save(&paths.config)?;
    app.language = config.settings.language;
    Ok(match config.settings.language {
        crate::config::UiLanguage::ZhCn => format!(
            "设置已保存：语言 {}，超时 {} 秒，输出上限 {} 字节。",
            "zh-CN", config.settings.timeout_seconds, config.settings.max_output
        ),
        crate::config::UiLanguage::En => format!(
            "Settings saved: language {}, timeout {}s, max output {} bytes.",
            "en", config.settings.timeout_seconds, config.settings.max_output
        ),
    })
}

pub async fn run(paths: AppPaths) -> Result<()> {
    run_with_options(paths, false).await
}

pub async fn run_with_options(paths: AppPaths, no_color: bool) -> Result<()> {
    let no_color = no_color || std::env::var_os("NO_COLOR").is_some();
    enable_raw_mode().map_err(|e| AppError::io("enable TUI raw mode", e))?;
    if let Err(error) = execute!(stdout(), EnableBracketedPaste, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(AppError::io("enter alternate screen", error));
    }
    let backend = CrosstermBackend::new(stdout());
    let result = match Terminal::new(backend) {
        Ok(terminal) => run_loop(terminal, paths, no_color).await,
        Err(error) => Err(AppError::io("create TUI terminal", error)),
    };
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), DisableBracketedPaste, LeaveAlternateScreen);
    result
}

async fn run_loop(
    mut terminal: Terminal<CrosstermBackend<Stdout>>,
    paths: AppPaths,
    no_color: bool,
) -> Result<()> {
    let language = Config::load(&paths.config)
        .map(|config| config.settings.language)
        .unwrap_or_default();
    let mut app = App {
        no_color,
        language,
        message: language
            .text(
                "L1 development build — remote output is untrusted",
                "L1 开发版本 — 远程输出不可信",
            )
            .into(),
        ..App::default()
    };
    let client = BrokerClient::new(paths.clone());
    let _ = client.ensure_running().await;
    let mut last_refresh = std::time::Instant::now() - Duration::from_secs(3);
    loop {
        if app
            .page_flash_started
            .is_some_and(|started| started.elapsed() >= Duration::from_millis(900))
        {
            app.page_flash_started = None;
        }
        if last_refresh.elapsed() >= Duration::from_secs(2) {
            refresh(&client, &mut app).await;
            if let Ok(log) = AuditLog::new(&paths.audit()) {
                app.audit = log.recent(50).unwrap_or_default();
            }
            last_refresh = std::time::Instant::now();
        }
        let config = Config::load(&paths.config);
        terminal
            .draw(|frame| draw(frame, &app, config.as_ref().ok()))
            .map_err(|e| AppError::io("draw TUI", e))?;
        if !event::poll(Duration::from_millis(250))
            .map_err(|e| AppError::io("poll TUI input", e))?
        {
            continue;
        }
        let incoming = event::read().map_err(|e| AppError::io("read TUI input", e))?;
        if app.searching
            && let Event::Paste(text) = incoming
        {
            let _ = app.search.paste(&text);
            app.selected = 0;
            continue;
        }
        let Event::Key(key) = incoming else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if app.searching {
            match key.code {
                KeyCode::Esc => {
                    app.searching = false;
                    app.search.clear();
                }
                KeyCode::Enter => app.searching = false,
                KeyCode::Backspace => {
                    app.search.backspace();
                    app.selected = 0;
                }
                KeyCode::Delete => {
                    app.search.delete();
                    app.selected = 0;
                }
                KeyCode::Left => {
                    app.search.move_left();
                }
                KeyCode::Right => {
                    app.search.move_right();
                }
                KeyCode::Home => app.search.move_home(),
                KeyCode::End => app.search.move_end(),
                KeyCode::Char(character) => {
                    let _ = app.search.insert_char(character);
                    app.selected = 0;
                }
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') => return Ok(()),
            KeyCode::Esc => return Ok(()),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
            KeyCode::Tab | KeyCode::Right => {
                let next = (app.page + 1) % PAGES_EN.len();
                switch_page(&mut app, next);
            }
            KeyCode::BackTab | KeyCode::Left => {
                let next = (app.page + PAGES_EN.len() - 1) % PAGES_EN.len();
                switch_page(&mut app, next);
            }
            KeyCode::Down if app.page == 0 => {
                let maximum = config
                    .as_ref()
                    .ok()
                    .map(|config| {
                        filtered_hosts(config, app.search.value())
                            .len()
                            .saturating_sub(1)
                    })
                    .unwrap_or(0);
                app.selected = app.selected.saturating_add(1).min(maximum);
            }
            KeyCode::Down => app.selected = app.selected.saturating_add(1),
            KeyCode::Up => app.selected = app.selected.saturating_sub(1),
            KeyCode::Char('a') if app.page == 0 => {
                suspend(&mut terminal)?;
                let result = crate::tui_wizard::run(&paths, None, None, app.no_color).await;
                resume(&mut terminal)?;
                match result {
                    Ok(result) => app.message = result.message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Char('e') if app.page == 0 => {
                if let Ok(config) = &config {
                    let aliases = filtered_hosts(config, app.search.value());
                    if let Some(alias) = aliases.get(app.selected).copied() {
                        suspend(&mut terminal)?;
                        let result =
                            crate::tui_wizard::run_edit(&paths, alias.to_string(), app.no_color)
                                .await;
                        resume(&mut terminal)?;
                        match result {
                            Ok(result) => app.message = result.message,
                            Err(error) => {
                                app.message = crate::i18n::error_message(&error, app.language)
                            }
                        }
                    }
                }
            }
            KeyCode::Char(page @ '1'..='7') => {
                switch_page(&mut app, page as usize - '1' as usize);
            }
            KeyCode::Char('t') if app.page == 0 => {
                if let Ok(config) = &config {
                    let aliases = filtered_hosts(config, app.search.value());
                    if let Some(alias) = aliases.get(app.selected).copied()
                        && let Some(host) = config.hosts.get(alias)
                    {
                        app.message = app
                            .language
                            .text(
                                "Testing the saved connection; no write command will run.",
                                "正在测试已保存的连接，不会执行写入命令。",
                            )
                            .into();
                        terminal
                            .draw(|frame| draw(frame, &app, Some(config)))
                            .map_err(|error| AppError::io("draw connection test status", error))?;
                        app.message = match crate::tui_wizard::test_registered_connection(
                            &paths,
                            alias,
                            host,
                            app.language,
                        )
                        .await
                        {
                            Ok((message, _)) => message,
                            Err(error) => crate::i18n::error_message(&error, app.language),
                        };
                    }
                }
            }
            KeyCode::Char('e' | '+') if app.page == 6 => {
                let action = if key.code == KeyCode::Char('e') {
                    SettingsAction::Language
                } else {
                    SettingsAction::Timeout(5)
                };
                match change_settings(&paths, &mut app, action) {
                    Ok(message) => app.message = message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Char('-') if app.page == 6 => {
                match change_settings(&paths, &mut app, SettingsAction::Timeout(-5)) {
                    Ok(message) => app.message = message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Char(']') if app.page == 6 => {
                match change_settings(&paths, &mut app, SettingsAction::MaxOutput(4096)) {
                    Ok(message) => app.message = message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Char('[') if app.page == 6 => {
                match change_settings(&paths, &mut app, SettingsAction::MaxOutput(-4096)) {
                    Ok(message) => app.message = message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Enter if app.page == 6 => {
                match change_settings(&paths, &mut app, SettingsAction::Language) {
                    Ok(message) => app.message = message,
                    Err(error) => app.message = crate::i18n::error_message(&error, app.language),
                }
            }
            KeyCode::Char('/') => app.searching = app.page == 0,
            KeyCode::Char('l') => match client.call(RpcRequest::Lock).await {
                Ok(_) => app.message = app.language.text("Vault locked", "Vault 已锁定").into(),
                Err(error) => app.message = error.message,
            },
            KeyCode::Char('u') => {
                unlock_prompt(&mut terminal, &client, &mut app).await?;
            }
            KeyCode::Enter if app.page == 0 => {
                if let Ok(config) = &config {
                    let aliases = filtered_hosts(config, app.search.value());
                    if let Some(alias) = aliases.get(app.selected).copied() {
                        interactive_ssh(&mut terminal, &paths, config, alias, &mut app).await?;
                    }
                }
            }
            _ => {}
        }
    }
}

async fn refresh(client: &BrokerClient, app: &mut App) {
    match client.call(RpcRequest::Status).await {
        Ok(RpcPayload::Status(status)) => app.vault_locked = status.vault_locked,
        Ok(_) => app.message = "Unexpected Broker status response".into(),
        Err(error) => app.message = format!("Broker unavailable: {}", error.message),
    }
    if let Ok(RpcPayload::Tasks(tasks)) = client.call(RpcRequest::TaskList).await {
        app.tasks = tasks;
    }
    if let Ok(RpcPayload::Approvals(approvals)) = client.call(RpcRequest::ApprovalList).await {
        app.approvals = approvals;
    }
    if let Ok(RpcPayload::Tunnels(tunnels)) = client.call(RpcRequest::TunnelList).await {
        app.tunnels = tunnels;
    }
}

async fn unlock_prompt(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    client: &BrokerClient,
    app: &mut App,
) -> Result<()> {
    suspend(terminal)?;
    let password = crate::masked_prompt::prompt(app.language.text("Master password: ", "主密码："));
    resume(terminal)?;
    match password {
        Ok(password) => match client
            .call(RpcRequest::Unlock {
                password: password.to_string(),
            })
            .await
        {
            Ok(_) => app.message = app.language.text("Vault unlocked", "Vault 已解锁").into(),
            Err(error) => app.message = error.message,
        },
        Err(error) => app.message = format!("Password input failed: {error}"),
    }
    Ok(())
}

async fn interactive_ssh(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    paths: &AppPaths,
    config: &Config,
    alias: &str,
    app: &mut App,
) -> Result<()> {
    let Some(host) = config.hosts.get(alias) else {
        return Ok(());
    };
    suspend(terminal)?;
    let context = crate::transport::AuthenticationContext::registered(paths.clone(), alias, host);
    let result = OpensshTransport::default()
        .interactive_authenticated(host, context.as_ref())
        .await;
    resume(terminal)?;
    app.message = match result {
        Ok(code) => match app.language {
            crate::config::UiLanguage::ZhCn => format!("交互式 SSH 已退出，退出码 {code}"),
            crate::config::UiLanguage::En => format!("Interactive SSH exited with code {code}"),
        },
        Err(error) => error.message,
    };
    Ok(())
}

pub(crate) fn suspend(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().map_err(|e| AppError::io("suspend TUI", e))?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    )
    .map_err(|e| AppError::io("leave TUI", e))
}

pub(crate) fn resume(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    enable_raw_mode().map_err(|e| AppError::io("resume TUI", e))?;
    execute!(
        terminal.backend_mut(),
        EnableBracketedPaste,
        EnterAlternateScreen
    )
    .map_err(|e| AppError::io("restore TUI", e))?;
    terminal.clear().map_err(|e| AppError::io("clear TUI", e))
}

fn filtered_hosts<'a>(config: &'a Config, search: &str) -> Vec<&'a str> {
    config
        .hosts
        .keys()
        .filter(|alias| search.is_empty() || alias.contains(search))
        .map(String::as_str)
        .collect()
}

fn draw(frame: &mut ratatui::Frame, app: &App, config: Option<&Config>) {
    let columns = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(3),
    ])
    .split(frame.area());
    let page_names = pages(app.language);
    let flash_frame = page_flash_frame(app);
    let mut tab_spans = Vec::new();
    for (index, name) in page_names.iter().enumerate() {
        let active = index == app.page;
        let style = if active {
            match flash_frame {
                Some(_frame) if app.no_color || std::env::var_os("NO_COLOR").is_some() => {
                    Style::default().add_modifier(Modifier::BOLD)
                }
                Some(_) => Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                None => Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            }
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let marker = if active {
            match flash_frame {
                Some(0) => "▶ ",
                Some(1) => "► ",
                Some(2) => "▸ ",
                _ => "● ",
            }
        } else {
            ""
        };
        tab_spans.push(Span::styled(format!("{marker}{name}"), style));
        if index + 1 < page_names.len() {
            tab_spans.push(Span::raw("  ·  "));
        }
    }
    let title = format!(
        " Remxo │ {} │ Vault {} │ L1 ",
        page_names[app.page],
        match (app.vault_locked, app.language) {
            (true, crate::config::UiLanguage::En) => "LOCKED",
            (false, crate::config::UiLanguage::En) => "UNLOCKED",
            (true, crate::config::UiLanguage::ZhCn) => "已锁定",
            (false, crate::config::UiLanguage::ZhCn) => "已解锁",
        }
    );
    frame.render_widget(
        Paragraph::new(Line::from(tab_spans))
            .block(Block::default().borders(Borders::ALL).title(title)),
        columns[0],
    );
    match app.page {
        0 => draw_hosts(frame, app, config, columns[1]),
        1 => draw_lines(
            frame,
            app.language.text("Tunnels", "隧道"),
            app.tunnels
                .iter()
                .map(|item| {
                    format!(
                        "{}  {}  {}  {:?}",
                        item.id, item.host, item.argument, item.kind
                    )
                })
                .collect(),
            columns[1],
        ),
        2 => draw_lines(
            frame,
            app.language.text("Tasks", "任务"),
            app.tasks
                .iter()
                .map(|item| {
                    format!(
                        "{}  {}  {:?}  {:?}",
                        item.id, item.host, item.state, item.error
                    )
                })
                .collect(),
            columns[1],
        ),
        3 => draw_lines(
            frame,
            app.language.text("One-time approvals", "一次性审批"),
            app.approvals
                .iter()
                .map(|item| {
                    format!(
                        "{}  {}  approved={}  expires={}",
                        item.id, item.host, item.approved, item.expires_at
                    )
                })
                .collect(),
            columns[1],
        ),
        4 => draw_lines(
            frame,
            app.language.text("Audit metadata", "审计元数据"),
            app.audit
                .iter()
                .map(|item| {
                    format!(
                        "{}  {}  {}  {}  exit={:?}  {}",
                        item.time,
                        item.host,
                        item.operation,
                        item.decision,
                        item.exit_code,
                        item.request_digest
                    )
                })
                .collect(),
            columns[1],
        ),
        5 => draw_lines(
            frame,
            app.language.text("Encrypted backup", "加密备份"),
            vec![
                app.language
                    .text(
                        "Use remxo backup create|verify|restore with a hidden backup password.",
                        "使用 remxo backup create|verify|restore，并通过隐藏提示输入备份密码。",
                    )
                    .into(),
                app.language
                    .text(
                        "Backups contain no sockets, runtime approvals, sessions, logs, or plaintext DEK.",
                        "备份不包含套接字、运行时审批、会话、日志或明文 DEK。",
                    )
                    .into(),
            ],
            columns[1],
        ),
        6 => {
            let lines = config
                .map(|config| {
                    vec![
                        format!("timeout = {}s", config.settings.timeout_seconds),
                        format!("max_output = {} bytes", config.settings.max_output),
                        format!("allow_ad_hoc = {}", config.settings.allow_ad_hoc),
                        format!(
                            "language = {}",
                            match config.settings.language {
                                crate::config::UiLanguage::En => "en",
                                crate::config::UiLanguage::ZhCn => "zh-CN",
                            }
                        ),
                        config.settings.language.text(
                            "Security level: L1 (same-user Broker, not L2 isolation)",
                            "安全级别：L1（同用户 Broker，不是 L2 隔离）",
                        )
                        .into(),
                        config.settings.language.text(
                            "e/Enter: switch language · +/-: timeout · [/]: output limit (changes save immediately)",
                            "e/Enter 切换语言 · +/- 调整超时 · [/] 调整输出上限（更改后立即保存）",
                        )
                        .into(),
                    ]
                })
                .unwrap_or_else(|| {
                    vec![
                        app.language
                            .text("Config unavailable", "配置不可用")
                            .into(),
                    ]
                });
            draw_lines(
                frame,
                app.language.text("Settings", "设置"),
                lines,
                columns[1],
            );
        }
        _ => {}
    }
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}",
            app.message,
            if app.page == 6 {
                app.language.text(
                    "Settings: e/Enter language · +/- timeout · [/] max output (atomic save, config backed up)",
                    "设置：e/Enter 语言 · +/- 超时 · [/] 输出上限（原子保存并备份配置）",
                )
            } else {
                app.language.text(
                    "1-7/Tab pages │ ↑↓ select │ a add │ e edit │ t test │ / search │ Enter SSH │ u unlock │ l lock │ q/Esc/Ctrl+C quit",
                    "1-7/Tab 页面 │ ↑↓ 选择 │ a 添加 │ e 编辑 │ t 测试 │ / 搜索 │ Enter SSH │ u 解锁 │ l 锁定 │ q/Esc/Ctrl+C 退出",
                )
            }
        ))
        .block(Block::default().borders(Borders::ALL)),
        columns[2],
    );
}

fn draw_hosts(
    frame: &mut ratatui::Frame,
    app: &App,
    config: Option<&Config>,
    area: ratatui::layout::Rect,
) {
    let Some(config) = config else {
        draw_lines(
            frame,
            app.language.text("Hosts", "主机"),
            vec![
                app.language
                    .text(
                        "Configuration missing or invalid; run remxo init or fix config.toml.",
                        "配置缺失或无效；请运行 remxo init 或修复 config.toml。",
                    )
                    .into(),
            ],
            area,
        );
        return;
    };
    let aliases = filtered_hosts(config, app.search.value());
    let rows = aliases.iter().filter_map(|alias| {
        config.hosts.get(*alias).map(|host| {
            let agent = if host.auth == crate::config::AuthMode::ExternalAgent {
                crate::transport::check_agent_available(host)
            } else {
                true
            };
            Row::new(vec![
                Cell::from((*alias).to_string()),
                Cell::from(host.number.map(|n| n.to_string()).unwrap_or_default()),
                Cell::from(host.environment.clone()),
                Cell::from(format!("{:?}", host.transport)),
                Cell::from(if host.transport == TransportKind::Telnet {
                    app.language.text("INSECURE", "不安全").to_string()
                } else if host.auth == crate::config::AuthMode::ExternalAgent {
                    if agent {
                        app.language.text("Agent available", "Agent 可用").into()
                    } else {
                        app.language
                            .text("Agent unavailable", "Agent 不可用")
                            .into()
                    }
                } else if matches!(
                    host.auth,
                    crate::config::AuthMode::VaultPassword | crate::config::AuthMode::VaultKey
                ) {
                    match (app.vault_locked, app.language) {
                        (true, crate::config::UiLanguage::En) => "Vault locked".into(),
                        (false, crate::config::UiLanguage::En) => "Vault unlocked".into(),
                        (true, crate::config::UiLanguage::ZhCn) => "Vault 已锁定".into(),
                        (false, crate::config::UiLanguage::ZhCn) => "Vault 已解锁".into(),
                    }
                } else {
                    app.language.text("OpenSSH config", "OpenSSH 配置").into()
                }),
            ])
        })
    });
    let filter_prefix = format!(
        "{} — {}: ",
        app.language.text("Hosts", "主机"),
        app.language.text("filter", "筛选")
    );
    let (filter, filter_cursor) = if app.searching {
        app.search
            .window(area.width.saturating_sub(12).max(1) as usize, None)
    } else {
        (app.search.value().to_string(), 0)
    };
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(24),
            Constraint::Length(7),
            Constraint::Percentage(18),
            Constraint::Length(11),
            Constraint::Percentage(40),
        ],
    )
    .header(
        Row::new([
            app.language.text("Alias", "别名"),
            app.language.text("Number", "编号"),
            app.language.text("Environment", "环境"),
            app.language.text("Transport", "传输"),
            app.language.text("State", "状态"),
        ])
        .style(if app.no_color {
            Style::default()
        } else {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        }),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("{filter_prefix}{filter}")),
    )
    .row_highlight_style(if app.no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(Color::DarkGray)
    })
    .highlight_symbol(if app.no_color { " > " } else { "" });
    let mut state = TableState::default()
        .with_selected(Some(app.selected.min(aliases.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut state);
    if app.searching {
        let x = (area.x
            + 1
            + crate::text_input::display_width(&filter_prefix) as u16
            + filter_cursor as u16)
            .min(area.x + area.width.saturating_sub(2));
        frame.set_cursor_position((x, area.y));
    }
}

fn draw_lines(
    frame: &mut ratatui::Frame,
    title: &str,
    lines: Vec<String>,
    area: ratatui::layout::Rect,
) {
    let items = if lines.is_empty() {
        vec![ListItem::new("No entries")]
    } else {
        lines.into_iter().map(ListItem::new).collect()
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_changes_are_bounded_persistent_and_preserve_hosts() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        let mut config =
            Config::initialize(&paths.config).unwrap_or_else(|error| panic!("config: {error}"));
        config.hosts.insert(
            "oracle".into(),
            crate::config::Host {
                hostname: Some("192.0.2.50".into()),
                ..crate::config::Host::default()
            },
        );
        config
            .save(&paths.config)
            .unwrap_or_else(|error| panic!("save: {error}"));
        let mut app = App::default();
        change_settings(&paths, &mut app, SettingsAction::Language)
            .unwrap_or_else(|error| panic!("language: {error}"));
        change_settings(&paths, &mut app, SettingsAction::Timeout(-20))
            .unwrap_or_else(|error| panic!("timeout floor: {error}"));
        change_settings(&paths, &mut app, SettingsAction::MaxOutput(4096))
            .unwrap_or_else(|error| panic!("max output: {error}"));
        let restored = Config::load(&paths.config).unwrap_or_else(|error| panic!("load: {error}"));
        assert_eq!(restored.settings.language, crate::config::UiLanguage::ZhCn);
        assert_eq!(restored.settings.timeout_seconds, 10);
        assert_eq!(restored.settings.max_output, 65_536 + 4096);
        assert!(restored.hosts.contains_key("oracle"));
        assert_eq!(app.language, restored.settings.language);
    }
}
