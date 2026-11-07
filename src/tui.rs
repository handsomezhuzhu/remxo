use crate::approval::Approval;
use crate::audit::{AuditEvent, AuditLog};
use crate::broker::{BrokerClient, RpcPayload, RpcRequest};
use crate::config::{AppPaths, Config, TransportKind};
use crate::error::{AppError, Result};
use crate::task::TaskSummary;
use crate::transport::Transport as _;
use crate::transport::openssh::OpensshTransport;
use crate::tunnel::TunnelSummary;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState};
use std::io::{Stdout, stdout};
use std::time::Duration;

const PAGES: [&str; 7] = [
    "Hosts",
    "Sessions",
    "Tasks",
    "Approvals",
    "Audit",
    "Backup",
    "Settings",
];

struct App {
    page: usize,
    selected: usize,
    search: String,
    searching: bool,
    message: String,
    tasks: Vec<TaskSummary>,
    approvals: Vec<Approval>,
    tunnels: Vec<TunnelSummary>,
    audit: Vec<AuditEvent>,
    vault_locked: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            page: 0,
            selected: 0,
            search: String::new(),
            searching: false,
            message: "L1 development build — remote output is untrusted".into(),
            tasks: Vec::new(),
            approvals: Vec::new(),
            tunnels: Vec::new(),
            audit: Vec::new(),
            vault_locked: true,
        }
    }
}

pub async fn run(paths: AppPaths) -> Result<()> {
    enable_raw_mode().map_err(|e| AppError::io("enable TUI raw mode", e))?;
    if let Err(error) = execute!(stdout(), EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(AppError::io("enter alternate screen", error));
    }
    let backend = CrosstermBackend::new(stdout());
    let result = match Terminal::new(backend) {
        Ok(terminal) => run_loop(terminal, paths).await,
        Err(error) => Err(AppError::io("create TUI terminal", error)),
    };
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
    result
}

async fn run_loop(mut terminal: Terminal<CrosstermBackend<Stdout>>, paths: AppPaths) -> Result<()> {
    let mut app = App::default();
    let client = BrokerClient::new(paths.clone());
    let _ = client.ensure_running().await;
    let mut last_refresh = std::time::Instant::now() - Duration::from_secs(3);
    loop {
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
        let Event::Key(key) = event::read().map_err(|e| AppError::io("read TUI input", e))? else {
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
                    app.search.pop();
                }
                KeyCode::Char(character) => app.search.push(character),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') => return Ok(()),
            KeyCode::Tab | KeyCode::Right => app.page = (app.page + 1) % PAGES.len(),
            KeyCode::BackTab | KeyCode::Left => {
                app.page = (app.page + PAGES.len() - 1) % PAGES.len()
            }
            KeyCode::Down => app.selected = app.selected.saturating_add(1),
            KeyCode::Up => app.selected = app.selected.saturating_sub(1),
            KeyCode::Char('/') => app.searching = app.page == 0,
            KeyCode::Char('l') => match client.call(RpcRequest::Lock).await {
                Ok(_) => app.message = "Vault locked".into(),
                Err(error) => app.message = error.message,
            },
            KeyCode::Char('u') => {
                unlock_prompt(&mut terminal, &client, &mut app).await?;
            }
            KeyCode::Enter if app.page == 0 => {
                if let Ok(config) = &config {
                    let aliases = filtered_hosts(config, &app.search);
                    if let Some(alias) = aliases.get(app.selected).copied() {
                        interactive_ssh(&mut terminal, config, alias, &mut app)?;
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
    let password = rpassword::prompt_password("Master password: ");
    resume(terminal)?;
    match password {
        Ok(password) => match client.call(RpcRequest::Unlock { password }).await {
            Ok(_) => app.message = "Vault unlocked".into(),
            Err(error) => app.message = error.message,
        },
        Err(error) => app.message = format!("Password input failed: {error}"),
    }
    Ok(())
}

fn interactive_ssh(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    config: &Config,
    alias: &str,
    app: &mut App,
) -> Result<()> {
    let Some(host) = config.hosts.get(alias) else {
        return Ok(());
    };
    suspend(terminal)?;
    let result = OpensshTransport::default().interactive(host);
    resume(terminal)?;
    app.message = match result {
        Ok(code) => format!("Interactive SSH exited with code {code}"),
        Err(error) => error.message,
    };
    Ok(())
}

fn suspend(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().map_err(|e| AppError::io("suspend TUI", e))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(|e| AppError::io("leave TUI", e))
}

fn resume(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    enable_raw_mode().map_err(|e| AppError::io("resume TUI", e))?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)
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
    let title = format!(
        " Remxo │ {} │ Vault {} │ L1 ",
        PAGES[app.page],
        if app.vault_locked {
            "LOCKED"
        } else {
            "UNLOCKED"
        }
    );
    frame.render_widget(
        Paragraph::new(PAGES.join("  ·  "))
            .block(Block::default().borders(Borders::ALL).title(title)),
        columns[0],
    );
    match app.page {
        0 => draw_hosts(frame, app, config, columns[1]),
        1 => draw_lines(
            frame,
            "Tunnels",
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
            "Tasks",
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
            "One-time approvals",
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
            "Audit metadata",
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
            "Encrypted backup",
            vec![
                "Use remxo backup create|verify|restore with a hidden backup password.".into(),
                "Backups contain no sockets, runtime approvals, sessions, logs, or plaintext DEK."
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
                        "Security level: L1 (same-user Broker, not L2 isolation)".into(),
                    ]
                })
                .unwrap_or_else(|| vec!["Config unavailable".into()]);
            draw_lines(frame, "Settings", lines, columns[1]);
        }
        _ => {}
    }
    frame.render_widget(
        Paragraph::new(format!(
            "{}\nq quit │ Tab pages │ ↑↓ select │ / search │ Enter SSH │ u unlock │ l lock",
            app.message
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
            "Hosts",
            vec!["Configuration missing or invalid; run remxo init or fix config.toml.".into()],
            area,
        );
        return;
    };
    let aliases = filtered_hosts(config, &app.search);
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
                    "INSECURE".to_string()
                } else if agent {
                    format!(
                        "Vault {} / Agent OK",
                        if app.vault_locked {
                            "locked"
                        } else {
                            "unlocked"
                        }
                    )
                } else {
                    "Agent unavailable".into()
                }),
            ])
        })
    });
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
        Row::new(["Alias", "Number", "Environment", "Transport", "State"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Hosts — filter: {}", app.search)),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    let mut state = TableState::default()
        .with_selected(Some(app.selected.min(aliases.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, &mut state);
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
