use crate::error::{AppError, Result};
use crate::text_input::{TextInput, display_width};
use crossterm::cursor::MoveToColumn;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use crossterm::{execute, queue};
use std::io::{IsTerminal, Write};
use zeroize::Zeroizing;

/// Read a secret on one terminal row. Terminal echo remains disabled; only
/// caller-rendered masks are emitted. The value is returned only to the caller.
pub fn prompt(prompt: &str) -> Result<Zeroizing<String>> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(AppError::invalid_argument(
            "this operation requires an interactive masked prompt; non-interactive input was not read",
        ));
    }
    if prompt.contains(['\r', '\n']) || display_width(prompt) > 4096 {
        return Err(AppError::invalid_argument("invalid masked prompt"));
    }

    let mut terminal = std::io::stderr();
    write!(terminal, "{prompt}")
        .and_then(|()| terminal.flush())
        .map_err(|error| AppError::io("display masked prompt", error))?;
    enable_raw_mode().map_err(|error| AppError::io("enable masked input raw mode", error))?;
    let result = read_masked(&mut terminal, prompt);
    let restore = disable_raw_mode();
    let cleanup = execute!(terminal, DisableBracketedPaste)
        .and_then(|()| writeln!(terminal))
        .and_then(|()| terminal.flush());
    if let Err(error) = restore {
        return Err(AppError::io("disable masked input raw mode", error));
    }
    cleanup.map_err(|error| AppError::io("restore masked input terminal", error))?;
    result
}

fn read_masked(terminal: &mut std::io::Stderr, prompt: &str) -> Result<Zeroizing<String>> {
    execute!(terminal, EnableBracketedPaste)
        .map_err(|error| AppError::io("enable masked paste input", error))?;
    let prompt_width = display_width(prompt) as u16;
    let mut input = TextInput::new(4096);
    loop {
        match event::read().map_err(|error| AppError::io("read masked input", error))? {
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('j' | 'm') => {
                            return Ok(Zeroizing::new(input.value().to_string()));
                        }
                        KeyCode::Char('c' | 'd') | KeyCode::Esc => {
                            return Err(AppError::invalid_argument("password entry cancelled"));
                        }
                        KeyCode::Char('u') => {
                            input.delete_to_start();
                        }
                        KeyCode::Char('w') => {
                            input.delete_word_before();
                        }
                        KeyCode::Char('l') => input.clear(),
                        KeyCode::Left | KeyCode::Home => input.move_home(),
                        KeyCode::Right | KeyCode::End => input.move_end(),
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Enter | KeyCode::Char('\r' | '\n') => {
                            return Ok(Zeroizing::new(input.value().to_string()));
                        }
                        KeyCode::Esc => {
                            return Err(AppError::invalid_argument("password entry cancelled"));
                        }
                        KeyCode::Char(character) => {
                            let _ = input.insert_char(character);
                        }
                        KeyCode::Backspace => {
                            input.backspace();
                        }
                        KeyCode::Delete => {
                            input.delete();
                        }
                        KeyCode::Left => input.move_left(),
                        KeyCode::Right => input.move_right(),
                        KeyCode::Home | KeyCode::PageUp => input.move_home(),
                        KeyCode::End | KeyCode::PageDown => input.move_end(),
                        _ => {}
                    }
                }
            }
            Event::Paste(text) => {
                let _ = input.paste(&text);
            }
            _ => continue,
        }
        let cursor_column =
            prompt_width.saturating_add(input.masked_cursor_display_column('*') as u16);
        queue!(
            terminal,
            MoveToColumn(0),
            Clear(ClearType::UntilNewLine),
            crossterm::style::Print(prompt),
            crossterm::style::Print(input.masked_value('*')),
            MoveToColumn(cursor_column)
        )
        .and_then(|()| terminal.flush())
        .map_err(|error| AppError::io("render masked input", error))?;
    }
}
