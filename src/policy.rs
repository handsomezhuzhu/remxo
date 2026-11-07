use crate::config::{ApprovalMode, Host, RawMode};
use crate::error::{AppError, ErrorCode, Result};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

static SERVICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_.@-]{1,64}$")
        .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});

pub fn profile_script(name: &str, arguments: &BTreeMap<String, String>) -> Result<String> {
    match name {
        "status" => {
            reject_arguments(arguments, &[])?;
            Ok("uname -a; uptime".into())
        }
        "disk" => {
            reject_arguments(arguments, &[])?;
            Ok("df -h".into())
        }
        "memory" => {
            reject_arguments(arguments, &[])?;
            Ok("free -m".into())
        }
        "service_status" => {
            reject_arguments(arguments, &["service"])?;
            let service = required_service(arguments)?;
            Ok(format!(
                "systemctl status -- {}",
                crate::shell::posix_quote(service)
            ))
        }
        "logs" => {
            reject_arguments(arguments, &["service", "lines"])?;
            let service = required_service(arguments)?;
            let lines = match arguments.get("lines") {
                Some(value) => value.parse::<u16>().map_err(|_| {
                    AppError::invalid_argument(
                        "profile argument lines must be an integer from 1 to 1000",
                    )
                })?,
                None => 100,
            };
            if !(1..=1000).contains(&lines) {
                return Err(AppError::invalid_argument(
                    "profile argument lines must be from 1 to 1000",
                ));
            }
            Ok(format!(
                "journalctl -u {} -n {} --no-pager",
                crate::shell::posix_quote(service),
                lines
            ))
        }
        _ => Err(AppError::new(
            ErrorCode::InvalidArgument,
            format!(
                "unknown profile: {name}; available: status, disk, memory, service_status, logs"
            ),
        )),
    }
}

fn reject_arguments(arguments: &BTreeMap<String, String>, allowed: &[&str]) -> Result<()> {
    if let Some(name) = arguments
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(AppError::invalid_argument(format!(
            "unsupported profile argument: {name}"
        )));
    }
    Ok(())
}

fn required_service(arguments: &BTreeMap<String, String>) -> Result<&str> {
    let service = arguments
        .get("service")
        .ok_or_else(|| AppError::invalid_argument("profile argument service is required"))?;
    if !SERVICE.is_match(service) {
        return Err(AppError::invalid_argument(
            "service must match [A-Za-z0-9_.@-]{1,64}",
        ));
    }
    Ok(service)
}

pub fn evaluate(host: &Host, script: &str, sudo: bool, profile: bool) -> Result<bool> {
    if !profile && host.raw_mode == RawMode::Deny {
        return Err(AppError::new(
            ErrorCode::PolicyDenied,
            "raw commands are denied for this host; use an allowed read-only profile",
        ));
    }
    if !profile && host.raw_mode == RawMode::ReadOnly {
        return Err(AppError::new(
            ErrorCode::PolicyDenied,
            "this host permits profiles only, not arbitrary raw commands",
        ));
    }
    if sudo {
        return Ok(true);
    }
    match host.approval {
        ApprovalMode::Never => Ok(false),
        ApprovalMode::Always => Ok(true),
        ApprovalMode::Writes => Ok(!is_unambiguous_read(script)),
    }
}

fn is_unambiguous_read(script: &str) -> bool {
    if script.chars().any(|character| {
        matches!(
            character,
            '\n' | '\r' | ';' | '|' | '&' | '<' | '>' | '`' | '$'
        )
    }) {
        return false;
    }
    let Ok(words) = shell_words::split(script) else {
        return false;
    };
    let Some(command) = words.first().map(String::as_str) else {
        return false;
    };
    match command {
        "ls" | "pwd" | "df" | "free" | "uptime" | "whoami" | "hostname" | "date" | "ps" | "cat"
        | "uname" => true,
        "systemctl" => words.get(1).is_some_and(|value| value == "status") && words.len() >= 2,
        "journalctl" => !words.iter().any(|value| {
            matches!(
                value.as_str(),
                "--vacuum-size" | "--vacuum-time" | "--rotate" | "--flush"
            )
        }),
        "git" => words.get(1).is_some_and(|value| {
            matches!(
                value.as_str(),
                "status" | "log" | "show" | "diff" | "branch"
            )
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_typed_and_shell_quoted() {
        let mut arguments = BTreeMap::new();
        arguments.insert("service".into(), "nginx; touch /tmp/nope".into());
        assert!(profile_script("logs", &arguments).is_err());
        arguments.insert("service".into(), "nginx".into());
        arguments.insert("lines".into(), "100;id".into());
        assert!(profile_script("logs", &arguments).is_err());
        arguments.insert("lines".into(), "100".into());
        assert_eq!(
            profile_script("logs", &arguments).ok().as_deref(),
            Some("journalctl -u 'nginx' -n 100 --no-pager")
        );
    }

    #[test]
    fn unknown_raw_commands_need_approval_but_obvious_reads_do_not() {
        assert!(is_unambiguous_read("'ls' '-la'"));
        assert!(is_unambiguous_read("systemctl status nginx"));
        assert!(!is_unambiguous_read("systemctl restart nginx"));
        assert!(!is_unambiguous_read("ls; id"));
        assert!(!is_unambiguous_read("echo $(id)"));
    }
}
