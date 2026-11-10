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
        "pwd" | "uptime" | "whoami" => words.len() == 1,
        "ls" | "df" | "free" | "ps" | "cat" | "uname" => true,
        "hostname" => match words.get(1).map(String::as_str) {
            None => true,
            Some(
                "-f" | "--fqdn" | "-s" | "--short" | "-d" | "--domain" | "-i" | "--ip-address"
                | "-I" | "--all-ip-addresses",
            ) => words.len() == 2,
            _ => false,
        },
        "date" => match words.get(1).map(String::as_str) {
            None => true,
            Some(
                "-u" | "--utc" | "--universal" | "-R" | "--rfc-email" | "--rfc-3339" | "-I"
                | "--iso-8601",
            ) => words.len() == 2,
            Some(option) if option.starts_with("--rfc-3339=") => words.len() == 2,
            Some(option) if option.starts_with("--iso-8601") => words.len() == 2,
            _ => false,
        },
        "systemctl" => words.len() >= 2 && words[1] == "status",
        "journalctl" => !words.iter().any(|value| {
            value.starts_with("--vacuum-")
                || matches!(
                    value.as_str(),
                    "--rotate"
                        | "--flush"
                        | "--sync"
                        | "--relinquish-var"
                        | "--smart-relinquish-var"
                )
        }),
        "git" => git_is_unambiguous_read(&words),
        _ => false,
    }
}

fn git_is_unambiguous_read(words: &[String]) -> bool {
    match words.get(1).map(String::as_str) {
        Some("status") => true,
        Some("log" | "show" | "diff") => !words.iter().any(|value| value.starts_with("--output")),
        Some("branch") => match words.get(2).map(String::as_str) {
            None
            | Some(
                "-l" | "--list" | "-a" | "--all" | "-r" | "--remotes" | "-v" | "--verbose" | "-vv"
                | "--show-current" | "--no-column",
            ) => !words.iter().skip(2).any(|value| {
                value.starts_with("--column")
                    || value.starts_with("--no-column=")
                    || value.starts_with("--sort")
            }),
            Some(option) if option.strip_prefix("--list=") == Some("") => words.len() == 3,
            _ => false,
        },
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

    #[test]
    fn commands_that_can_write_require_approval() {
        for script in [
            "git branch -D feature",
            "git branch new-feature",
            "git branch --column=always",
            "git branch --no-column=always",
            "git branch --sort=-committerdate",
            "git branch --list --sort=-committerdate",
            "git branch --contains=main",
            "git diff --output=patch",
            "git diff --output patch",
            "git log --output=patch",
            "journalctl --vacuum-size=1M",
            "journalctl --vacuum-size 1M",
            "journalctl --vacuum-files=1",
            "date --set=now",
            "date --set now",
            "date -s now",
            "date +%Y",
            "date -u +%Y",
            "date --reference=now",
            "hostname new-name",
            "hostname -f new-name",
            "uptime -p",
            "whoami root",
            "pwd -P",
        ] {
            assert!(
                !is_unambiguous_read(script),
                "must require approval: {script}"
            );
        }
    }

    #[test]
    fn read_options_and_ordinary_git_reads_remain_exempt() {
        for script in [
            "git status --short",
            "git diff HEAD -- file",
            "git branch --list",
            "git branch --list feature",
            "git branch --no-column",
            "git branch -a",
            "journalctl -n 100 --no-pager",
            "date -u",
            "date --iso-8601=seconds",
            "hostname --fqdn",
            "hostname -f",
        ] {
            assert!(is_unambiguous_read(script), "known read: {script}");
        }
    }

    #[test]
    fn writes_approval_keeps_sudo_and_mode_semantics() {
        let mut host = Host::default();
        assert_eq!(
            evaluate(&host, "date --set=now", false, false).ok(),
            Some(true)
        );
        assert!(evaluate(&host, "hostname new-name", true, false).ok() == Some(true));
        assert_eq!(evaluate(&host, "date -u", false, false).ok(), Some(false));

        host.approval = crate::config::ApprovalMode::Never;
        assert_eq!(
            evaluate(&host, "hostname new-name", false, false).ok(),
            Some(false)
        );
        host.approval = crate::config::ApprovalMode::Always;
        assert!(evaluate(&host, "date -u", false, false).ok() == Some(true));
    }
}
