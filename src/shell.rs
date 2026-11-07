use crate::config::ShellKind;
use crate::error::{AppError, ErrorCode, Result};

pub fn posix_quote(value: &str) -> String {
    if value.contains('\0') {
        return "''".to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub fn command_script(arguments: &[String], shell: ShellKind) -> Result<String> {
    if arguments.is_empty() {
        return Err(AppError::invalid_argument("remote command is empty"));
    }
    if shell != ShellKind::Posix {
        return Err(AppError::new(
            ErrorCode::UnsupportedShell,
            format!(
                "non-interactive command composition is implemented only for POSIX shell, not {shell:?}"
            ),
        ));
    }
    if arguments.iter().any(|value| value.contains('\0')) {
        return Err(AppError::invalid_argument(
            "NUL is not valid in a remote command",
        ));
    }
    if arguments.len() == 1 {
        return Ok(arguments[0].clone());
    }
    Ok(arguments
        .iter()
        .map(|argument| posix_quote(argument))
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn with_cwd(script: &str, cwd: Option<&str>, shell: ShellKind) -> Result<String> {
    let Some(cwd) = cwd else {
        return Ok(script.to_string());
    };
    if shell != ShellKind::Posix {
        return Err(AppError::new(
            ErrorCode::UnsupportedShell,
            "--cwd currently requires POSIX shell",
        ));
    }
    if cwd.is_empty() || cwd.contains('\0') {
        return Err(AppError::invalid_argument("invalid working directory"));
    }
    Ok(format!("cd {} && ({})", posix_quote(cwd), script))
}

pub fn sudo_script(script: &str, shell: ShellKind) -> Result<String> {
    if shell != ShellKind::Posix {
        return Err(AppError::new(
            ErrorCode::UnsupportedShell,
            "sudo injection currently requires POSIX shell and /bin/sh",
        ));
    }
    Ok(format!(
        "sudo -S -p '' -- /bin/sh -c {}",
        posix_quote(script)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_arguments_cannot_inject_a_second_command() {
        let args = vec!["printf".into(), "%s".into(), "x; touch /tmp/nope".into()];
        let script = command_script(&args, ShellKind::Posix)
            .ok()
            .unwrap_or_default();
        assert_eq!(script, "'printf' '%s' 'x; touch /tmp/nope'");
    }

    #[test]
    fn cwd_is_quoted() {
        let value = "/tmp/a'; touch /tmp/nope; echo '";
        let script = with_cwd("pwd", Some(value), ShellKind::Posix)
            .ok()
            .unwrap_or_default();
        assert!(script.starts_with("cd '/tmp/a'\"'\"'; touch"));
        assert!(script.ends_with(" && (pwd)"));
    }

    #[test]
    fn non_posix_shells_fail_instead_of_using_posix_quoting() {
        let error = command_script(&["Get-ChildItem".into()], ShellKind::Powershell).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedShell);
    }

    #[test]
    fn single_argument_is_an_explicit_raw_script() {
        let args = vec!["cd /var/www && ls -la".to_string()];
        assert_eq!(
            command_script(&args, ShellKind::Posix).ok().as_deref(),
            Some("cd /var/www && ls -la")
        );
    }
}
