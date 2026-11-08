use crate::config::UiLanguage;
use crate::error::{AppError, ErrorCode};

/// Returns a sanitized, human-facing message for display at a CLI/TUI boundary.
///
/// This localizes only the message bound to `AppError`; callers should continue to
/// display the original `error.code` (and any approval ID) separately. It does not
/// change JSON `error.code` or `detail`. Stable Remxo messages are translated, but
/// arbitrary underlying OpenSSH output is not claimed to be fully translated.
pub fn error_message(error: &AppError, language: UiLanguage) -> String {
    let sanitized = crate::redact::sanitize(&error.message);
    if language == UiLanguage::En {
        return sanitized;
    }

    let localized = chinese_message(error.code, &error.message).unwrap_or_else(|| {
        let category = chinese_category(error.code);
        if sanitized.is_empty() {
            category.to_string()
        } else {
            format!("{category}：{sanitized}")
        }
    });
    crate::redact::sanitize(&localized)
}

fn chinese_message(code: ErrorCode, message: &str) -> Option<String> {
    let fixed = match (code, message) {
        (ErrorCode::VaultLocked, "Remxo is locked. A human must run: remxo unlock") => {
            "Remxo 已锁定。请由用户运行 'remxo unlock' 解锁后再操作。"
        }
        (ErrorCode::AuthenticationFailed, "wrong master password or corrupted vault") => {
            "主密码不正确，或 Vault 已损坏。请核对主密码；若确认无误，请从可信备份恢复。"
        }
        (ErrorCode::AuthenticationFailed, "wrong current master password or corrupted vault") => {
            "当前主密码不正确，或 Vault 已损坏。请核对当前主密码；若确认无误，请从可信备份恢复。"
        }
        (ErrorCode::AuthenticationFailed, "invalid wrapped vault key") => {
            "Vault 包装密钥无效，Vault 可能已损坏。请检查 Vault 文件或从可信备份恢复。"
        }
        (ErrorCode::AuthenticationFailed, "vault data is corrupted") => {
            "Vault 数据已损坏或未通过完整性校验。请从可信备份恢复。"
        }
        (
            ErrorCode::AuthenticationFailed,
            "the required SSH credential is not configured for this host; a human must configure it through the host wizard",
        ) => "此主机缺少所需的 SSH 凭据。请由用户通过主机向导配置 Vault SSH 密码或私钥后再连接。",
        (
            ErrorCode::AuthenticationFailed,
            "credential type does not match the host authentication mode",
        ) => "凭据类型与主机认证方式不匹配。请在主机向导中重新选择认证方式并配置对应凭据。",
        (
            ErrorCode::AuthenticationFailed,
            "the selected credential is not a Vault-managed OpenSSH private key",
        ) => "所选凭据不是 Vault 管理的 OpenSSH 私钥。请在主机向导中重新导入私钥。",
        (
            ErrorCode::AuthenticationFailed,
            "OpenSSH authentication failed. Remxo does not retry or request credentials from an agent.",
        ) => {
            "OpenSSH 认证失败，可能涉及账号、凭据或服务器策略。请按认证方式检查：密码及服务器密码登录设置；或私钥、私钥口令及服务器 authorized_keys 中的对应公钥。Remxo 未自动重试，也未向 Agent 索取凭据。"
        }
        (
            ErrorCode::HostKeyFailed,
            "OpenSSH host key verification failed. Remxo never disables host key checks; a human must verify the host key.",
        ) => {
            "OpenSSH 主机密钥验证失败。Remxo 不会关闭主机密钥检查；请由用户核对主机指纹和 known_hosts 后再连接，不要自动接受主机密钥。"
        }
        (
            ErrorCode::ApprovalRequired,
            "this operation requires one-time human approval; rerun the unchanged operation after approval",
        ) => {
            "此操作需要用户进行一次性人工批准。请由用户使用原审批 ID 审批；获批前不得自动批准或重试，获批后只能重新运行完全相同的操作，不得修改请求复用审批。"
        }
        (
            ErrorCode::SudoPasswordNotConfigured,
            "No sudo password is configured for this host. Ask a human to configure it in Remxo.",
        ) => {
            "此主机未配置 sudo 密码。请由用户运行 'remxo vault set-sudo <alias>' 配置独立的 sudo 密码，不要复用 SSH 密码。"
        }
        (ErrorCode::SudoNotPermitted, "the configured credential type is not valid for sudo") => {
            "已配置的凭据类型不能用于 sudo。请使用独立的 sudo 密码重新配置。"
        }
        (
            ErrorCode::SudoNotPermitted,
            "remote sudo was not permitted; check least-privilege sudoers, authentication, and requiretty policy. No password retry was attempted",
        ) => {
            "服务器不允许此次 sudo 操作。请检查最小权限 sudoers、认证和 requiretty 策略；Remxo 未重试密码。"
        }
        (
            ErrorCode::Timeout,
            "remote operation exceeded its timeout; no automatic retry was attempted",
        ) => "远程操作已超时，未自动重试。请先检查连接和远程状态，再决定是否重试。",
        (
            ErrorCode::ConnectionFailed,
            "local SSH was stopped; remote execution state is unknown and must be verified",
        ) => "本地 SSH 已停止；远程命令是否执行尚不确定。请先核对远程状态，不要盲目重试写操作。",
        (ErrorCode::ConnectionFailed, "broker connection timed out") => {
            "连接本地 Broker 超时。请运行 'remxo status' 检查 Broker 状态。"
        }
        (ErrorCode::OutputLimit, "raw command output exceeded the configured safety limit") => {
            "原始命令输出超过配置的安全上限。请缩小输出范围或调整 max_output。"
        }
        (ErrorCode::InvalidArgument, "alias is required") => "请填写主机别名。",
        (
            ErrorCode::InvalidConfig,
            "host aliases must be non-empty, non-numeric, and contain no whitespace",
        ) => "主机别名不能为空、不能全为数字，也不能包含空白字符。请修改别名。",
        (
            ErrorCode::InvalidArgument,
            "an OpenSSH alias or hostname is required before testing or saving",
        ) => "测试或保存前，请填写 OpenSSH 别名、主机名或 IP 地址。",
        (ErrorCode::InvalidArgument, "port must be an integer from 1 to 65535") => {
            "端口必须是 1 到 65535 之间的整数。"
        }
        (ErrorCode::InvalidArgument, "host number must be a positive integer") => {
            "主机编号必须是大于 0 的整数。"
        }
        (ErrorCode::InvalidConfig, "timeout_seconds and max_output must be greater than zero") => {
            "timeout_seconds 和 max_output 都必须大于 0，请修改配置。"
        }
        (
            ErrorCode::InvalidArgument,
            "selecting Vault SSH password requires a non-empty password entered through the hidden field",
        ) => "选择 Vault SSH 密码后，必须在隐藏字段中输入非空密码。",
        (
            ErrorCode::InvalidArgument,
            "selecting Vault private key requires a private key file path (not the .pub file)",
        ) => "选择 Vault 私钥后，必须填写私钥文件路径（不是 .pub 公钥文件）。",
        (
            ErrorCode::InvalidArgument,
            "choose Vault SSH password or Vault private key before importing credentials; no secret was saved",
        ) => "请先选择 Vault SSH 密码或 Vault 私钥认证，再导入凭据；尚未保存任何秘密。",
        (
            ErrorCode::InvalidArgument,
            "an SSH password is required for this authentication mode",
        ) => "当前认证方式需要 SSH 密码，请在隐藏输入框中填写。",
        (
            ErrorCode::InvalidArgument,
            "SSH password/private-key import is available only for SSH hosts, not Telnet",
        ) => "SSH 密码或私钥导入仅适用于 SSH 主机，不适用于 Telnet。",
        (ErrorCode::InvalidArgument, "invalid credential name or kind") => {
            "凭据名称或类型无效，请使用受支持的 SSH、sudo 或 Telnet 凭据类型。"
        }
        (ErrorCode::InvalidArgument, "master password must contain at least 12 bytes") => {
            "主密码必须至少包含 12 字节，请设置更长的主密码。"
        }
        (ErrorCode::InvalidArgument, "new master password must contain at least 12 bytes") => {
            "新主密码必须至少包含 12 字节，请设置更长的新主密码。"
        }
        (
            ErrorCode::InvalidConfig,
            "private key import accepts a regular file, not a symlink, directory, or special file",
        ) => "私钥导入只接受普通文件，不接受符号链接、目录或特殊文件。请更换私钥路径。",
        (ErrorCode::InvalidConfig, "private key exceeds the 1 MiB import limit") => {
            "私钥超过 1 MiB 导入上限，请确认选择的是私钥文件而不是其他文件。"
        }
        (
            ErrorCode::InvalidConfig,
            "private key must be a textual OpenSSH PEM file, not binary or non-UTF-8 data",
        ) => "私钥必须是文本格式的 OpenSSH PEM 文件，不能是二进制或非 UTF-8 数据。",
        (
            ErrorCode::InvalidConfig,
            "unrecognized private key format; expected an OpenSSH/RSA/EC/PKCS#8 PEM private key",
        ) => {
            "无法识别私钥格式。请选择 OpenSSH、RSA、EC 或 PKCS#8 PEM 私钥文件，而不是 .pub 公钥文件。"
        }
        (ErrorCode::InvalidConfig, "unsupported vault schema or cryptographic algorithm") => {
            "Vault schema 或加密算法不受支持。请使用兼容版本，或从可信备份恢复。"
        }
        (
            ErrorCode::InvalidConfig,
            "Remxo is not initialized. Run 'remxo init' to create a password and empty inventory before adding hosts",
        ) => "Remxo 尚未初始化。添加主机前，请运行 'remxo init' 设置主密码并创建空主机清单。",
        (
            ErrorCode::HostNotAllowed,
            "IP is not registered; ad-hoc targets are disabled by policy",
        ) => "该 IP 未登记，且策略禁止临时目标。请先添加主机，或使用已登记的别名、编号或 IP。",
        (ErrorCode::AgentUnavailable, "external SSH agent is unavailable") => {
            "外部 SSH Agent 不可用。请由用户启动并解锁 Agent 后再操作。"
        }
        (
            ErrorCode::AgentIdentityUnavailable,
            "external SSH agent is unavailable or has no usable socket; a human must unlock/configure it",
        ) => "外部 SSH Agent 不可用或没有可用 socket。请由用户启动、解锁并配置 Agent。",
        (
            ErrorCode::UnsupportedOperation,
            "vault-managed SSH authentication requires an active Broker and an unlocked Vault",
        ) => {
            "Vault 管理的 SSH 认证需要运行中的 Broker 和已解锁的 Vault。请启动 Broker 并由用户运行 'remxo unlock'。"
        }
        (
            ErrorCode::UnsupportedOperation,
            "Vault authentication requires interactive_authenticated with a Broker authentication context",
        ) => "Vault 认证需要 Broker 认证上下文和交互式认证流程，请通过受支持的 CLI/TUI 入口连接。",
        (
            ErrorCode::UnsupportedOperation,
            "requested authentication material is not valid for this host authentication mode",
        ) => "请求的认证材料不适用于此主机的认证方式。请检查并重新配置认证方式。",
        (
            ErrorCode::UnsupportedShell,
            "Vault-managed authentication currently requires POSIX shell",
        ) => "Vault 管理的认证目前要求 POSIX shell。请调整主机 shell 配置或改用受支持的认证方式。",
        (
            ErrorCode::UnsupportedShell,
            "connection testing currently requires a POSIX shell; no unsupported command was attempted",
        ) => "连接测试目前要求 POSIX shell，未执行不受支持的命令。请调整主机 shell 配置。",
        (
            ErrorCode::UnsupportedShell,
            "only POSIX shell non-interactive execution is implemented in this build",
        ) => "当前版本仅实现 POSIX shell 非交互执行，未尝试其他 shell。请调整主机 shell 配置。",
        (ErrorCode::UnsupportedShell, "--cwd currently requires POSIX shell") => {
            "--cwd 目前仅支持 POSIX shell。请改用 POSIX shell 或移除 --cwd。"
        }
        (
            ErrorCode::UnsupportedShell,
            "sudo injection currently requires POSIX shell and /bin/sh",
        ) => "sudo 注入目前仅支持 POSIX shell 和 /bin/sh，请检查主机 shell 配置。",
        (
            ErrorCode::InvalidArgument,
            "Telnet sends credentials and commands without encryption. Enable 'Acknowledge insecure Telnet' only if you accept that risk",
        ) => {
            "Telnet 不加密（INSECURE），凭据和命令会以明文传输。只有明确接受该风险时，才能启用“确认 Telnet 不加密风险”；建议改用 SSH。"
        }
        (
            ErrorCode::InsecureTransport,
            "Telnet is plaintext; adding it requires explicit --ack-insecure",
        ) => {
            "Telnet 使用明文传输（INSECURE，不安全）。如明确接受风险，添加主机时必须显式指定 --ack-insecure；建议改用 SSH。"
        }
        (
            ErrorCode::InsecureTransport,
            "Telnet transmits credentials, commands, and output without transport encryption; explicit insecure_acknowledged=true is required",
        ) => {
            "Telnet 不加密（INSECURE），凭据、命令和输出都会明文传输。必须显式设置 insecure_acknowledged=true；建议改用 SSH。"
        }
        (ErrorCode::InsecureTransport, "Telnet transfer is insecure and was not acknowledged") => {
            "Telnet 文件传输不安全且尚未确认风险。请改用 SSH；只有明确接受明文风险时才可确认 Telnet。"
        }
        (
            ErrorCode::UnsupportedOperation,
            "Telnet has no encrypted connection test in this version. Its plaintext automation is not implemented.",
        ) => "此版本没有加密的 Telnet 连接测试，也未实现明文自动化。请改用 SSH。",
        (
            ErrorCode::UnsupportedOperation,
            "Telnet command framing is not implemented in this build; the host remains explicitly INSECURE",
        ) => "此版本未实现 Telnet 命令分帧；该主机仍是明确的不安全（INSECURE）传输。请改用 SSH。",
        (
            ErrorCode::UnsupportedOperation,
            "Telnet interactive support is not implemented in this build",
        ) => "此版本未实现 Telnet 交互支持。Telnet 不加密，请改用 SSH。",
        (ErrorCode::UnsupportedOperation, "file transfer is not supported over Telnet") => {
            "不支持通过 Telnet 传输文件，请改用 SSH。"
        }
        _ => return dynamic_chinese(code, message),
    };
    Some(fixed.to_string())
}

fn dynamic_chinese(code: ErrorCode, message: &str) -> Option<String> {
    if matches!(code, ErrorCode::InvalidArgument | ErrorCode::InvalidConfig) {
        if let Some(alias) = host_alias(message, ": numbers and ports must be greater than zero") {
            return Some(format!(
                "主机 '{alias}' 的编号和端口必须大于 0，请修改后重试。"
            ));
        }
        if let Some(alias) = host_alias(message, ": ssh_alias or hostname is required") {
            return Some(format!(
                "主机 '{alias}' 缺少连接地址，请填写 OpenSSH 别名、主机名或 IP 地址。"
            ));
        }
        if let Some(alias) = host_alias(message, ": telnet requires hostname") {
            return Some(format!(
                "主机 '{alias}' 使用 Telnet 时必须填写主机名或 IP 地址。"
            ));
        }
        if let Some(alias) = host_alias(message, ": invalid connection field") {
            return Some(format!(
                "主机 '{alias}' 的连接字段无效：地址、别名和用户名不能为空、以 '-' 开头，或包含空白/控制字符。"
            ));
        }
        if let Some(details) = message.strip_prefix("unsupported config schema version: ") {
            return Some(format!(
                "配置 schema 版本 '{details}' 不受支持，请使用兼容版本或迁移配置。"
            ));
        }
        if let Some(details) = message.strip_prefix("invalid TOML configuration: ") {
            return Some(format!(
                "TOML 配置无效，请修正语法和字段后重试。已脱敏详情：{details}"
            ));
        }
        if let Some(details) = message.strip_prefix("invalid vault format: ") {
            return Some(format!(
                "Vault 文件格式无效，请检查文件或从可信备份恢复。已脱敏详情：{details}"
            ));
        }
        if let Some(details) = message.strip_prefix("invalid decrypted vault data: ") {
            return Some(format!(
                "解密后的 Vault 数据无效，请从可信备份恢复。已脱敏详情：{details}"
            ));
        }
    }

    match code {
        ErrorCode::InvalidConfig => {
            if let Some(number) = message.strip_prefix("duplicate host number: ")
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Some(format!("主机编号 {number} 已被使用，请改用其他编号。"));
            }
            if let Some(details) =
                message.strip_prefix("cannot inspect the specified private key file: ")
            {
                return Some(format!(
                    "无法检查指定私钥文件，请确认路径正确且文件可访问。已脱敏详情：{details}"
                ));
            }
            if let Some(details) = message.strip_prefix("cannot resolve private key location: ") {
                return Some(format!(
                    "无法解析私钥位置，请检查路径和访问权限。已脱敏详情：{details}"
                ));
            }
            if let Some(path) =
                message.strip_prefix("private file has group/other permissions; expected 0600: ")
            {
                return Some(format!(
                    "私有文件的组/其他用户权限过宽，请将权限设为 0600：{path}"
                ));
            }
        }
        ErrorCode::InvalidArgument => {
            if message == "invalid remote path" {
                return Some("远程路径无效，请检查路径格式并移除 NUL 或换行符。".to_string());
            }
        }
        ErrorCode::AlreadyExists => {
            if let Some(alias) = message.strip_prefix("host alias already exists: ") {
                return Some(format!("主机别名 '{alias}' 已存在，请使用其他别名。"));
            }
            if message == "vault already exists" {
                return Some("Vault 已存在，未覆盖原文件。".to_string());
            }
        }
        ErrorCode::HostNotFound => {
            if let Some(target) = message.strip_prefix("host not found: ") {
                return Some(format!(
                    "未找到主机 '{target}'。请运行 'remxo hosts' 查看已登记主机，并核对别名、编号或地址。"
                ));
            }
        }
        ErrorCode::SudoPasswordNotConfigured => {
            if message.starts_with("credential is not configured: ") {
                return Some(
                    "此主机缺少所需的 sudo 凭据。请由用户运行 'remxo vault set-sudo <alias>' 配置独立的 sudo 密码。"
                        .to_string(),
                );
            }
        }
        ErrorCode::ConnectionFailed => {
            if let Some(details) = message.strip_prefix("OpenSSH connection failed: ") {
                return Some(format!(
                    "OpenSSH 连接失败。请检查网络、地址、端口和 SSH 服务。以下为已脱敏的原始诊断（未保证逐句翻译）：{details}"
                ));
            }
        }
        ErrorCode::IoError => {
            if let Some(details) = message.strip_prefix("resolve private key import path: ") {
                return Some(format!(
                    "无法解析私钥导入路径，请检查路径和当前目录。已脱敏详情：{details}"
                ));
            }
            if let Some(details) = message.strip_prefix("open the specified private key: ") {
                return Some(format!(
                    "无法打开指定私钥，请检查路径和读取权限。已脱敏详情：{details}"
                ));
            }
            if let Some(details) = message.strip_prefix("read private key into memory: ") {
                return Some(format!(
                    "读取私钥失败，请检查文件和读取权限。已脱敏详情：{details}"
                ));
            }
        }
        ErrorCode::UnsupportedShell
            if message.starts_with(
                "non-interactive command composition is implemented only for POSIX shell, not ",
            ) =>
        {
            return Some(
                "当前仅支持 POSIX shell 的非交互命令组合。请调整主机 shell 配置；未套用其他 shell 的引号规则。"
                    .to_string(),
            );
        }
        ErrorCode::AuthenticationFailed if message.starts_with("OpenSSH authentication failed") => {
            let details = message
                .strip_prefix(
                    "OpenSSH authentication failed. Remxo does not retry or request credentials from an agent. OpenSSH diagnostic: ",
                )
                .unwrap_or(message);
            return Some(format!(
                "OpenSSH 认证失败，可能涉及账号、凭据、私钥读取、私钥口令或服务器授权。请检查用户名和私钥/口令，并确认服务器 authorized_keys 中有对应公钥。Remxo 未自动重试或回退到其他身份。以下为已脱敏的原始诊断（未保证逐句翻译）：{details}"
            ));
        }
        _ => {}
    }
    None
}

fn host_alias<'a>(message: &'a str, suffix: &str) -> Option<&'a str> {
    message.strip_prefix("host ")?.strip_suffix(suffix)
}

fn chinese_category(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::VaultLocked => "Vault 已锁定；请由用户运行 'remxo unlock'",
        ErrorCode::AgentUnavailable | ErrorCode::AgentIdentityUnavailable => {
            "外部 SSH Agent 不可用或没有可用身份"
        }
        ErrorCode::HostNotFound => "未找到主机",
        ErrorCode::HostNotAllowed => "目标主机未被策略允许",
        ErrorCode::PolicyDenied => "操作被策略拒绝",
        ErrorCode::ApprovalRequired => "需要用户人工批准；不得自动批准或在批准前重试",
        ErrorCode::AuthenticationFailed => "认证失败",
        ErrorCode::HostKeyFailed => "主机密钥验证失败；请人工核验，不要关闭检查",
        ErrorCode::ConnectionFailed => "连接失败",
        ErrorCode::Timeout => "操作超时",
        ErrorCode::OutputLimit => "输出超过安全限制",
        ErrorCode::UnsupportedPlatform => "当前平台不受支持",
        ErrorCode::UnsupportedShell => "当前 shell 不受支持；请检查是否支持 POSIX shell",
        ErrorCode::UnsupportedOperation => "当前操作不受支持",
        ErrorCode::SudoPasswordNotConfigured => {
            "未配置 sudo 密码；请由用户使用 'remxo vault set-sudo <alias>' 配置"
        }
        ErrorCode::SudoNotPermitted => "不允许执行 sudo",
        ErrorCode::InsecureTransport => "不安全的明文传输（INSECURE）；请改用 SSH",
        ErrorCode::InvalidConfig => "配置无效",
        ErrorCode::InvalidArgument => "参数无效",
        ErrorCode::AlreadyExists => "目标已存在",
        ErrorCode::NotFound => "目标不存在",
        ErrorCode::IoError => "输入/输出操作失败",
        ErrorCode::InternalError => "内部错误",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn localized(code: ErrorCode, message: &str) -> String {
        error_message(&AppError::new(code, message), UiLanguage::ZhCn)
    }

    #[test]
    fn english_is_exactly_the_sanitized_original() {
        let error = AppError::new(
            ErrorCode::ConnectionFailed,
            "OpenSSH connection failed: password=test-only-english-secret\n\u{1b}[2J",
        );
        let expected = crate::redact::sanitize(&error.message);
        let actual = error_message(&error, UiLanguage::En);
        assert_eq!(actual, expected);
        assert!(!actual.contains("test-only-english-secret"));
        assert!(actual.contains("[REDACTED]"));
        assert!(actual.contains("\\x1b[2J"));
    }

    #[test]
    fn common_validation_messages_are_actionable_chinese() {
        let cases = [
            (ErrorCode::InvalidArgument, "alias is required", "主机别名"),
            (
                ErrorCode::InvalidArgument,
                "an OpenSSH alias or hostname is required before testing or saving",
                "IP 地址",
            ),
            (
                ErrorCode::InvalidArgument,
                "port must be an integer from 1 to 65535",
                "1 到 65535",
            ),
            (
                ErrorCode::InvalidArgument,
                "host number must be a positive integer",
                "大于 0",
            ),
            (
                ErrorCode::InvalidArgument,
                "selecting Vault SSH password requires a non-empty password entered through the hidden field",
                "隐藏字段",
            ),
            (
                ErrorCode::InvalidArgument,
                "selecting Vault private key requires a private key file path (not the .pub file)",
                "私钥文件路径",
            ),
        ];
        for (code, message, expected) in cases {
            let output = localized(code, message);
            assert!(output.contains(expected), "unexpected output: {output}");
            assert!(!output.contains(message));
        }
    }

    #[test]
    fn dynamic_host_validation_keeps_only_the_relevant_context() {
        let output = localized(
            ErrorCode::InvalidConfig,
            "host prod-01: numbers and ports must be greater than zero",
        );
        assert_eq!(
            output,
            "主机 'prod-01' 的编号和端口必须大于 0，请修改后重试。"
        );

        let output = localized(ErrorCode::InvalidConfig, "duplicate host number: 7");
        assert!(output.contains("编号 7"));

        let output = localized(ErrorCode::HostNotFound, "host not found: prod-01");
        assert!(output.contains("remxo hosts"));
        assert!(output.contains("prod-01"));
    }

    #[test]
    fn vault_and_credential_messages_cover_safe_next_steps() {
        let locked = localized(
            ErrorCode::VaultLocked,
            "Remxo is locked. A human must run: remxo unlock",
        );
        assert!(locked.contains("remxo unlock"));
        assert!(locked.contains("用户"));

        let wrong = localized(
            ErrorCode::AuthenticationFailed,
            "wrong master password or corrupted vault",
        );
        assert!(wrong.contains("主密码不正确"));
        assert!(wrong.contains("或 Vault 已损坏"));
        assert!(wrong.contains("可信备份"));

        let missing = localized(
            ErrorCode::AuthenticationFailed,
            "the required SSH credential is not configured for this host; a human must configure it through the host wizard",
        );
        assert!(missing.contains("SSH 凭据"));
        assert!(missing.contains("主机向导"));

        let sudo = localized(
            ErrorCode::SudoPasswordNotConfigured,
            "credential is not configured: prod:sudo",
        );
        assert!(sudo.contains("set-sudo"));
        assert!(sudo.contains("独立"));
    }

    #[test]
    fn private_key_errors_do_not_echo_key_material() {
        let format = localized(
            ErrorCode::InvalidConfig,
            "unrecognized private key format; expected an OpenSSH/RSA/EC/PKCS#8 PEM private key",
        );
        assert!(format.contains("OpenSSH"));
        assert!(format.contains("不是 .pub"));

        let error = AppError::new(
            ErrorCode::InvalidConfig,
            "cannot inspect the specified private key file: -----BEGIN OPENSSH PRIVATE KEY-----\ntest-only-key-material\n-----END OPENSSH PRIVATE KEY-----",
        );
        let output = error_message(&error, UiLanguage::ZhCn);
        assert!(!output.contains("test-only-key-material"));
        assert!(output.contains("[REDACTED PRIVATE KEY]"));
        assert!(output.contains("已脱敏详情"));
    }

    #[test]
    fn ssh_failures_preserve_security_guidance_without_certainty() {
        let host_key = localized(
            ErrorCode::HostKeyFailed,
            "OpenSSH host key verification failed. Remxo never disables host key checks; a human must verify the host key.",
        );
        assert!(host_key.contains("不会关闭主机密钥检查"));
        assert!(host_key.contains("known_hosts"));
        assert!(host_key.contains("不要自动接受"));

        let authentication = localized(
            ErrorCode::AuthenticationFailed,
            "OpenSSH authentication failed. Remxo does not retry or request credentials from an agent.",
        );
        assert!(authentication.contains("密码"));
        assert!(authentication.contains("私钥口令"));
        assert!(authentication.contains("authorized_keys"));
        assert!(authentication.contains("可能涉及"));
        assert!(authentication.contains("未自动重试"));

        let connection = localized(
            ErrorCode::ConnectionFailed,
            "OpenSSH connection failed: ssh: connect to host example.invalid port 22: timed out",
        );
        assert!(connection.contains("检查网络、地址、端口"));
        assert!(connection.contains("未保证逐句翻译"));
        assert!(connection.contains("example.invalid"));
    }

    #[test]
    fn approval_shell_and_telnet_keep_fail_closed_instructions() {
        let approval = localized(
            ErrorCode::ApprovalRequired,
            "this operation requires one-time human approval; rerun the unchanged operation after approval",
        );
        assert!(approval.contains("一次性人工批准"));
        assert!(approval.contains("不得自动批准或重试"));
        assert!(approval.contains("完全相同的操作"));
        assert!(approval.contains("不得修改请求复用审批"));

        let shell = localized(
            ErrorCode::UnsupportedShell,
            "non-interactive command composition is implemented only for POSIX shell, not Powershell",
        );
        assert!(shell.contains("POSIX shell"));
        assert!(!shell.contains("Powershell"));

        let telnet = localized(
            ErrorCode::InsecureTransport,
            "Telnet is plaintext; adding it requires explicit --ack-insecure",
        );
        assert!(telnet.contains("INSECURE"));
        assert!(telnet.contains("明文"));
        assert!(telnet.contains("--ack-insecure"));
        assert!(telnet.contains("改用 SSH"));
    }

    #[test]
    fn unknown_messages_use_a_safe_category_and_sanitized_original() {
        let output = localized(
            ErrorCode::ConnectionFailed,
            "future transport detail: password=test-only-chinese-secret",
        );
        assert!(output.starts_with("连接失败："));
        assert!(!output.contains("test-only-chinese-secret"));
        assert!(output.contains("password=[REDACTED]"));

        let output = localized(ErrorCode::PolicyDenied, "");
        assert_eq!(output, "操作被策略拒绝");
    }

    #[test]
    fn localized_auth_failure_preserves_publickey_hint_and_diagnostic() {
        let error = AppError::new(
            ErrorCode::AuthenticationFailed,
            "OpenSSH authentication failed. Remxo does not retry or request credentials from an agent. OpenSSH diagnostic: ubuntu@example: Permission denied (publickey).",
        );
        let localized = error_message(&error, crate::config::UiLanguage::ZhCn);
        assert!(localized.contains("authorized_keys"));
        assert!(localized.contains("Permission denied (publickey)"));
    }

    #[test]
    fn near_match_does_not_echo_a_test_secret_in_chinese() {
        let error = AppError::new(
            ErrorCode::AuthenticationFailed,
            "wrong master password or corrupted vault; password=test-only-near-match-secret",
        );
        for language in [UiLanguage::En, UiLanguage::ZhCn] {
            let output = error_message(&error, language);
            assert!(!output.contains("test-only-near-match-secret"));
            assert!(output.contains("[REDACTED]"));
        }
        assert_eq!(error.code, ErrorCode::AuthenticationFailed);
        assert_eq!(
            error.message,
            "wrong master password or corrupted vault; password=test-only-near-match-secret"
        );
    }
}
