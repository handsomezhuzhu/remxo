use regex::Regex;
use std::sync::LazyLock;

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----")
        .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});
static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?P<prefix>authorization\s*[:=]\s*)(?P<kind>bearer|basic)\s+[^\s,;\x22]+")
        .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});
static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?ix)(?P<prefix>[\\x22\\x27]?(?:password|passwd|pwd|api[_-]?key|access[_-]?token|secret|token)[\\x22\\x27]?\\s*[:=]\\s*[\\x22\\x27]?)(?P<value>[^\\s,\\x22\\x27;}\\]]+)")
        .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});
static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:)(?P<password>[^\s/@]+)(?P<suffix>@)",
    )
    .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});
static COMMON_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b")
        .unwrap_or_else(|_| Regex::new("a^").unwrap_or_else(|_| unreachable!()))
});

pub fn redact(input: &str) -> String {
    let value = PRIVATE_KEY.replace_all(input, "[REDACTED PRIVATE KEY]");
    let value = AUTHORIZATION.replace_all(&value, "${prefix}${kind} [REDACTED]");
    let value = KEY_VALUE.replace_all(&value, "${prefix}[REDACTED]");
    let value = URL_PASSWORD.replace_all(&value, "${prefix}[REDACTED]${suffix}");
    COMMON_TOKEN
        .replace_all(&value, "[REDACTED TOKEN]")
        .into_owned()
}

pub fn escape_controls(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '\n' | '\t' => result.push(character),
            '\r' => result.push_str("\\r"),
            '\u{1b}' => result.push_str("\\x1b"),
            value if value.is_control() => {
                result.push_str(&format!("\\u{{{:x}}}", value as u32));
            }
            value => result.push(value),
        }
    }
    result
}

pub fn sanitize(input: &str) -> String {
    escape_controls(&redact(input))
}

/// Render untrusted external command output for humans without leaking binary
/// noise or pretending invalid bytes are meaningful text.
pub fn external_error_detail(bytes: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    let mut cleaned = String::with_capacity(lossy.len());
    let mut in_replacement = false;
    for character in lossy.chars() {
        if character == '\u{FFFD}' {
            if !in_replacement {
                cleaned.push('?');
                in_replacement = true;
            }
        } else {
            cleaned.push(character);
            in_replacement = false;
        }
    }
    escape_controls(&cleaned).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_secrets_and_ansi() {
        let input = "Authorization: Bearer abcdef\npassword=super-secret\n\u{1b}[2J";
        let output = sanitize(input);
        assert!(!output.contains("abcdef"));
        assert!(!output.contains("super-secret"));
        assert!(output.starts_with("Authorization: Bearer [REDACTED]"));
        assert!(output.contains("\\x1b[2J"));
    }

    #[test]
    fn strips_json_secrets_and_password_urls() {
        let input = r#"{"password":"json-secret"} postgres://user:url-secret@example/db"#;
        let output = sanitize(input);
        assert!(!output.contains("json-secret"));
        assert!(!output.contains("url-secret"));
        assert!(output.contains("password"));
    }

    #[test]
    fn external_error_detail_replaces_invalid_utf8_without_octal_noise() {
        // GBK bytes for a Chinese error message; they are not valid UTF-8.
        let detail = external_error_detail(&[0xd5, 0xe2, 0x21, 0x0a]);
        assert_eq!(detail, "?!");
        assert!(!detail.contains("\\325"));
    }

    #[test]
    fn strips_private_keys() {
        let input =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----";
        assert!(!sanitize(input).contains("abc"));
    }
}
