use crate::redact::sanitize;
use zeroize::Zeroize;

#[derive(Debug, Clone, Default)]
pub struct ProcessedOutput {
    pub text: String,
    pub truncated: bool,
    pub raw_bytes: usize,
}

pub fn process(raw: &[u8], limit: usize, reader_truncated: bool) -> ProcessedOutput {
    process_with_secrets(raw, limit, reader_truncated, &[])
}

pub fn process_with_secrets(
    raw: &[u8],
    limit: usize,
    reader_truncated: bool,
    secrets: &[&str],
) -> ProcessedOutput {
    let raw_bytes = raw.len();
    let mut decoded = String::from_utf8_lossy(raw).into_owned();
    for secret in secrets {
        if !secret.is_empty() {
            decoded = decoded.replace(secret, "[REDACTED SUDO PASSWORD]");
        }
    }
    let sanitized = sanitize(&decoded);
    decoded.zeroize();
    let mut end = sanitized.len().min(limit);
    while end > 0 && !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = reader_truncated || end < sanitized.len();
    ProcessedOutput {
        text: sanitized[..end].to_string(),
        truncated,
        raw_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_occurs_before_final_truncation() {
        let raw = b"password=not-visible-after-redaction OK";
        let processed = process(raw, 24, false);
        assert!(!processed.text.contains("not-visible"));
        assert!(processed.text.ends_with("OK") || processed.truncated);
    }

    #[test]
    fn truncation_is_utf8_safe_and_bounded() {
        let processed = process("你好世界".as_bytes(), 5, false);
        assert!(processed.text.len() <= 5);
        assert!(processed.truncated);
        assert_eq!(processed.text, "你");
    }

    #[test]
    fn explicitly_injected_secrets_are_scrubbed_even_without_a_key_name() {
        let processed = process_with_secrets(
            b"echoed: test-secret-value",
            100,
            false,
            &["test-secret-value"],
        );
        assert!(!processed.text.contains("test-secret-value"));
        assert!(processed.text.contains("REDACTED SUDO PASSWORD"));
    }
}
