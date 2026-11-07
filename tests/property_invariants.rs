use std::net::Ipv4Addr;

use proptest::collection::vec;
use proptest::prelude::*;
use remxo::config::{ApprovalMode, Config, Host, ShellKind, resolve_target};
use remxo::output::process;
use remxo::redact::sanitize;
use remxo::shell::command_script;

fn unicode_argument() -> impl Strategy<Value = String> {
    vec(
        any::<char>().prop_filter("NUL is not a valid command argument", |c| *c != '\0'),
        1..=20,
    )
    .prop_map(|characters| characters.into_iter().collect())
}

fn secret() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,48}"
}

fn escaped_control(control: char) -> String {
    match control {
        '\n' | '\t' => control.to_string(),
        '\r' => "\\r".to_string(),
        '\u{1b}' => "\\x1b".to_string(),
        value => format!("\\u{{{:x}}}", value as u32),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn posix_command_arguments_round_trip_without_nul(
        arguments in vec(unicode_argument(), 2..=7),
    ) {
        let script = command_script(&arguments, ShellKind::Posix)
            .unwrap_or_else(|error| panic!("command construction failed: {error}"));
        let split = shell_words::split(&script)
            .unwrap_or_else(|error| panic!("constructed command did not parse: {error}"));
        prop_assert_eq!(split, arguments);
    }

    #[test]
    fn single_unicode_argument_remains_an_explicit_raw_script(argument in unicode_argument()) {
        let script = command_script(std::slice::from_ref(&argument), ShellKind::Posix)
            .unwrap_or_else(|error| panic!("command construction failed: {error}"));
        prop_assert_eq!(script, argument);
    }

    #[test]
    fn processed_output_is_bounded_utf8_without_unsafe_controls(
        raw in vec(any::<u8>(), 0..=2048),
        limit in 0..257usize,
        reader_truncated in any::<bool>(),
    ) {
        let processed = process(&raw, limit, reader_truncated);
        prop_assert!(processed.text.len() <= limit);
        prop_assert!(processed.text.chars().all(|character| {
            !character.is_control() || matches!(character, '\n' | '\t')
        }), "processed output retained an unsafe control character");
        prop_assert_eq!(processed.raw_bytes, raw.len());
    }

    #[test]
    fn explicit_secret_patterns_are_redacted_and_controls_escaped(
        json_secret in secret(),
        bearer_secret in secret(),
        url_secret in secret(),
        control in any::<char>().prop_filter("expected a control character", |c| c.is_control()),
    ) {
        let escaped = escaped_control(control);

        // Exact output comparisons also prove that one-character secrets do not remain
        // in their sensitive positions; unrelated key names may contain the same character.
        let json = sanitize(&format!(
            r#"{{"password":"{json_secret}"}}{control}"#
        ));
        prop_assert_eq!(
            json,
            format!(r#"{{"password":"[REDACTED]"}}{escaped}"#)
        );

        let authorization = sanitize(&format!(
            "Authorization: Bearer {bearer_secret} {control}"
        ));
        prop_assert_eq!(
            authorization,
            format!("Authorization: Bearer [REDACTED] {escaped}")
        );

        let url = sanitize(&format!(
            "https://user:{url_secret}@example.invalid/{control}"
        ));
        prop_assert_eq!(
            url,
            format!("https://user:[REDACTED]@example.invalid/{escaped}")
        );
    }
}

fn host(number: Option<u32>, address: Ipv4Addr, approval: ApprovalMode) -> Host {
    Host {
        number,
        hostname: Some(address.to_string()),
        approval,
        ..Host::default()
    }
}

fn resolved_alias(config: &Config, target: &str) -> String {
    resolve_target(config, target)
        .map(|resolved| resolved.alias)
        .unwrap_or_else(|error| panic!("failed to resolve {target}: {error}"))
}

#[test]
fn target_resolution_uses_exact_alias_number_then_registered_ipv4() {
    let mut config = Config::default();
    // Registered addresses must win even when ad-hoc IP targets are permitted.
    config.settings.allow_ad_hoc = true;
    config.hosts.insert(
        "alias-target".to_string(),
        host(Some(7), Ipv4Addr::new(192, 0, 2, 7), ApprovalMode::Never),
    );
    config.hosts.insert(
        "number-target".to_string(),
        host(Some(8), Ipv4Addr::new(192, 0, 2, 8), ApprovalMode::Writes),
    );
    config.hosts.insert(
        "ip-target".to_string(),
        host(Some(9), Ipv4Addr::new(192, 0, 2, 9), ApprovalMode::Always),
    );
    config
        .validate()
        .unwrap_or_else(|error| panic!("invalid test configuration: {error}"));

    assert_eq!(resolved_alias(&config, "alias-target"), "alias-target");
    assert_eq!(resolved_alias(&config, "8"), "number-target");
    assert_eq!(resolved_alias(&config, "192.0.2.9"), "ip-target");
    assert!(resolve_target(&config, "missing-target").is_err());
}
