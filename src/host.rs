use crate::config::{AppPaths, Config, Host};
use crate::error::{AppError, ErrorCode, Result};

pub fn check_can_add(paths: &AppPaths, alias: &str, host: &Host) -> Result<()> {
    if !paths.config.exists() {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "Remxo is not initialized. Run 'remxo init' to create a password and empty inventory before adding hosts",
        ));
    }
    let config = Config::load(&paths.config)?;
    host.validate(alias)?;
    if config.hosts.contains_key(alias) {
        return Err(AppError::new(
            ErrorCode::AlreadyExists,
            format!("host alias already exists: {alias}"),
        ));
    }
    Ok(())
}

/// Shared registration for CLI and interactive wizards. Secrets never enter a Host.
pub fn add_host(paths: &AppPaths, alias: &str, host: Host) -> Result<()> {
    check_can_add(paths, alias, &host)?;
    let mut config = Config::load(&paths.config)?;
    config.hosts.insert(alias.to_string(), host);
    config.save(&paths.config)
}

pub fn check_can_edit(paths: &AppPaths, alias: &str, expected: &Host, host: &Host) -> Result<()> {
    if !paths.config.exists() {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "Remxo is not initialized. Run 'remxo init' before editing hosts",
        ));
    }
    host.validate(alias)?;
    let config = Config::load(&paths.config)?;
    check_expected_host(&config, alias, expected)
}

fn check_expected_host(config: &Config, alias: &str, expected: &Host) -> Result<()> {
    let current = config.hosts.get(alias).ok_or_else(|| {
        AppError::new(
            ErrorCode::NotFound,
            format!("host '{alias}' no longer exists; reload the inventory before editing"),
        )
    })?;
    if current != expected {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            format!(
                "host '{alias}' changed while it was being edited; review the current configuration and retry"
            ),
        ));
    }
    Ok(())
}

/// Replace an existing Host while preserving the rest of the inventory.
/// The caller supplies the version it edited so stale forms cannot silently
/// overwrite changes made after the form was opened.
pub fn edit_host(paths: &AppPaths, alias: &str, expected: &Host, host: Host) -> Result<()> {
    check_can_edit(paths, alias, expected, &host)?;
    let mut config = Config::load(&paths.config)?;
    check_expected_host(&config, alias, expected)?;
    config.hosts.insert(alias.to_string(), host);
    config.save(&paths.config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_reuses_validation_and_preserves_inventory() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        Config::initialize(&paths.config).unwrap_or_else(|error| panic!("config: {error}"));
        let host = Host {
            ssh_alias: Some("production".into()),
            hostname: Some("192.0.2.1".into()),
            number: Some(2),
            ..Host::default()
        };
        add_host(&paths, "prod", host.clone()).unwrap_or_else(|error| panic!("add: {error}"));
        let before = std::fs::read_to_string(&paths.config).unwrap_or_default();
        let duplicate = add_host(&paths, "prod", host).unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::AlreadyExists);
        let after = std::fs::read_to_string(&paths.config).unwrap_or_default();
        assert_eq!(before, after);
    }

    #[test]
    fn editing_replaces_only_the_expected_host_and_rejects_stale_forms() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"));
        Config::initialize(&paths.config).unwrap_or_else(|error| panic!("config: {error}"));
        let original = Host {
            hostname: Some("192.0.2.10".into()),
            username: Some("ubuntu".into()),
            port: 22,
            ..Host::default()
        };
        add_host(&paths, "prod", original.clone()).unwrap_or_else(|error| panic!("add: {error}"));
        add_host(
            &paths,
            "other",
            Host {
                hostname: Some("192.0.2.20".into()),
                ..Host::default()
            },
        )
        .unwrap_or_else(|error| panic!("add other: {error}"));
        let updated = Host {
            hostname: Some("192.0.2.11".into()),
            username: Some("ubuntu".into()),
            port: 2222,
            ..original.clone()
        };
        edit_host(&paths, "prod", &original, updated.clone())
            .unwrap_or_else(|error| panic!("edit: {error}"));
        let config = Config::load(&paths.config).unwrap_or_else(|error| panic!("load: {error}"));
        assert_eq!(config.hosts.get("prod"), Some(&updated));
        assert_eq!(
            config
                .hosts
                .get("other")
                .and_then(|host| host.hostname.as_deref()),
            Some("192.0.2.20")
        );

        let stale = edit_host(&paths, "prod", &original, original.clone()).unwrap_err();
        assert_eq!(stale.code, ErrorCode::InvalidConfig);
        let missing = edit_host(&paths, "missing", &original.clone(), original).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
    }
}
