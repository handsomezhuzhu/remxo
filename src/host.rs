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
}
