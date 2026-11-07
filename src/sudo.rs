use crate::config::Host;
use crate::error::Result;
use crate::vault::VaultSession;
use zeroize::Zeroizing;

pub fn password_for(
    host_alias: &str,
    host: &Host,
    vault: Option<&VaultSession>,
) -> Result<Zeroizing<String>> {
    let vault = vault.ok_or_else(crate::vault::vault_locked)?;
    let name = host.sudo_credential.as_deref().unwrap_or(host_alias);
    let value = vault.credential_with_kind(name, "sudo-password").map_err(|error| {
        if error.code == crate::error::ErrorCode::SudoPasswordNotConfigured {
            crate::error::AppError::new(
                crate::error::ErrorCode::SudoPasswordNotConfigured,
                "No sudo password is configured for this host. Ask a human to configure it in Remxo.",
            )
        } else {
            error
        }
    })?;
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Credential;
    use std::collections::BTreeMap;

    #[test]
    fn sudo_requires_a_specific_vault_credential_type() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("vault.json");
        let mut vault = VaultSession::initialize(&path, "long test master password")
            .unwrap_or_else(|e| panic!("init: {e}"));
        let host = Host::default();
        assert_eq!(
            password_for("prod", &host, Some(&vault))
                .err()
                .map(|e| e.code),
            Some(crate::error::ErrorCode::VaultLocked)
        );
        vault
            .unlock("long test master password")
            .unwrap_or_else(|e| panic!("unlock: {e}"));
        assert_eq!(
            password_for("prod", &host, Some(&vault))
                .err()
                .map(|e| e.code),
            Some(crate::error::ErrorCode::SudoPasswordNotConfigured)
        );
        vault
            .put_record(
                "prod",
                Credential {
                    kind: "ssh-password".into(),
                    value: "must-not-be-reused".into(),
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|e| panic!("record: {e}"));
        assert_eq!(
            password_for("prod", &host, Some(&vault))
                .err()
                .map(|e| e.code),
            Some(crate::error::ErrorCode::SudoNotPermitted)
        );
    }
}
