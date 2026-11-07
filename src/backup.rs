use crate::config::Config;
use crate::error::{AppError, ErrorCode, Result};
use crate::store::{atomic_write, create_new, require_private_file};
use crate::vault::{KdfParameters, SealedData, VaultFile, derive_kek, open, seal};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const BACKUP_CONTEXT: &[u8] = b"remxo:rxb:v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupPayload {
    schema_version: u32,
    created_at: String,
    config_toml: String,
    vault: VaultFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    format: String,
    version: u32,
    kdf: KdfParameters,
    payload: SealedData,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupMetadata {
    pub schema_version: u32,
    pub created_at: String,
    pub hosts: usize,
    pub path: PathBuf,
}

pub fn create(
    config_path: &Path,
    vault_path: &Path,
    destination: &Path,
    password: &str,
) -> Result<()> {
    if password.len() < 12 {
        return Err(AppError::invalid_argument(
            "backup password must contain at least 12 bytes",
        ));
    }
    let config_toml = std::fs::read_to_string(config_path)
        .map_err(|e| AppError::io("read config for backup", e))?;
    let config: Config = toml::from_str(&config_toml).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("cannot back up invalid config: {e}"),
        )
    })?;
    config.validate()?;
    let vault: VaultFile = serde_json::from_slice(
        &std::fs::read(vault_path).map_err(|e| AppError::io("read vault for backup", e))?,
    )
    .map_err(|e| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("cannot back up invalid vault: {e}"),
        )
    })?;
    let payload = BackupPayload {
        schema_version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        config_toml,
        vault,
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|e| AppError::internal(format!("serialize backup: {e}")))?,
    );
    let kdf = KdfParameters::generate();
    let key = derive_kek(password, &kdf)?;
    let file = BackupFile {
        format: "remxo-encrypted-backup".to_string(),
        version: 1,
        payload: seal(&key, &plaintext, BACKUP_CONTEXT)?,
        kdf,
    };
    let mut bytes = b"RXB1\n".to_vec();
    bytes.extend(
        serde_json::to_vec_pretty(&file)
            .map_err(|e| AppError::internal(format!("serialize encrypted backup: {e}")))?,
    );
    create_new(destination, &bytes)
}

pub fn verify(path: &Path, password: &str) -> Result<BackupMetadata> {
    let payload = decrypt(path, password)?;
    let config: Config = toml::from_str(&payload.config_toml).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("backup contains invalid config: {e}"),
        )
    })?;
    config.validate()?;
    if payload.schema_version != 1 || payload.vault.version != 1 {
        return Err(AppError::invalid_argument("unsupported backup schema"));
    }
    Ok(BackupMetadata {
        schema_version: payload.schema_version,
        created_at: payload.created_at,
        hosts: config.hosts.len(),
        path: path.to_path_buf(),
    })
}

pub fn restore(
    source: &Path,
    config_path: &Path,
    vault_path: &Path,
    password: &str,
    force: bool,
) -> Result<BackupMetadata> {
    let payload = decrypt(source, password)?;
    let config: Config = toml::from_str(&payload.config_toml).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("backup contains invalid config: {e}"),
        )
    })?;
    config.validate()?;
    if !force && (config_path.exists() || vault_path.exists()) {
        return Err(AppError::new(
            ErrorCode::AlreadyExists,
            "restore would overwrite existing config or vault; use --force after reviewing the conflict",
        ));
    }
    if force {
        for path in [config_path, vault_path] {
            if path.exists() {
                let bytes =
                    std::fs::read(path).map_err(|e| AppError::io("read restore conflict", e))?;
                let backup = path.with_extension(format!(
                    "before-restore.{}.bak",
                    chrono::Utc::now().timestamp()
                ));
                atomic_write(&backup, &bytes)?;
            }
        }
    }
    atomic_write(config_path, payload.config_toml.as_bytes())?;
    let vault_bytes = serde_json::to_vec_pretty(&payload.vault)
        .map_err(|e| AppError::internal(format!("serialize restored vault: {e}")))?;
    atomic_write(vault_path, &vault_bytes)?;
    Ok(BackupMetadata {
        schema_version: payload.schema_version,
        created_at: payload.created_at,
        hosts: config.hosts.len(),
        path: source.to_path_buf(),
    })
}

fn decrypt(path: &Path, password: &str) -> Result<BackupPayload> {
    require_private_file(path)?;
    let bytes = std::fs::read(path).map_err(|e| AppError::io("read encrypted backup", e))?;
    let encoded = bytes
        .strip_prefix(b"RXB1\n")
        .ok_or_else(|| AppError::invalid_argument("not a Remxo RXB1 encrypted backup"))?;
    let file: BackupFile = serde_json::from_slice(encoded)
        .map_err(|e| AppError::invalid_argument(format!("invalid backup envelope: {e}")))?;
    if file.format != "remxo-encrypted-backup" || file.version != 1 {
        return Err(AppError::invalid_argument("unsupported backup format"));
    }
    let key = derive_kek(password, &file.kdf)?;
    let plaintext = Zeroizing::new(open(
        &key,
        &file.payload,
        BACKUP_CONTEXT,
        "wrong backup password or corrupted backup",
    )?);
    serde_json::from_slice(&plaintext).map_err(|e| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("invalid decrypted backup: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppPaths, Host};
    use crate::vault::VaultSession;

    const MASTER: &str = "test master password";
    const BACKUP: &str = "independent backup password";

    #[test]
    fn encrypted_backup_verifies_and_restores_into_a_fresh_directory() {
        let source = tempfile::tempdir().unwrap_or_else(|e| panic!("source: {e}"));
        let paths = AppPaths::new(Some(source.path().join("config.toml")))
            .unwrap_or_else(|e| panic!("paths: {e}"));
        Config::initialize(&paths.config).unwrap_or_else(|e| panic!("config: {e}"));
        let mut config = Config::load(&paths.config).unwrap_or_else(|e| panic!("load: {e}"));
        config.hosts.insert(
            "example".into(),
            Host {
                hostname: Some("192.0.2.10".into()),
                ssh_alias: None,
                ..Host {
                    number: Some(1),
                    transport: crate::config::TransportKind::Ssh,
                    ssh_alias: None,
                    hostname: None,
                    port: 22,
                    username: None,
                    platform: crate::config::Platform::Linux,
                    shell: crate::config::ShellKind::Posix,
                    auth: crate::config::AuthMode::OpensshConfig,
                    environment: String::new(),
                    tags: Vec::new(),
                    raw_mode: crate::config::RawMode::Allow,
                    approval: crate::config::ApprovalMode::Never,
                    insecure_acknowledged: false,
                    sudo_credential: None,
                    credential: None,
                    prompt: None,
                }
            },
        );
        config
            .save(&paths.config)
            .unwrap_or_else(|e| panic!("save: {e}"));
        VaultSession::initialize(&paths.vault(), MASTER).unwrap_or_else(|e| panic!("vault: {e}"));
        let archive = source.path().join("test.rxb");
        create(&paths.config, &paths.vault(), &archive, BACKUP)
            .unwrap_or_else(|e| panic!("backup: {e}"));
        let disk = std::fs::read_to_string(&archive).unwrap_or_default();
        assert!(!disk.contains("192.0.2.10"));
        assert!(verify(&archive, "wrong backup password").is_err());
        let metadata = verify(&archive, BACKUP).unwrap_or_else(|e| panic!("verify: {e}"));
        assert_eq!(metadata.hosts, 1);

        let destination = tempfile::tempdir().unwrap_or_else(|e| panic!("destination: {e}"));
        let restored = AppPaths::new(Some(destination.path().join("config.toml")))
            .unwrap_or_else(|e| panic!("paths: {e}"));
        restore(&archive, &restored.config, &restored.vault(), BACKUP, false)
            .unwrap_or_else(|e| panic!("restore: {e}"));
        assert!(restored.config.exists());
        let mut vault =
            VaultSession::load(&restored.vault()).unwrap_or_else(|e| panic!("load vault: {e}"));
        assert!(!vault.is_unlocked());
        assert!(vault.unlock(MASTER).is_ok());
        assert!(restore(&archive, &restored.config, &restored.vault(), BACKUP, false).is_err());
    }
}
