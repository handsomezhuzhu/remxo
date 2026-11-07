use crate::error::{AppError, ErrorCode, Result};
use crate::store::{atomic_write, create_new, require_private_file};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const DEK_CONTEXT: &[u8] = b"remxo:v1:wrapped-dek";
const DATA_CONTEXT: &[u8] = b"remxo:v1:vault-data";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfParameters {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

impl KdfParameters {
    pub fn generate() -> Self {
        let mut salt = [0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: "argon2id".to_string(),
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
            salt: BASE64.encode(salt),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedData {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: KdfParameters,
    pub wrapped_dek: SealedData,
    pub data: SealedData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Zeroize for Credential {
    fn zeroize(&mut self) {
        self.kind.zeroize();
        self.value.zeroize();
        for (mut key, mut value) in std::mem::take(&mut self.metadata) {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub records: BTreeMap<String, Credential>,
}

impl Zeroize for VaultData {
    fn zeroize(&mut self) {
        for (mut name, mut credential) in std::mem::take(&mut self.records) {
            name.zeroize();
            credential.zeroize();
        }
    }
}

impl Drop for VaultData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct VaultSession {
    path: PathBuf,
    file: VaultFile,
    dek: Option<Zeroizing<Vec<u8>>>,
}

impl VaultSession {
    pub fn initialize(path: &Path, master_password: &str) -> Result<Self> {
        if master_password.len() < 12 {
            return Err(AppError::invalid_argument(
                "master password must contain at least 12 bytes",
            ));
        }
        if path.exists() {
            return Err(AppError::new(
                ErrorCode::AlreadyExists,
                "vault already exists",
            ));
        }
        let file = create_file(master_password, VaultData::default())?;
        let text = serde_json::to_vec_pretty(&file)
            .map_err(|e| AppError::internal(format!("serialize vault: {e}")))?;
        create_new(path, &text)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            dek: None,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        require_private_file(path)?;
        let bytes = std::fs::read(path).map_err(|e| AppError::io("read vault", e))?;
        let file: VaultFile = serde_json::from_slice(&bytes).map_err(|e| {
            AppError::new(
                ErrorCode::InvalidConfig,
                format!("invalid vault format: {e}"),
            )
        })?;
        validate_vault_format(&file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            dek: None,
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        let kek = derive_kek(master_password, &self.file.kdf)?;
        let dek = Zeroizing::new(open(
            &kek,
            &self.file.wrapped_dek,
            DEK_CONTEXT,
            "wrong master password or corrupted vault",
        )?);
        if dek.len() != 32 {
            return Err(AppError::new(
                ErrorCode::AuthenticationFailed,
                "invalid wrapped vault key",
            ));
        }
        let plaintext = Zeroizing::new(open(
            &dek,
            &self.file.data,
            DATA_CONTEXT,
            "vault data is corrupted",
        )?);
        let _: VaultData = serde_json::from_slice(&plaintext).map_err(|e| {
            AppError::new(
                ErrorCode::InvalidConfig,
                format!("invalid decrypted vault data: {e}"),
            )
        })?;
        self.dek = Some(dek);
        Ok(())
    }

    pub fn lock(&mut self) {
        self.dek = None;
    }

    pub fn put_record(&mut self, name: &str, credential: Credential) -> Result<()> {
        let mut data = self.read_data()?;
        data.records.insert(name.to_string(), credential);
        self.write_data(&data)
    }

    pub fn remove_record(&mut self, name: &str) -> Result<bool> {
        let mut data = self.read_data()?;
        let removed = data.records.remove(name).is_some();
        if removed {
            self.write_data(&data)?;
        }
        Ok(removed)
    }

    pub fn credential(&self, name: &str) -> Result<String> {
        let data = self.read_data()?;
        data.records
            .get(name)
            .map(|credential| credential.value.clone())
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::SudoPasswordNotConfigured,
                    format!("credential is not configured: {name}"),
                )
            })
    }

    pub fn has_credential(&self, name: &str) -> Result<bool> {
        Ok(self.read_data()?.records.contains_key(name))
    }

    pub fn credential_with_kind(&self, name: &str, expected_kind: &str) -> Result<String> {
        let data = self.read_data()?;
        let credential = data.records.get(name).ok_or_else(|| {
            AppError::new(
                ErrorCode::SudoPasswordNotConfigured,
                format!("credential is not configured: {name}"),
            )
        })?;
        if credential.kind != expected_kind {
            return Err(AppError::new(
                ErrorCode::SudoNotPermitted,
                "the configured credential type is not valid for sudo",
            ));
        }
        Ok(credential.value.clone())
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        if new_password.len() < 12 {
            return Err(AppError::invalid_argument(
                "new master password must contain at least 12 bytes",
            ));
        }
        let old_kek = derive_kek(old_password, &self.file.kdf)?;
        let dek = Zeroizing::new(open(
            &old_kek,
            &self.file.wrapped_dek,
            DEK_CONTEXT,
            "wrong current master password or corrupted vault",
        )?);
        let kdf = KdfParameters::generate();
        let new_kek = derive_kek(new_password, &kdf)?;
        self.file.kdf = kdf;
        self.file.wrapped_dek = seal(&new_kek, &dek, DEK_CONTEXT)?;
        self.dek = Some(dek);
        self.persist()
    }

    fn read_data(&self) -> Result<VaultData> {
        let dek = self.dek.as_ref().ok_or_else(vault_locked)?;
        let plaintext = Zeroizing::new(open(
            dek,
            &self.file.data,
            DATA_CONTEXT,
            "vault data is corrupted",
        )?);
        serde_json::from_slice(&plaintext).map_err(|e| {
            AppError::new(
                ErrorCode::InvalidConfig,
                format!("invalid decrypted vault data: {e}"),
            )
        })
    }

    fn write_data(&mut self, data: &VaultData) -> Result<()> {
        let dek = self.dek.as_ref().ok_or_else(vault_locked)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(data)
                .map_err(|e| AppError::internal(format!("serialize vault data: {e}")))?,
        );
        self.file.data = seal(dek, &plaintext, DATA_CONTEXT)?;
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let text = serde_json::to_vec_pretty(&self.file)
            .map_err(|e| AppError::internal(format!("serialize vault: {e}")))?;
        atomic_write(&self.path, &text)
    }

    pub fn file(&self) -> &VaultFile {
        &self.file
    }
}

pub fn vault_locked() -> AppError {
    AppError::new(
        ErrorCode::VaultLocked,
        "Remxo is locked. A human must run: remxo unlock",
    )
}

fn create_file(master_password: &str, data: VaultData) -> Result<VaultFile> {
    let dek = Zeroizing::new(OsRng.r#gen::<[u8; 32]>().to_vec());
    let kdf = KdfParameters::generate();
    let kek = derive_kek(master_password, &kdf)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&data)
            .map_err(|e| AppError::internal(format!("serialize vault data: {e}")))?,
    );
    Ok(VaultFile {
        version: 1,
        wrapped_dek: seal(&kek, &dek, DEK_CONTEXT)?,
        kdf,
        data: seal(&dek, &plaintext, DATA_CONTEXT)?,
    })
}

fn validate_vault_format(file: &VaultFile) -> Result<()> {
    if file.version != 1
        || file.kdf.algorithm != "argon2id"
        || file.wrapped_dek.algorithm != "xchacha20poly1305"
        || file.data.algorithm != "xchacha20poly1305"
    {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "unsupported vault schema or cryptographic algorithm",
        ));
    }
    Ok(())
}

pub(crate) fn derive_kek(password: &str, parameters: &KdfParameters) -> Result<Zeroizing<Vec<u8>>> {
    if parameters.algorithm != "argon2id" {
        return Err(AppError::invalid_argument("unsupported KDF"));
    }
    if !(8 * 1024..=256 * 1024).contains(&parameters.memory_kib)
        || !(1..=10).contains(&parameters.iterations)
        || !(1..=4).contains(&parameters.parallelism)
    {
        return Err(AppError::invalid_argument(
            "Argon2 parameters are outside the permitted safety limits",
        ));
    }
    let salt = BASE64
        .decode(&parameters.salt)
        .map_err(|_| AppError::invalid_argument("invalid KDF salt"))?;
    if !(16..=64).contains(&salt.len()) {
        return Err(AppError::invalid_argument("invalid KDF salt length"));
    }
    let params = Params::new(
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
        Some(32),
    )
    .map_err(|e| AppError::invalid_argument(format!("invalid Argon2 parameters: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| AppError::internal(format!("derive encryption key: {e}")))?;
    Ok(key)
}

pub(crate) fn seal(key: &[u8], plaintext: &[u8], context: &[u8]) -> Result<SealedData> {
    let key = chacha20poly1305::Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad: context,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| AppError::internal("authenticated encryption failed"))?;
    Ok(SealedData {
        algorithm: "xchacha20poly1305".to_string(),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(ciphertext),
    })
}

pub(crate) fn open(
    key: &[u8],
    sealed: &SealedData,
    context: &[u8],
    failure_message: &str,
) -> Result<Vec<u8>> {
    if sealed.algorithm != "xchacha20poly1305" {
        return Err(AppError::invalid_argument("unsupported AEAD algorithm"));
    }
    let nonce_bytes = BASE64
        .decode(&sealed.nonce)
        .map_err(|_| AppError::new(ErrorCode::AuthenticationFailed, failure_message))?;
    if nonce_bytes.len() != 24 {
        return Err(AppError::new(
            ErrorCode::AuthenticationFailed,
            failure_message,
        ));
    }
    let ciphertext = BASE64
        .decode(&sealed.ciphertext)
        .map_err(|_| AppError::new(ErrorCode::AuthenticationFailed, failure_message))?;
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: context,
            },
        )
        .map_err(|_| AppError::new(ErrorCode::AuthenticationFailed, failure_message))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn locks_on_new_session_and_rejects_a_wrong_password() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("vault.json");
        let mut vault =
            VaultSession::initialize(&path, PASSWORD).unwrap_or_else(|e| panic!("init: {e}"));
        vault.lock();
        assert!(
            matches!(vault.unlock("incorrect password"), Err(error) if error.code == ErrorCode::AuthenticationFailed)
        );
        assert!(!vault.is_unlocked());
        let mut restarted = VaultSession::load(&path).unwrap_or_else(|e| panic!("load: {e}"));
        assert!(!restarted.is_unlocked());
        assert!(restarted.unlock(PASSWORD).is_ok());
    }

    #[test]
    fn neither_secret_nor_dek_are_plaintext_on_disk() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("vault.json");
        let mut vault =
            VaultSession::initialize(&path, PASSWORD).unwrap_or_else(|e| panic!("init: {e}"));
        vault
            .unlock(PASSWORD)
            .unwrap_or_else(|e| panic!("unlock: {e}"));
        let dek = vault.dek.clone().unwrap_or_default();
        vault
            .put_record(
                "prod:sudo",
                Credential {
                    kind: "sudo-password".into(),
                    value: "test-only-sudo-secret".into(),
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|e| panic!("put record: {e}"));
        let disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!disk.contains("test-only-sudo-secret"));
        assert!(!disk.contains(&hex::encode(dek.as_slice())));
        assert!(!disk.contains(&BASE64.encode(dek.as_slice())));
    }

    #[test]
    fn malicious_kdf_parameters_are_rejected_before_allocation() {
        let mut parameters = KdfParameters::generate();
        parameters.memory_kib = 256 * 1024 + 1;
        assert!(derive_kek(PASSWORD, &parameters).is_err());
        parameters.memory_kib = 19_456;
        parameters.iterations = 0;
        assert!(derive_kek(PASSWORD, &parameters).is_err());
        parameters.iterations = 2;
        parameters.parallelism = 0;
        assert!(derive_kek(PASSWORD, &parameters).is_err());
    }

    #[test]
    fn password_change_rewraps_the_same_dek() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = directory.path().join("vault.json");
        let mut vault =
            VaultSession::initialize(&path, PASSWORD).unwrap_or_else(|e| panic!("init: {e}"));
        vault
            .unlock(PASSWORD)
            .unwrap_or_else(|e| panic!("unlock: {e}"));
        let before = vault.dek.clone().unwrap_or_default();
        let ciphertext = vault.file.data.ciphertext.clone();
        vault
            .change_password(PASSWORD, "a new correct password")
            .unwrap_or_else(|e| panic!("change: {e}"));
        assert_eq!(
            before.as_slice(),
            vault.dek.as_ref().map(|v| v.as_slice()).unwrap_or_default()
        );
        assert_eq!(ciphertext, vault.file.data.ciphertext);
        let mut restarted = VaultSession::load(&path).unwrap_or_else(|e| panic!("load: {e}"));
        assert!(restarted.unlock("a new correct password").is_ok());
    }
}
