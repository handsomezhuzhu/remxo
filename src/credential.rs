use crate::error::{AppError, ErrorCode, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub const SSH_PASSWORD_KIND: &str = "ssh-password";
pub const SSH_PRIVATE_KEY_KIND: &str = "ssh-private-key";
pub const MAX_PRIVATE_KEY_BYTES: usize = 1024 * 1024;

pub fn ssh_credential_name(alias: &str) -> String {
    format!("{alias}:ssh")
}

pub fn key_credential_name(alias: &str) -> String {
    format!("{alias}:key")
}

pub fn sudo_credential_name(alias: &str) -> String {
    format!("{alias}:sudo")
}
pub fn read_private_key(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("cannot inspect the specified private key file: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "private key import accepts a regular file, not a symlink, directory, or special file",
        ));
    }
    if metadata.len() > MAX_PRIVATE_KEY_BYTES as u64 {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "private key exceeds the 1 MiB import limit",
        ));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        AppError::new(
            ErrorCode::InvalidConfig,
            format!("cannot resolve private key location: {error}"),
        )
    })?;
    let mut contents = Vec::new();
    File::open(canonical)
        .map_err(|error| AppError::io("open the specified private key", error))?
        .take((MAX_PRIVATE_KEY_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|error| AppError::io("read private key into memory", error))?;
    if contents.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "private key exceeds the 1 MiB import limit",
        ));
    }
    let mut plaintext = Zeroizing::new(contents);
    let text = match String::from_utf8(std::mem::take(plaintext.as_mut())) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            return Err(AppError::new(
                ErrorCode::InvalidConfig,
                "private key must be a textual OpenSSH PEM file, not binary or non-UTF-8 data",
            ));
        }
    };
    if !text.is_ascii()
        || !matches!(
            first_marker(&text).as_deref(),
            Some("OPENSSH PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "PRIVATE KEY")
        )
    {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            "unrecognized private key format; expected an OpenSSH/RSA/EC/PKCS#8 PEM private key",
        ));
    }
    Ok(text)
}

fn first_marker(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|marker| marker.strip_suffix("-----"))
            .map(str::to_string)
    })
}

#[derive(Debug)]
pub struct TemporaryPrivateKey {
    temporary: NamedTempFile,
}

impl TemporaryPrivateKey {
    pub fn create(parent: &Path, contents: &str) -> Result<Self> {
        crate::store::ensure_private_dir(parent)?;
        let mut temporary = NamedTempFile::new_in(parent)
            .map_err(|error| AppError::io("create managed temporary key file", error))?;
        crate::store::restrict_file(temporary.as_file())?;
        std::io::Write::write_all(temporary.as_file_mut(), contents.as_bytes())
            .map_err(|error| AppError::io("write temporary key file", error))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| AppError::io("sync temporary key file", error))?;
        Ok(Self { temporary })
    }

    pub fn path(&self) -> &Path {
        self.temporary.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_import_rejects_non_key_text_without_echoing_contents() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("not-a-key");
        std::fs::write(&path, "test-only-invalid-private-material")
            .unwrap_or_else(|error| panic!("write: {error}"));
        let error = read_private_key(&path).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidConfig);
        assert!(!error.message.contains("test-only-invalid-private-material"));
    }

    #[test]
    fn openssh_pem_marker_is_imported() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("id_test");
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\ndGVzdC1vbmx5LW5vdC1hLXJlYWwta2V5\n-----END OPENSSH PRIVATE KEY-----\n";
        std::fs::write(&path, pem).unwrap_or_else(|error| panic!("write: {error}"));
        let imported = read_private_key(&path).unwrap_or_else(|error| panic!("import: {error}"));
        assert_eq!(imported.as_str(), pem);
    }

    #[cfg(unix)]
    #[test]
    fn imported_key_tmp_file_is_private_and_removed_on_drop() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let runtime = directory.path().join("runtime");
        let (path, source) = {
            let key = TemporaryPrivateKey::create(&runtime, "test-key-material")
                .unwrap_or_else(|error| panic!("create: {error}"));
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(key.path())
                    .unwrap_or_else(|error| panic!("metadata: {error}"))
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::read_to_string(key.path()).unwrap_or_default(),
                "test-key-material"
            );
            (key.path().to_path_buf(), key)
        };
        assert!(path.exists());
        drop(source);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_imported() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("link");
        symlink("/etc/hosts", &path).unwrap_or_else(|error| panic!("symlink: {error}"));
        assert!(read_private_key(&path).is_err());
    }
}
