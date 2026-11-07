use crate::error::{AppError, ErrorCode, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| AppError::io("create private directory", e))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| AppError::io("restrict private directory", e))?;
    Ok(())
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::invalid_argument("output path has no parent directory"))?;
    ensure_private_dir(parent)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|e| AppError::io("create temporary file", e))?;
    restrict_file(temporary.as_file())?;
    temporary
        .write_all(contents)
        .map_err(|e| AppError::io("write temporary file", e))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| AppError::io("sync temporary file", e))?;
    temporary
        .persist(path)
        .map_err(|e| AppError::io("atomically replace file", e.error))?;
    restrict_path(path)?;
    Ok(())
}

pub fn create_new(path: &Path, contents: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(AppError::new(
            ErrorCode::AlreadyExists,
            format!("refusing to overwrite existing file: {}", path.display()),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::invalid_argument("output path has no parent directory"))?;
    ensure_private_dir(parent)?;
    #[cfg(unix)]
    let mut options = {
        let mut options = OpenOptions::new();
        options.mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let mut options = OpenOptions::new();
    let mut file = options
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| AppError::io("create new private file", e))?;
    restrict_file(&file)?;
    file.write_all(contents)
        .map_err(|e| AppError::io("write private file", e))?;
    file.sync_all()
        .map_err(|e| AppError::io("sync private file", e))
}

fn restrict_file(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| AppError::io("restrict private file", e))?;
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

pub fn restrict_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| AppError::io("restrict private file", e))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn require_private_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|e| AppError::io("inspect private file", e))?;
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AppError::new(
            ErrorCode::InvalidConfig,
            format!(
                "private file has group/other permissions; expected 0600: {}",
                path.display()
            ),
        ));
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}
