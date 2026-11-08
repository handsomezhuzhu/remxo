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
    restrict_file(temporary.as_file(), temporary.path())?;
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
    restrict_file(&file, path)?;
    file.write_all(contents)
        .map_err(|e| AppError::io("write private file", e))?;
    file.sync_all()
        .map_err(|e| AppError::io("sync private file", e))
}

pub(crate) fn restrict_file(_file: &fs::File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    let _ = path;
    #[cfg(unix)]
    _file
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|e| AppError::io("restrict private file", e))?;
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        restrict_windows_acl(path)?;
        #[cfg(not(windows))]
        let _ = _file;
    }
    Ok(())
}

pub fn restrict_path(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| AppError::io("restrict private file", e))?;
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        restrict_windows_acl(path)?;
        #[cfg(not(windows))]
        let _ = path;
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_acl(path: &Path) -> Result<()> {
    const ACL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $true)
$identity = "$($env:USERDOMAIN)\$($env:USERNAME)"
$acl.SetOwner((New-Object System.Security.Principal.NTAccount($identity)))
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
[System.IO.File]::SetAccessControl($env:REMXO_PRIVATE_FILE_PATH, $acl)
"#;
    let system_root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    let output = std::process::Command::new(
        system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
    )
    .arg("-NoProfile")
    .arg("-NonInteractive")
    .arg("-ExecutionPolicy")
    .arg("Bypass")
    .arg("-Command")
    .arg(ACL_SCRIPT)
    .env("REMXO_PRIVATE_FILE_PATH", path)
    .output()
    .map_err(|error| AppError::io("apply Windows ACL to private file", error))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let detail = crate::redact::escape_controls(&String::from_utf8_lossy(detail));
    let detail = detail.chars().take(1024).collect::<String>();
    Err(AppError::new(
        ErrorCode::IoError,
        format!("failed to restrict private file to the current Windows user: {detail}"),
    ))
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

#[cfg(all(windows, test))]
mod tests {
    use super::{NamedTempFile, restrict_file};
    use std::io::Write as _;

    fn windows_icacls(path: &std::path::Path) -> std::process::Output {
        let system_root = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        std::process::Command::new(system_root.join(r"System32\icacls.exe"))
            .arg(path)
            .output()
            .unwrap_or_else(|error| panic!("run icacls: {error}"))
    }

    #[test]
    fn private_file_acl_allows_only_the_current_windows_user() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let mut file = NamedTempFile::new_in(directory.path())
            .unwrap_or_else(|error| panic!("create private file: {error}"));
        restrict_file(file.as_file(), file.path())
            .unwrap_or_else(|error| panic!("restrict ACL: {error}"));
        let output = windows_icacls(file.path());
        assert!(output.status.success(), "icacls inspection failed");
        let listing = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        let account = format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default()
        )
        .to_ascii_lowercase();
        assert!(
            listing.contains(&account),
            "current user has no explicit grant"
        );
        let entries = listing.lines().skip(1).collect::<Vec<_>>().join("\n");
        for denied in ["\\administrators", "\\users", "everyone", "\\unknown"] {
            assert!(
                !entries.contains(denied),
                "unexpected additional ACL grant: {denied}"
            );
        }
        file.write_all(b"test only nonsecret bytes")
            .unwrap_or_else(|error| panic!("write without altering the ACL: {error}"));
    }
}
