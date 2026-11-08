/// Prevent a captured non-interactive child from allocating a visible console
/// window on Windows. Interactive CLI/SSH processes do not use these helpers.
#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x08000000;

pub(crate) fn without_console_window(command: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}

pub(crate) fn tokio_without_console_window(command: &mut tokio::process::Command) {
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    #[cfg(not(windows))]
    let _ = command;
}

#[cfg(all(windows, test))]
mod tests {
    #[test]
    fn hidden_powershell_does_not_have_a_visible_console_window() {
        let probe = r#"
Add-Type -Namespace RemxoProcessTest -Name WindowProbe -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);'
$window = [RemxoProcessTest.WindowProbe]::GetConsoleWindow()
if ($window -ne [IntPtr]::Zero -and [RemxoProcessTest.WindowProbe]::IsWindowVisible($window)) { throw 'visible console window' }
"#;
        let system_root = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        let mut command = std::process::Command::new(
            system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
        );
        command
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(probe);
        super::without_console_window(&mut command);
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("run Windows console fixture: {error}"));
        assert!(
            output.status.success(),
            "hidden console fixture observed a visible window"
        );
    }
}
