#[cfg(unix)]
mod unix {
    use assert_cmd::Command;
    use remxo::broker::{BrokerClient, RpcRequest};
    use remxo::config::{AppPaths, ApprovalMode, Config, Host};
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: AppPaths,
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
            let paths = AppPaths::new(Some(directory.path().join("config.toml")))
                .unwrap_or_else(|e| panic!("paths: {e}"));
            Config::initialize(&paths.config).unwrap_or_else(|e| panic!("config: {e}"));
            let mut config = Config::load(&paths.config).unwrap_or_else(|e| panic!("load: {e}"));
            config.hosts.insert(
                "prod".into(),
                Host {
                    number: Some(2),
                    hostname: Some("192.0.2.1".into()),
                    ssh_alias: None,
                    approval: ApprovalMode::Never,
                    ..Host::default()
                },
            );
            config
                .save(&paths.config)
                .unwrap_or_else(|e| panic!("save: {e}"));
            let root = directory.path().to_path_buf();
            Self {
                _directory: directory,
                paths,
                root,
            }
        }

        fn executable(&self, name: &str, body: &str) -> PathBuf {
            let path = self.root.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n"))
                .unwrap_or_else(|e| panic!("fake: {e}"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|e| panic!("chmod: {e}"));
            path
        }

        fn remxo(&self) -> Command {
            let mut command = Command::cargo_bin("remxo").unwrap_or_else(|e| panic!("binary: {e}"));
            command.arg("--config").arg(&self.paths.config);
            command.timeout(std::time::Duration::from_secs(20));
            command
        }

        async fn shutdown(&self) {
            let client = BrokerClient::new(self.paths.clone());
            let _ = client.call(RpcRequest::Shutdown).await;
        }
    }

    fn json_stdout(output: &[u8]) -> Value {
        serde_json::from_slice(output)
            .unwrap_or_else(|e| panic!("JSON: {e}; raw={}", String::from_utf8_lossy(output)))
    }

    #[test]
    fn non_tty_target_without_command_never_waits_for_input() {
        let fixture = Fixture::new();
        let output = fixture
            .remxo()
            .arg("prod")
            .output()
            .unwrap_or_else(|e| panic!("run: {e}"));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("non-interactive"));
    }

    #[tokio::test]
    async fn fake_ssh_json_secrecy_and_ad_hoc_policy_work_end_to_end() {
        let fixture = Fixture::new();
        let argv_log = fixture.root.join("argv");
        let fake = fixture.executable(
            "fake-ssh",
            &format!(
                "printf '%s\\n' \"$@\" >> '{}'\nprintf 'token=integration-test-secret stdout\\n'\nprintf 'password=integration-test-secret stderr\\n' >&2",
                argv_log.display()
            ),
        );

        let rejected = fixture
            .remxo()
            .env("REMXO_SSH", &fake)
            .args(["--json", "192.0.2.200", "ls"])
            .output()
            .unwrap_or_else(|e| panic!("rejected run: {e}"));
        assert!(!rejected.status.success());
        assert_eq!(
            json_stdout(&rejected.stdout)["error"]["code"],
            "host_not_allowed"
        );

        let output = fixture
            .remxo()
            .env("REMXO_SSH", &fake)
            .args(["--json", "--max-output", "4096", "2", "ls", "-la", "--help"])
            .output()
            .unwrap_or_else(|e| panic!("run: {e}"));
        fixture.shutdown().await;
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = json_stdout(&output.stdout);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["host"], "prod");
        assert_eq!(report["remote_exit_code"], 0);
        assert!(
            !report["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("integration-test-secret")
        );
        assert!(
            !report["stderr"]
                .as_str()
                .unwrap_or_default()
                .contains("integration-test-secret")
        );
        assert!(report["error"].is_null());
        let argv = fs::read_to_string(&argv_log).unwrap_or_default();
        assert!(argv.contains("BatchMode=yes"));
        assert!(argv.contains("--help"));
        assert!(argv.contains("'ls' '-la' '--help'"));
        assert!(!argv.contains("StrictHostKeyChecking=no"));
        assert!(!argv.contains("UserKnownHostsFile=/dev/null"));
        assert!(!argv.contains("ForwardAgent=yes"));
        let audit_path = fixture.paths.audit();
        let audit = fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(!audit.contains("integration-test-secret"));
        assert!(!audit.contains("stdout"));
    }

    #[tokio::test]
    async fn fake_scp_upload_and_download_report_real_bytes() {
        let fixture = Fixture::new();
        let upload = fixture.root.join("app.txt");
        fs::write(&upload, "upload-content").unwrap_or_else(|e| panic!("upload: {e}"));
        let argv_log = fixture.root.join("scp-argv");
        let fake = fixture.executable(
            "fake-scp",
            &format!("printf '%s\\n' \"$@\" > '{}'", argv_log.display()),
        );
        let output = fixture
            .remxo()
            .env("REMXO_SCP", &fake)
            .args(["--json", "--overwrite", "put"])
            .arg(&upload)
            .arg("prod:/tmp/app.txt")
            .output()
            .unwrap_or_else(|e| panic!("put: {e}"));
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = json_stdout(&output.stdout);
        assert_eq!(report["operation"], "put");
        assert!(report["stdout"].as_str().unwrap_or_default().contains("14"));
        assert!(
            fs::read_to_string(&argv_log)
                .unwrap_or_default()
                .contains("--")
        );

        // Broker deliberately inherits transport configuration at startup. Use a fresh
        // broker for the second fake rather than pretending this is a hot reload.
        fixture.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        let fake_get = fixture.executable(
            "fake-scp-get",
            "for last do :; done\nprintf 'downloaded-data' > \"$last\"",
        );
        let download = fixture.root.join("downloaded.txt");
        let output = fixture
            .remxo()
            .env("REMXO_SCP", fake_get)
            .args(["--json", "get", "prod:/tmp/source.txt"])
            .arg(&download)
            .output()
            .unwrap_or_else(|e| panic!("get: {e}"));
        fixture.shutdown().await;
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(download).ok().as_deref(),
            Some("downloaded-data")
        );
        assert!(
            json_stdout(&output.stdout)["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("15")
        );
    }

    #[test]
    fn direct_hostname_is_always_an_argv_not_a_local_shell() {
        let host = Host {
            hostname: Some("192.0.2.1;touch-not-executed".into()),
            ..Host::default()
        };
        assert!(host.validate("host").is_ok());
        let marker = Path::new("touch-not-executed");
        assert!(!marker.exists());
    }
}
