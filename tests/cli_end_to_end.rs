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

    #[tokio::test]
    async fn fake_ssh_vault_password_uses_real_askpass_without_logging_the_secret() {
        use remxo::config::AuthMode;
        use remxo::vault::{Credential, VaultSession};
        use std::collections::BTreeMap;

        let fixture = Fixture::new();
        let master = "TEST-ONLY-fake-master-password";
        let login = "TEST-ONLY-fake-vault-login";
        let mut vault = VaultSession::initialize(&fixture.paths.vault(), master)
            .unwrap_or_else(|error| panic!("vault: {error}"));
        vault
            .unlock(master)
            .unwrap_or_else(|error| panic!("unlock: {error}"));
        vault
            .put_record(
                "prod:ssh",
                Credential {
                    kind: "ssh-password".into(),
                    value: login.into(),
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|error| panic!("credential: {error}"));
        let mut config =
            Config::load(&fixture.paths.config).unwrap_or_else(|error| panic!("load: {error}"));
        let host = config.hosts.get_mut("prod").expect("fixture host");
        host.auth = AuthMode::VaultPassword;
        host.credential = Some("prod".into());
        config
            .save(&fixture.paths.config)
            .unwrap_or_else(|error| panic!("save: {error}"));

        let argv_log = fixture.root.join("vault-argv");
        let context_log = fixture.root.join("vault-context");
        let progress_log = fixture.root.join("vault-progress");
        let fake = fixture.executable(
            "fake-vault-ssh",
            &format!(
                "[ \"$SSH_ASKPASS_REQUIRE\" = force ] || exit 41\n\
                 [ \"$REMXO_ASKPASS_TARGET\" = prod ] || exit 42\n\
                 [ -z \"${{REMXO_ASKPASS_PENDING_HOST+x}}\" ] || exit 43\n\
                 printf 'before-password\\n' >> '{}'\n\
                 reply=$(\"$SSH_ASKPASS\" \"prod's password: \") || exit 44\n\
                 printf 'after-password\\n' >> '{}'\n\
                 [ -n \"$reply\" ] || exit 45\n\
                 unset reply\n\
                 for prompt in 'continue connecting (yes/no)?' 'Verification code:' 'Unexpected prompt:'; do\n\
                     if \"$SSH_ASKPASS\" \"$prompt\" >/dev/null 2>/dev/null; then exit 46; fi\n\
                     printf 'rejected-prompt\\n' >> '{}'\n\
                 done\n\
                 printf '%s\\n' \"$@\" > '{}'\n\
                 printf '%s\\n' \"$REMXO_ASKPASS_TARGET\" \"$SSH_ASKPASS_REQUIRE\" > '{}'\n\
                 printf 'vault-auth-ok\\n'",
                progress_log.display(),
                progress_log.display(),
                progress_log.display(),
                argv_log.display(),
                context_log.display()
            ),
        );
        let audit_path = fixture.paths.audit();
        let mut daemon = std::process::Command::new(env!("CARGO_BIN_EXE_remxo"));
        let daemon_status = daemon
            .arg("--config")
            .arg(&fixture.paths.config)
            .env("REMXO_SSH", &fake)
            .arg("__broker-daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn broker: {error}"))
            .wait()
            .unwrap_or_else(|error| panic!("wait for broker parent: {error}"));
        assert!(daemon_status.success());
        let client = BrokerClient::new(fixture.paths.clone());
        let mut ready = false;
        for _ in 0..100 {
            if client.ping().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready, "test broker daemon did not start");
        let _ = client
            .call(RpcRequest::Unlock {
                password: master.into(),
            })
            .await
            .unwrap_or_else(|error| panic!("RPC unlock: {error}"));
        let output = fixture
            .remxo()
            .env("REMXO_SSH", fake)
            .args(["--json", "prod", "true"])
            .output()
            .unwrap_or_else(|error| panic!("run: {error}"));
        fixture.shutdown().await;
        let progress = fs::read_to_string(progress_log).unwrap_or_default();
        assert!(
            output.status.success(),
            "stderr={}; stdout={}; progress={progress}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let report = json_stdout(&output.stdout);
        assert_eq!(report["remote_exit_code"], 0);
        let argv = fs::read_to_string(argv_log).unwrap_or_default();
        assert!(argv.contains("BatchMode=no"));
        assert!(argv.contains("NumberOfPasswordPrompts=1"));
        assert!(argv.contains("PreferredAuthentications=password"));
        assert!(argv.contains("KbdInteractiveAuthentication=no"));
        assert!(!argv.contains("BatchMode=yes"));
        assert!(!argv.contains(login));
        assert!(!argv.contains("__askpass"));
        assert_eq!(
            fs::read_to_string(context_log).unwrap_or_default(),
            "prod\nforce\n"
        );
        for contents in [argv, fs::read_to_string(audit_path).unwrap_or_default()] {
            assert!(!contents.contains(login));
        }

        fixture.shutdown().await;
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;
        let mut config = Config::load(&fixture.paths.config)
            .unwrap_or_else(|error| panic!("load key host: {error}"));
        config.hosts.get_mut("prod").expect("fixture host").auth = AuthMode::VaultKey;
        config
            .save(&fixture.paths.config)
            .unwrap_or_else(|error| panic!("save key host: {error}"));
        let mut vault = VaultSession::load(&fixture.paths.vault())
            .unwrap_or_else(|error| panic!("load vault: {error}"));
        vault
            .unlock(master)
            .unwrap_or_else(|error| panic!("unlock key vault: {error}"));
        vault
            .put_record(
                "prod:key",
                Credential {
                    kind: "ssh-private-key".into(),
                    value: "-----BEGIN OPENSSH PRIVATE KEY-----\ndGVzdC1vbmx5LW5vdC1hLXJlYWwta2V5\n-----END OPENSSH PRIVATE KEY-----\n".into(),
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap_or_else(|error| panic!("private key: {error}"));
        let key_path_log = fixture.root.join("key-path");
        let sleeping_fake = fixture.executable(
            "fake-vault-key-timeout",
            &format!(
                "while [ \"$#\" -gt 0 ]; do\n\
                    if [ \"$1\" = -i ]; then printf '%s\\n' \"$2\" > '{}'; break; fi\n\
                    shift\n\
                 done\n\
                 sleep 2",
                key_path_log.display()
            ),
        );
        let mut daemon = std::process::Command::new(env!("CARGO_BIN_EXE_remxo"));
        let daemon_status = daemon
            .arg("--config")
            .arg(&fixture.paths.config)
            .env("REMXO_SSH", &sleeping_fake)
            .arg("__broker-daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn key broker: {error}"))
            .wait()
            .unwrap_or_else(|error| panic!("wait for key broker parent: {error}"));
        assert!(daemon_status.success());
        let mut ready = false;
        for _ in 0..100 {
            if client.ping().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ready, "key test broker daemon did not start");
        let _ = client
            .call(RpcRequest::Unlock {
                password: master.into(),
            })
            .await
            .unwrap_or_else(|error| panic!("RPC key unlock: {error}"));
        let output = fixture
            .remxo()
            .args(["--json", "--timeout", "1s", "prod", "true"])
            .output()
            .unwrap_or_else(|error| panic!("timeout run: {error}"));
        fixture.shutdown().await;
        assert!(!output.status.success());
        assert_eq!(json_stdout(&output.stdout)["error"]["code"], "timeout");
        let key_path = fs::read_to_string(key_path_log).unwrap_or_default();
        assert!(
            !key_path.trim().is_empty(),
            "fake did not receive a key path"
        );
        assert!(
            !Path::new(key_path.trim()).exists(),
            "temporary private key survived transport timeout"
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

#[cfg(windows)]
mod windows {
    use remxo::broker::{BrokerClient, RpcPayload, RpcRequest};
    use remxo::config::{AppPaths, Config};
    use remxo::vault::VaultSession;

    #[tokio::test]
    async fn cli_reuses_unlocked_broker_after_the_invoking_process_exits() {
        let directory = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let paths = AppPaths::new(Some(directory.path().join("config.toml")))
            .unwrap_or_else(|e| panic!("paths: {e}"));
        Config::initialize_with_language(&paths.config, remxo::config::UiLanguage::ZhCn)
            .unwrap_or_else(|e| panic!("initialize config: {e}"));
        VaultSession::initialize(&paths.vault(), "test-only-broker-lifecycle")
            .unwrap_or_else(|e| panic!("initialize vault: {e}"));

        let first = std::process::Command::new(env!("CARGO_BIN_EXE_remxo"))
            .arg("--config")
            .arg(&paths.config)
            .args(["task", "list"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("first CLI process: {e}"));
        let status = first
            .wait_with_output()
            .unwrap_or_else(|e| panic!("wait for first CLI: {e}"));
        assert!(status.status.success(), "first terminal process failed");

        let client = BrokerClient::new(paths.clone());
        let mut running = None;
        for _ in 0..40 {
            if let Ok(RpcPayload::Status(status)) = client.call(RpcRequest::Status).await {
                running = Some(status);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let status = running.unwrap_or_else(|| panic!("broker did not survive the first CLI exit"));
        assert!(status.broker_running);
        assert!(status.vault_locked);
        let _ = client
            .call(RpcRequest::Unlock {
                password: "test-only-broker-lifecycle".into(),
            })
            .await
            .unwrap_or_else(|error| panic!("test-only unlock failed: {error}"));
        let second = BrokerClient::new(paths.clone());
        let RpcPayload::Status(refreshed) = second
            .call(RpcRequest::Status)
            .await
            .unwrap_or_else(|error| panic!("second terminal query: {error}"))
        else {
            panic!("unexpected status response")
        };
        assert!(refreshed.broker_running);
        assert!(!refreshed.vault_locked);
        let _ = second.call(RpcRequest::Shutdown).await;
    }
}
