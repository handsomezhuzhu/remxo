#!/usr/bin/env python3
"""Real sshd tests for Vault passwords and encrypted private keys.

Only generated test-only secrets and disposable containers are used. Neither
ASKPASS output nor private-key material is written to test logs.
"""
import os
from pathlib import Path
import shutil
import unittest

from pty_acceptance import (
    KEY_PASSPHRASE,
    ORIGINAL_MASTER,
    SSH_PASSWORD,
    PtyCommand,
)
from sshd_acceptance import SshdFixture


class VaultAuthFixture(SshdFixture):
    def __init__(self, binary):
        super().__init__(binary)
        self.transcripts = []
        self.login_password = SSH_PASSWORD.encode("ascii")
        self.key_passphrase = KEY_PASSPHRASE.encode("ascii")
        credential = self.root / "sudo_credential"
        credential.write_bytes(b"rxuser:" + self.login_password + b"\n")
        credential.chmod(0o600)

        sshd_config = (self.root / "sshd_config").read_text(encoding="utf-8")
        sshd_config = sshd_config.replace("PasswordAuthentication no", "PasswordAuthentication yes")
        sshd_config = sshd_config.replace("AuthenticationMethods publickey\n", "")
        (self.root / "sshd_config").write_text(sshd_config, encoding="utf-8")

        self.vault_key = self.root / "id_ed25519_vault"
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            raise RuntimeError("ssh-keygen is unavailable")
        result = PtyCommand(
            keygen,
            self.config,
            ["-q", "-t", "ed25519", "-f", str(self.vault_key)],
            self.env,
            self.root,
            "generate encrypted test-only key",
            [
                (b"Enter passphrase", self.key_passphrase + b"\n"),
                (b"Enter same passphrase again", self.key_passphrase + b"\n"),
            ],
            with_config=False,
        ).run()
        self.transcripts.append(result.output)
        self.vault_key.chmod(0o600)

        entrypoint = self.root / "image" / "entrypoint.sh"
        script = entrypoint.read_text(encoding="utf-8")
        old_install = (
            "install -m 600 -o rxuser -g rxuser /test/id_ed25519.pub "
            "/home/rxuser/.ssh/authorized_keys"
        )
        new_install = (
            "cat /test/id_ed25519.pub /test/id_ed25519_vault.pub "
            "> /home/rxuser/.ssh/authorized_keys\n"
            "chown rxuser:rxuser /home/rxuser/.ssh/authorized_keys\n"
            "chmod 600 /home/rxuser/.ssh/authorized_keys"
        )
        if old_install not in script:
            raise RuntimeError("cannot prepare the isolated authorized_keys fixture")
        entrypoint.write_text(script.replace(old_install, new_install), encoding="utf-8")

        # Apply strict host-key settings to direct hostnames as well as the
        # existing remxo-test alias. No user's SSH configuration is used.
        self.openssh_config.write_text(
            "Host *\n"
            "  UserKnownHostsFile {0}\n"
            "  StrictHostKeyChecking yes\n".format(self.known_hosts)
            + self.openssh_config.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.openssh_config.chmod(0o600)

        baseline = self.config.read_text(encoding="utf-8")
        self.config.unlink()
        self.hidden(
            "vault authentication fixture init",
            ["init", "--lang", "en"],
            [
                (b"New master password: ", ORIGINAL_MASTER.encode("ascii") + b"\n"),
                (b"Confirm password: ", ORIGINAL_MASTER.encode("ascii") + b"\n"),
            ],
        )
        for alias, number, auth in (
            ("vaultpass", 3, "vault-password"),
            ("vaultkey", 4, "vault-key"),
        ):
            baseline += (
                "\n[hosts.{0}]\n"
                "number = {1}\n"
                "transport = 'ssh'\n"
                "hostname = '127.0.0.1'\n"
                "port = {2}\n"
                "username = 'rxuser'\n"
                "platform = 'linux'\n"
                "shell = 'posix'\n"
                "auth = '{3}'\n"
                "environment = 'test'\n"
                "tags = []\n"
                "raw_mode = 'allow'\n"
                "approval = 'never'\n"
                "insecure_acknowledged = false\n"
                "credential = '{0}'\n".format(alias, number, self.port, auth)
            )
        self.config.write_text(baseline, encoding="utf-8")
        self.config.chmod(0o600)

    def hidden(self, stage, arguments, replies):
        result = PtyCommand(
            str(self.binary),
            self.config,
            arguments,
            self.env,
            self.root,
            stage,
            replies,
        ).run()
        self.transcripts.append(result.output)
        return result

    def assert_secret_hygiene(self):
        secrets_and_key = [self.login_password, self.key_passphrase, self.vault_key.read_bytes()]
        artifacts = [self.config, self.data / "vault.json"]
        audit = self.data / "audit.jsonl"
        if audit.exists():
            artifacts.append(audit)
        for artifact in artifacts:
            contents = artifact.read_bytes()
            if any(secret in contents for secret in secrets_and_key):
                raise AssertionError("plaintext authentication material in " + artifact.name)
        for transcript in self.transcripts:
            if any(secret in transcript for secret in secrets_and_key[:2]):
                raise AssertionError("hidden authentication prompt was echoed")
        if str(self.vault_key).encode() in self.config.read_bytes():
            raise AssertionError("private key path was persisted as host authentication data")


class VaultAuthAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("REMXO_BIN")
        if not binary:
            raise unittest.SkipTest("REMXO_BIN was not set; Vault authentication tests were not run")
        cls.fixture = VaultAuthFixture(binary)
        try:
            cls.fixture.start()
        except (FileNotFoundError, RuntimeError) as error:
            cls.fixture.close()
            if os.environ.get("REMXO_REQUIRE_REAL_SSH") == "1":
                raise
            raise unittest.SkipTest("Docker/sshd unavailable: {0}".format(error))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "fixture"):
            cls.fixture.close()

    def test_vault_password_key_passphrase_transfer_and_host_key_policy(self):
        fixture = self.fixture
        fixture.hidden(
            "unlock real authentication vault",
            ["unlock"],
            [(b"Master password: ", ORIGINAL_MASTER.encode("ascii") + b"\n")],
        )
        fixture.hidden(
            "store real SSH login password",
            ["vault", "set-ssh-password", "vaultpass"],
            [(b"SSH password or private key passphrase (hidden): ", fixture.login_password + b"\n")],
        )
        fixture.hidden(
            "import test-only encrypted private key",
            ["vault", "import-key", "vaultkey", "--path", str(fixture.vault_key)],
            [],
        )
        fixture.hidden(
            "store private key passphrase",
            ["vault", "set-ssh-password", "vaultkey"],
            [(b"SSH password or private key passphrase (hidden): ", fixture.key_passphrase + b"\n")],
        )

        report = fixture.expect(["vaultpass", "printf", "vault-password-ok"])
        self.assertEqual(report["stdout"], "vault-password-ok")
        report = fixture.expect(["vaultkey", "printf", "vault-key-ok"])
        self.assertEqual(report["stdout"], "vault-key-ok")

        upload = fixture.root / "vault-upload.txt"
        download = fixture.root / "vault-download.txt"
        upload.write_text("isolated-vault-transfer", encoding="utf-8")
        fixture.expect(["put", upload, "vaultpass:/tmp/remxo-vault-transfer.txt"])
        fixture.expect(["get", "vaultkey:/tmp/remxo-vault-transfer.txt", download])
        self.assertEqual(download.read_text(encoding="utf-8"), upload.read_text(encoding="utf-8"))

        good_hosts = fixture.known_hosts.read_bytes()
        fixture.known_hosts.write_text(
            "[127.0.0.1]:{0} {1}\n".format(
                fixture.port,
                " ".join((fixture.root / "id_ed25519.pub").read_text().split()[:2]),
            )
        )
        fixture.known_hosts.chmod(0o600)
        report = fixture.expect(["vaultpass", "true"], code=1)
        self.assertEqual(report["error"]["code"], "host_key_failed")
        fixture.known_hosts.write_bytes(good_hosts)
        fixture.known_hosts.chmod(0o600)
        fixture.expect(["vaultpass", "true"])

        runtime = fixture.data / "runtime"
        if runtime.exists() and any(runtime.iterdir()):
            raise AssertionError("temporary private key survived completed authentication")
        fixture.assert_secret_hygiene()


if __name__ == "__main__":
    unittest.main(verbosity=2)
