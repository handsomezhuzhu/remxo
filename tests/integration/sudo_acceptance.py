#!/usr/bin/env python3
"""Real SSH + real sudo + real Vault/approval flow, entirely inside a fixture."""
import os
from pathlib import Path
import json
import secrets
import stat
import unittest

from sshd_acceptance import SshdFixture
from pty_acceptance import PtyCommand, ORIGINAL_MASTER


class SudoSshAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("REMXO_BIN")
        if not binary:
            raise unittest.SkipTest("REMXO_BIN was not set; real sudo test was not run")
        cls.fixture = SudoFixture(binary)
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

    def test_real_sudo_requires_human_approval_and_never_leaks_password(self):
        fixture = self.fixture
        fixture.hidden("initial real sudo unlock", ["unlock"], [
            (b"Master password: ", fixture.master + b"\n"),
        ])
        status = fixture.hidden("check broker survives unlock terminal exit", ["--json", "status"], [])
        parsed = json.loads(status.output)
        assert parsed["vault_locked"] is False, "broker reverted to locked before the next CLI call"
        assert parsed["broker_running"], "broker did not survive unlock terminal exit"
        fixture.hidden("configure typed sudo credential", ["vault", "set-sudo", "prod"], [
            (b"Sudo password (hidden): ", fixture.sudo_password + b"\n"),
        ])
        ordinary = fixture.expect(["prod", "id", "-u"])
        self.assertNotEqual(ordinary["stdout"].strip(), "0")

        arguments = ["--sudo", "prod", "id", "-u"]
        report = fixture.expect(arguments, code=1)
        self.assertEqual(report["error"]["code"], "approval_required")
        approval_id = report["error"].get("approval_id")
        self.assertTrue(approval_id)
        approval = fixture.expect(["approval", "approve", approval_id])
        self.assertTrue(approval["approved"])

        report = fixture.expect(arguments)
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["remote_exit_code"], 0)
        self.assertEqual(report["stdout"].strip(), "0")
        replay = fixture.expect(arguments, code=1)
        self.assertEqual(replay["error"]["code"], "approval_required")
        self.assertNotEqual(replay["error"]["approval_id"], approval_id)
        fixture.assert_no_intentional_secret_file()


class SudoFixture(SshdFixture):
    """Use actual CLI prompts to create Vault; never inject a password via argv."""
    def __init__(self, binary):
        super().__init__(binary)
        self.master = ORIGINAL_MASTER.encode("ascii")
        self.sudo_password = ("TEST-ONLY-real-sshd-sudo-" + secrets.token_hex(18)).encode("ascii")
        self.transcripts = []
        baseline = self.config.read_bytes()
        self.config.unlink()
        self.hidden("real fixture init", ["init", "--lang", "en"], [
            (b"New master password: ", self.master + b"\n"),
            (b"Confirm password: ", self.master + b"\n"),
        ])
        self.config.write_bytes(baseline)
        self.config.chmod(0o600)
        credential_file = self.root / "sudo_credential"
        # bash/su inside the container consumes this input before teardown; the
        # encrypted local Vault receives the same value only through hidden PTY.
        credential_file.write_bytes(b"rxuser:" + self.sudo_password + b"\n")
        credential_file.chmod(0o600)

    def hidden(self, stage, arguments, replies):
        result = PtyCommand(
            str(self.binary), self.config, arguments,
            self.env, self.root, stage, replies,
        ).run()
        self.transcripts.append(result.output)
        return result

    def assert_no_intentional_secret_file(self):
        password = self.sudo_password
        artifacts = [self.config, self.data / "vault.json"]
        audit = self.data / "audit.jsonl"
        if audit.exists():
            artifacts.append(audit)
        for artifact in artifacts:
            contents = artifact.read_bytes()
            if password in contents:
                raise AssertionError("sudo fixture password was stored or audited in plaintext")
        for transcript in self.transcripts:
            if password in transcript:
                raise AssertionError("sudo credential was echoed by the CLI")
        mode = stat.S_IMODE((self.root / "sudo_credential").stat().st_mode)
        if mode != 0o600:
            raise AssertionError("temporary sudo input has unintended file permissions")


if __name__ == "__main__":
    unittest.main(verbosity=2)
