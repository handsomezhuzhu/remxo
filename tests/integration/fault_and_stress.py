#!/usr/bin/env python3
"""Linux integration fault/stress tests using only per-test fake SSH scripts.

No test in this module contacts a real SSH server.  REMXO_BIN must name the
Remxo executable under test.  The broker endpoint file is inspected only for
its numeric PID; its IPC token is never printed or otherwise used by tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor


CONFIG_TEXT = """version = 1

[settings]
allow_ad_hoc = false
timeout_seconds = 2
max_output = 1024
allow_overwrite = false
audit_output = false

[hosts.fake]
number = 1
transport = 'ssh'
ssh_alias = 'alias'
platform = 'linux'
shell = 'posix'
auth = 'openssh-config'
raw_mode = 'allow'
approval = 'never'
insecure_acknowledged = false
"""

MAX_JSON_BYTES = 16 * 1024


def posix_quote(value: str) -> str:
    """Match Remxo's deliberately small POSIX argv quoting rule."""

    return "'{}'".format(value.replace("'", "'\"'\"'"))


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only fake SSH tests")
class FaultAndStressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("REMXO_BIN")
        if not configured:
            raise RuntimeError("REMXO_BIN is required and must name the Remxo executable")
        binary = Path(configured).resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("REMXO_BIN must name an executable file")
        cls.remxo_bin = str(binary)

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="remxo-fault-stress-")
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

        self.home = self._directory("home")
        self.work = self._directory("work")
        self._directory("tmp")
        self._directory("xdg-config")
        self._directory("xdg-cache")
        self._directory("xdg-data")
        self._directory("xdg-state")
        self._directory("xdg-runtime")
        data = self._directory("config")
        self.config = data / "config.toml"
        self.config.write_text(CONFIG_TEXT, encoding="utf-8")
        os.chmod(self.config, 0o600)
        self.broker_path = data / "broker.json"
        self.fake_ssh = self.root / "fake-ssh"

        self.fake_pid_path = self.root / "fake.pid"
        self.fake_counter_path = self.root / "fake.counter"
        self.fake_lock_path = self.root / "fake.lock"
        self.fake_argv_path = self.root / "fake.argv"

        self.env = {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.root / "xdg-config"),
            "XDG_CACHE_HOME": str(self.root / "xdg-cache"),
            "XDG_DATA_HOME": str(self.root / "xdg-data"),
            "XDG_STATE_HOME": str(self.root / "xdg-state"),
            "XDG_RUNTIME_DIR": str(self.root / "xdg-runtime"),
            "TMPDIR": str(self.root / "tmp"),
            "TMP": str(self.root / "tmp"),
            "TEMP": str(self.root / "tmp"),
            "PWD": str(self.work),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "REMXO_SSH": str(self.fake_ssh),
            "REMXO_TEST_FAKE_PID": str(self.fake_pid_path),
            "REMXO_TEST_FAKE_COUNTER": str(self.fake_counter_path),
            "REMXO_TEST_FAKE_LOCK": str(self.fake_lock_path),
            "REMXO_TEST_FAKE_ARGV": str(self.fake_argv_path),
        }

        self.broker_process: subprocess.Popen[bytes] | None = None
        self._broker_generation = 0
        self.addCleanup(self.stop_broker)
        self.start_broker()

    def _directory(self, name: str) -> Path:
        path = self.root / name
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        return path

    def write_fake(self, body: str) -> None:
        self.fake_ssh.write_text(
            "#!/bin/sh\nset -eu\n" + body + "\n",
            encoding="utf-8",
        )
        os.chmod(self.fake_ssh, 0o700)

    def _broker_pid(self) -> int:
        """Read only the numeric PID; never decode, retain, or print the token."""

        data = self.broker_path.read_bytes()
        match = re.search(rb'"pid"\s*:\s*([0-9]+)', data)
        if match is None:
            raise ValueError("broker PID is not available")
        pid = int(match.group(1))
        if pid <= 1:
            raise ValueError("broker PID is invalid")
        return pid

    def start_broker(self) -> None:
        if self.broker_process is not None:
            self.fail("broker start requested while another broker is managed")
        self.broker_path.unlink(missing_ok=True)
        self._broker_generation += 1
        stdout_path = self.root / f"broker-{self._broker_generation}.stdout"
        stderr_path = self.root / f"broker-{self._broker_generation}.stderr"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [self.remxo_bin, "--config", str(self.config), "__broker"],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                cwd=self.work,
                env=self.env,
                close_fds=True,
                start_new_session=True,
            )
        self.broker_process = process

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("fake-test broker exited before becoming ready")
            try:
                endpoint_pid = self._broker_pid()
            except (OSError, ValueError):
                endpoint_pid = None
            if endpoint_pid == process.pid:
                try:
                    completed, status = self._run_json(("status",), timeout=2)
                    if (
                        completed.returncode == 0
                        and status.get("broker_running") is True
                    ):
                        return
                except AssertionError:
                    pass
            time.sleep(0.05)
        self.fail("fake-test broker did not become ready within 10 seconds")

    def stop_broker(self) -> None:
        process = self.broker_process
        if process is None:
            return
        self.broker_process = None
        pid = process.pid

        # The broker was started in its own session, so this group can contain
        # only this test's broker and fake transport descendants.
        if process.poll() is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=3)

        # A forced broker stop does not provide application-level child cleanup.
        # Bound test residue without touching any process outside this session.
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        time.sleep(0.05)
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _run_cli(
        self,
        arguments: tuple[str, ...],
        *,
        options: tuple[str, ...] = (),
        timeout: float = 15,
    ) -> subprocess.CompletedProcess[bytes]:
        # Global options always precede both subcommands and external targets.
        command = [
            self.remxo_bin,
            "--config",
            str(self.config),
            "--json",
            *options,
            *arguments,
        ]
        try:
            return subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.work,
                env=self.env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError(f"CLI did not finish within {timeout:g} seconds") from None

    def _single_json(self, completed: subprocess.CompletedProcess[bytes]) -> dict:
        raw = completed.stdout
        if len(raw) > MAX_JSON_BYTES:
            self.fail(f"JSON output exceeded {MAX_JSON_BYTES} bytes")
        nonempty_lines = [line for line in raw.splitlines() if line.strip()]
        if len(nonempty_lines) != 1:
            self.fail(
                "expected exactly one JSON output line; "
                f"got {len(nonempty_lines)} lines ({len(raw)} bytes)"
            )
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.fail(f"CLI stdout was not one JSON document ({len(raw)} bytes)")
        if not isinstance(value, dict):
            self.fail("CLI JSON document was not an object")
        return value

    def _run_json(
        self,
        arguments: tuple[str, ...],
        *,
        options: tuple[str, ...] = (),
        timeout: float = 15,
    ) -> tuple[subprocess.CompletedProcess[bytes], dict]:
        completed = self._run_cli(arguments, options=options, timeout=timeout)
        return completed, self._single_json(completed)

    @staticmethod
    def error_code(document: dict) -> str | None:
        error = document.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            return error["code"]
        return None

    def assert_no_fixture_secrets(self, stream_name: str, value: str, secrets: tuple[str, ...]) -> None:
        for index, secret in enumerate(secrets):
            self.assertTrue(
                secret not in value,
                f"{stream_name} retained fixture secret #{index + 1}",
            )

    def assert_controls_escaped(self, stream_name: str, value: str) -> None:
        unexpected = sum(
            1 for character in value if ord(character) < 32 and character not in "\n\t"
        )
        self.assertEqual(
            unexpected,
            0,
            f"{stream_name} retained unescaped control characters",
        )

    def read_integer(self, path: Path, description: str) -> int:
        try:
            return int(path.read_text(encoding="ascii").strip())
        except (OSError, UnicodeError, ValueError):
            self.fail(f"{description} did not contain one integer")

    @staticmethod
    def pid_exists(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def wait_for_fake_exit(self, pid: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not self.pid_exists(pid):
                return
            time.sleep(0.05)
        self.fail("fake SSH process remained alive after local termination")

    def task_status(self, task_id: str) -> dict:
        completed, status = self._run_json(("task", "status", task_id))
        self.assertEqual(completed.returncode, 0, "task status command failed")
        return status

    def wait_for_task_state(self, task_id: str, expected: str) -> dict:
        deadline = time.monotonic() + 8
        last_state = "unavailable"
        while time.monotonic() < deadline:
            status = self.task_status(task_id)
            last_state = status.get("state", "missing")
            if last_state == expected:
                return status
            time.sleep(0.05)
        self.fail(f"task did not reach {expected}; last state was {last_state}")

    def test_fake_host_key_exit_255_is_host_key_failed(self) -> None:
        self.write_fake("printf 'Host key verification failed.\\n' >&2\nexit 255")
        completed, report = self._run_json(("fake", "true"))
        self.assertNotEqual(completed.returncode, 0, "host-key failure returned success")
        self.assertEqual(self.error_code(report), "host_key_failed")

    def test_huge_stdout_and_stderr_have_one_bounded_json_error(self) -> None:
        self.write_fake(
            "head -c 262144 /dev/zero | tr '\\000' 'x'\n"
            "head -c 262144 /dev/zero | tr '\\000' 'y' >&2"
        )
        completed, report = self._run_json(
            ("fake", "generate-output"),
            options=("--timeout", "5s", "--max-output", "128"),
            timeout=15,
        )
        self.assertNotEqual(completed.returncode, 0, "output-limit failure returned success")
        self.assertLessEqual(len(completed.stdout), MAX_JSON_BYTES)
        # Both an OperationReport and a top-level output_limit error are valid.
        self.assertEqual(self.error_code(report), "output_limit")
        for stream_name in ("stdout", "stderr"):
            value = report.get(stream_name)
            if value is not None:
                self.assertIsInstance(value, str, f"{stream_name} was not text")
                self.assertLessEqual(
                    len(value.encode("utf-8")),
                    128,
                    f"{stream_name} exceeded the processed-output limit",
                )

    def test_timeout_kills_fake_process_without_hanging_json_report(self) -> None:
        self.write_fake(
            "printf '%s\\n' \"$$\" > \"$REMXO_TEST_FAKE_PID\"\n"
            "printf 'before-timeout-stdout\\n'\n"
            "printf 'before-timeout-stderr\\n' >&2\n"
            "exec sleep 30"
        )
        completed, report = self._run_json(
            ("fake", "sleep", "30"),
            options=("--timeout", "1s"),
            timeout=12,
        )
        self.assertNotEqual(completed.returncode, 0, "timeout returned success")
        self.assertEqual(self.error_code(report), "timeout")
        fake_pid = self.read_integer(self.fake_pid_path, "fake PID file")
        self.wait_for_fake_exit(fake_pid)

    def test_control_characters_pem_and_api_passwords_are_processed_on_both_streams(self) -> None:
        stdout_secrets = (
            "test-only-stdout-pem-body",
            "test-only-stdout-api-secret",
            "test-only-stdout-password",
        )
        stderr_secrets = (
            "test-only-stderr-pem-body",
            "test-only-stderr-api-secret",
            "test-only-stderr-password",
        )
        self.write_fake(
            "printf '%s\\n' '-----BEGIN OPENSSH PRIVATE KEY-----' "
            f"'{stdout_secrets[0]}' '-----END OPENSSH PRIVATE KEY-----'\n"
            f"printf 'api_key={stdout_secrets[1]} password={stdout_secrets[2]} "
            "\\033[2J\\r\\007\\n'\n"
            "printf '%s\\n' '-----BEGIN RSA PRIVATE KEY-----' "
            f"'{stderr_secrets[0]}' '-----END RSA PRIVATE KEY-----' >&2\n"
            f"printf 'api-key={stderr_secrets[1]} passwd={stderr_secrets[2]} "
            "\\033[0m\\r\\007\\n' >&2"
        )
        completed, report = self._run_json(
            ("fake", "emit-sensitive-fixtures"),
            options=("--max-output", "4096"),
        )
        self.assertEqual(completed.returncode, 0, "fake sanitization command failed")
        stdout = report.get("stdout")
        stderr = report.get("stderr")
        self.assertIsInstance(stdout, str, "operation stdout was not text")
        self.assertIsInstance(stderr, str, "operation stderr was not text")
        self.assert_no_fixture_secrets("stdout", stdout, stdout_secrets)
        self.assert_no_fixture_secrets("stderr", stderr, stderr_secrets)
        self.assert_controls_escaped("stdout", stdout)
        self.assert_controls_escaped("stderr", stderr)
        for stream_name, value in (("stdout", stdout), ("stderr", stderr)):
            self.assertTrue(
                "[REDACTED PRIVATE KEY]" in value,
                f"{stream_name} PEM was not redacted",
            )
            self.assertTrue(
                "[REDACTED]" in value,
                f"{stream_name} key/value was not redacted",
            )
            self.assertTrue(
                "\\x1b" in value,
                f"{stream_name} ESC was not escaped",
            )
            self.assertTrue(
                "\\r" in value,
                f"{stream_name} CR was not escaped",
            )
            self.assertTrue(
                "\\u{7}" in value,
                f"{stream_name} BEL was not escaped",
            )

    def test_cwd_and_argument_injection_never_create_a_local_marker(self) -> None:
        marker = self.root / "local-injection-marker"
        malicious_cwd = f"/remote/dir'; touch {marker}; echo '"
        malicious_argument = f"value'; touch {marker}; #"
        self.write_fake("printf '%s\\n' \"$@\" > \"$REMXO_TEST_FAKE_ARGV\"")
        remote_arguments = ("printf", "%s", malicious_argument)
        completed, report = self._run_json(
            ("fake", *remote_arguments),
            options=("--cwd", malicious_cwd),
        )
        self.assertEqual(completed.returncode, 0, "fake quoting command failed")
        self.assertIsNone(report.get("error"), "fake quoting command returned an error")
        try:
            argv = self.fake_argv_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            self.fail("fake SSH did not record its argv")
        expected_script = "cd {} && ({})".format(
            posix_quote(malicious_cwd),
            " ".join(posix_quote(argument) for argument in remote_arguments),
        )
        self.assertGreaterEqual(len(argv), 1, "fake SSH argv did not include a remote script")
        self.assertTrue(
            argv[-1] == expected_script,
            "cwd/arguments were not preserved as one safely quoted remote script",
        )
        self.assertFalse(marker.exists(), "remote-looking injection created a local marker")

    def test_eight_concurrent_json_clients_execute_once_with_unique_request_ids(self) -> None:
        self.write_fake(
            "while ! mkdir \"$REMXO_TEST_FAKE_LOCK\" 2>/dev/null; do sleep 0.01; done\n"
            "count=0\n"
            "if [ -f \"$REMXO_TEST_FAKE_COUNTER\" ]; then\n"
            "  IFS= read -r count < \"$REMXO_TEST_FAKE_COUNTER\"\n"
            "fi\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$REMXO_TEST_FAKE_COUNTER\"\n"
            "rmdir \"$REMXO_TEST_FAKE_LOCK\"\n"
            "printf 'read-ok\\n'"
        )

        def one_request(_: int) -> tuple[subprocess.CompletedProcess[bytes], dict]:
            return self._run_json(("fake", "cat", "registered-input"), timeout=15)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(one_request, range(8)))

        request_ids: list[str] = []
        for index, (completed, report) in enumerate(results):
            self.assertEqual(completed.returncode, 0, f"concurrent request {index + 1} failed")
            self.assertEqual(report.get("status"), "success", f"request {index + 1} was unsuccessful")
            request_id = report.get("request_id")
            self.assertIsInstance(request_id, str, f"request {index + 1} lacked a request ID")
            self.assertTrue(request_id, f"request {index + 1} had an empty request ID")
            request_ids.append(request_id)
        self.assertEqual(len(set(request_ids)), 8, "concurrent request IDs were not unique")
        executions = self.read_integer(self.fake_counter_path, "fake execution counter")
        self.assertLessEqual(executions, 8, "read commands were blindly retried")
        self.assertEqual(executions, 8, "not every successful request reached fake SSH exactly once")

    def test_task_cancel_logs_process_reap_and_broker_restart_locked(self) -> None:
        self.write_fake(
            "printf '%s\\n' \"$$\" > \"$REMXO_TEST_FAKE_PID\"\n"
            "printf 'task-before-wait-stdout\\n'\n"
            "printf 'task-before-wait-stderr\\n' >&2\n"
            "exec sleep 30"
        )
        completed, started = self._run_json(
            ("task", "start", "fake", "--", "sleep", "30"),
            options=("--timeout", "10s"),
        )
        self.assertEqual(completed.returncode, 0, "task start failed")
        task_id = started.get("id")
        self.assertIsInstance(task_id, str, "task start returned no ID")
        self.assertTrue(task_id, "task start returned an empty ID")
        self.wait_for_task_state(task_id, "running")

        deadline = time.monotonic() + 5
        while not self.fake_pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        fake_pid = self.read_integer(self.fake_pid_path, "task fake PID file")
        self.assertTrue(self.pid_exists(fake_pid), "task fake sleep was not running")

        completed, stopping = self._run_json(("task", "stop", task_id))
        self.assertEqual(completed.returncode, 0, "task stop failed")
        self.assertEqual(stopping.get("state"), "cancelling")
        cancelled = self.wait_for_task_state(task_id, "cancelled")
        self.assertIsNotNone(cancelled.get("finished_at"), "cancelled task had no finish time")
        self.wait_for_fake_exit(fake_pid)

        completed, logs = self._run_json(("task", "logs", task_id))
        self.assertEqual(completed.returncode, 0, "cancelled task logs were unavailable")
        self.assertIsInstance(logs.get("stdout"), str, "task stdout log was not text")
        self.assertIsInstance(logs.get("stderr"), str, "task stderr log was not text")
        self.assertLessEqual(len(logs["stdout"].encode("utf-8")), 1024)
        self.assertLessEqual(len(logs["stderr"].encode("utf-8")), 1024)

        completed, second_stop = self._run_json(("task", "stop", task_id))
        self.assertNotEqual(completed.returncode, 0, "stopping a finished task returned success")
        self.assertEqual(self.error_code(second_stop), "invalid_argument")

        _, before_restart = self._run_json(("status",))
        self.assertTrue(before_restart.get("vault_locked"), "vault was not locked before restart")
        old_process = self.broker_process
        self.stop_broker()
        self.assertIsNotNone(old_process, "managed broker disappeared before shutdown")
        self.assertIsNotNone(old_process.returncode, "old broker was not reaped")
        self.start_broker()

        completed, after_restart = self._run_json(("status",))
        self.assertEqual(completed.returncode, 0, "status after broker restart failed")
        self.assertTrue(after_restart.get("broker_running"), "restarted broker was unavailable")
        self.assertTrue(after_restart.get("vault_locked"), "restarted broker did not keep vault locked")
        self.assertEqual(after_restart.get("hosts"), 1)

        completed, missing = self._run_json(("task", "status", task_id))
        self.assertNotEqual(completed.returncode, 0, "task unexpectedly survived broker restart")
        self.assertEqual(self.error_code(missing), "not_found")


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
