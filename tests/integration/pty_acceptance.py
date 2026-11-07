#!/usr/bin/env python3
"""Linux PTY acceptance coverage for the Remxo CLI.

Run with REMXO_BIN set to the executable under test. Every path and every
credential used by this test is temporary and test-only. Captured terminal
output is retained solely for in-memory secret checks and is never printed.
"""

from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import sys
import tempfile
import termios
import time
import unittest


COMMAND_TIMEOUT_SECONDS = 20.0
ORIGINAL_MASTER = "TEST-ONLY-original-master-6f8d2a-not-real"
NEW_MASTER = "TEST-ONLY-replacement-master-91c4be-not-real"
BACKUP_PASSWORD = "TEST-ONLY-backup-password-37a5d0-not-real"
TEST_PASSWORDS = (ORIGINAL_MASTER, NEW_MASTER, BACKUP_PASSWORD)


class PhaseFailure(AssertionError):
    """A failure whose representation can never disclose terminal contents."""

    def __init__(self, stage: str, exit_code: int, timed_out: bool = False) -> None:
        self.stage = stage
        self.exit_code = exit_code
        self.timed_out = timed_out
        outcome = "timed out" if timed_out else "failed"
        super().__init__(f"{stage} {outcome}; exit code {exit_code}")


class CommandTimeout(Exception):
    pass


class PtyResult:
    def __init__(self, exit_code: int, output: bytes) -> None:
        self.exit_code = exit_code
        self.output = output


def _exit_code(wait_status: int | None) -> int:
    if wait_status is None:
        return 1
    if os.WIFEXITED(wait_status):
        return os.WEXITSTATUS(wait_status)
    if os.WIFSIGNALED(wait_status):
        return 128 + os.WTERMSIG(wait_status)
    return 1


def _poll_child(pid: int) -> int | None:
    try:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return 0
    return status if waited_pid == pid else None


def _signal_pty_session(pid: int) -> None:
    """Kill only the process group created by pty.fork for this command."""
    try:
        os.killpg(pid, signal.SIGKILL)
        return
    except ProcessLookupError:
        pass
    except PermissionError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _kill_and_reap(pid: int, wait_status: int | None) -> int | None:
    if wait_status is not None:
        return wait_status
    _signal_pty_session(pid)
    try:
        _, status = os.waitpid(pid, 0)
        return status
    except ChildProcessError:
        return 0


def _write_all(fd: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        try:
            written += os.write(fd, data[written:])
        except InterruptedError:
            continue


def _wait_for_echo_off(fd: int, deadline: float) -> None:
    """Wait for hidden-prompt mode rather than racing its termios transition."""
    while True:
        try:
            local_flags = termios.tcgetattr(fd)[3]
        except (OSError, termios.error):
            raise CommandTimeout() from None
        if local_flags & termios.ECHO == 0:
            return
        if time.monotonic() >= deadline:
            raise CommandTimeout()
        time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))


class PtyCommand:
    """One bounded CLI invocation with ordered, prompt-driven replies."""

    def __init__(
        self,
        binary: str,
        config: Path,
        arguments: list[str],
        environment: dict[str, str],
        working_directory: Path,
        stage: str,
        replies: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        self.binary = binary
        self.arguments = [binary, "--config", str(config), *arguments]
        self.environment = environment
        self.working_directory = working_directory
        self.stage = stage
        self.replies = replies or []

    def run(self) -> PtyResult:
        try:
            pid, master_fd = pty.fork()
        except OSError:
            raise PhaseFailure(self.stage, 127) from None

        if pid == 0:
            try:
                os.chdir(self.working_directory)
                os.execve(self.binary, self.arguments, self.environment)
            except BaseException:
                # Do not print an exception: the terminal stream must stay safe.
                os._exit(127)

        output = bytearray()
        wait_status: int | None = None
        reply_index = 0
        search_offset = 0
        reached_eof = False
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
        failure: PhaseFailure | None = None

        try:
            # openpty commonly starts with a zero-sized window, which is not
            # suitable for a fullscreen TUI.
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))

            while True:
                if wait_status is None:
                    wait_status = _poll_child(pid)
                if reached_eof and wait_status is not None:
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CommandTimeout()

                if reached_eof:
                    time.sleep(min(0.01, remaining))
                    continue

                readable, _, _ = select.select(
                    [master_fd], [], [], min(0.05, remaining)
                )
                if not readable:
                    continue
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        chunk = b""
                    elif error.errno == errno.EINTR:
                        continue
                    else:
                        raise
                if not chunk:
                    reached_eof = True
                    continue

                output.extend(chunk)
                while reply_index < len(self.replies):
                    prompt, response = self.replies[reply_index]
                    prompt_at = output.find(prompt, search_offset)
                    if prompt_at < 0:
                        break
                    _wait_for_echo_off(master_fd, deadline)
                    _write_all(master_fd, response)
                    search_offset = prompt_at + len(prompt)
                    reply_index += 1

            exit_code = _exit_code(wait_status)
            if reply_index != len(self.replies) or exit_code != 0:
                failure = PhaseFailure(self.stage, exit_code)
        except CommandTimeout:
            wait_status = _kill_and_reap(pid, wait_status)
            failure = PhaseFailure(
                self.stage, _exit_code(wait_status), timed_out=True
            )
        except PhaseFailure as error:
            failure = error
        except Exception:
            wait_status = _kill_and_reap(pid, wait_status)
            failure = PhaseFailure(self.stage, _exit_code(wait_status))
        finally:
            if failure is not None:
                wait_status = _kill_and_reap(pid, wait_status)
            try:
                os.close(master_fd)
            except OSError:
                pass
            if wait_status is None:
                wait_status = _kill_and_reap(pid, wait_status)

        if failure is not None:
            raise failure
        return PtyResult(_exit_code(wait_status), bytes(output))


def _broker_pid(path: Path) -> int | None:
    """Extract only the numeric pid; never deserialize, print, or store a token."""
    try:
        with path.open("rb") as broker_file:
            contents = broker_file.read(65537)
    except OSError:
        return None
    if len(contents) > 65536:
        return None
    matches = re.findall(rb'"pid"\s*:\s*([0-9]+)', contents)
    if len(matches) != 1:
        return None
    try:
        pid = int(matches[0])
    except ValueError:
        return None
    if pid <= 1 or pid == os.getpid():
        return None
    return pid


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _stop_broker(data_directory: Path) -> None:
    pid = _broker_pid(data_directory / "broker.json")
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        return

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux PTY support required")
class RemxoPtyAcceptanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        binary_value = os.environ.get("REMXO_BIN")
        if not binary_value:
            raise PhaseFailure("setup", 127)
        try:
            binary = Path(binary_value).expanduser().resolve(strict=True)
        except OSError:
            raise PhaseFailure("setup", 127) from None
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise PhaseFailure("setup", 127)
        cls.binary = str(binary)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="remxo-pty-acceptance-")
        self.addCleanup(self._cleanup)
        self.root = Path(self.temporary.name)
        self.original = self.root / "original"
        self.restored = self.root / "restored"
        self.original_config = self.original / "config.toml"
        self.restored_config = self.restored / "config.toml"
        self.backup = self.root / "test.rxb"

        self.home = self.root / "home"
        self.xdg_config = self.root / "xdg-config"
        self.temporary_files = self.root / "tmp"
        self.runtime = self.root / "runtime"
        for directory in (
            self.home,
            self.xdg_config,
            self.temporary_files,
            self.runtime,
        ):
            directory.mkdir(mode=0o700)

        # Do not inherit SSH agents, credential variables, or the real home.
        self.environment = {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.xdg_config),
            "XDG_RUNTIME_DIR": str(self.runtime),
            "TMPDIR": str(self.temporary_files),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "xterm-256color",
            "NO_COLOR": "1",
        }
        self.transcripts: list[bytes] = []

    def _cleanup(self) -> None:
        try:
            _stop_broker(self.original)
            _stop_broker(self.restored)
        finally:
            try:
                self.temporary.cleanup()
            except OSError:
                pass

    def _invoke(
        self,
        stage: str,
        config: Path,
        arguments: list[str],
        replies: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        print(f"[pty-acceptance] {stage}", flush=True)
        result = PtyCommand(
            self.binary,
            config,
            arguments,
            self.environment,
            self.root,
            stage,
            replies,
        ).run()
        self.transcripts.append(result.output)

    @staticmethod
    def _password_replies(*entries: tuple[bytes, str]) -> list[tuple[bytes, bytes]]:
        return [(prompt, password.encode("ascii") + b"\n") for prompt, password in entries]

    def test_complete_hidden_password_and_tui_flow(self) -> None:
        self._invoke(
            "init",
            self.original_config,
            ["init"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        self._invoke(
            "host add",
            self.original_config,
            [
                "host",
                "add",
                "prod",
                "--ssh-alias",
                "fake-test",
                "--number",
                "1",
                "--approval",
                "never",
            ],
        )
        self._invoke(
            "initial unlock",
            self.original_config,
            ["unlock"],
            self._password_replies((b"Master password: ", ORIGINAL_MASTER)),
        )
        self._invoke(
            "backup create",
            self.original_config,
            ["backup", "create", str(self.backup)],
            self._password_replies(
                (b"New backup password: ", BACKUP_PASSWORD),
                (b"Confirm password: ", BACKUP_PASSWORD),
            ),
        )
        self._invoke(
            "backup verify",
            self.original_config,
            ["backup", "verify", str(self.backup)],
            self._password_replies((b"Backup password: ", BACKUP_PASSWORD)),
        )
        self._invoke(
            "backup restore",
            self.restored_config,
            ["backup", "restore", str(self.backup)],
            self._password_replies((b"Backup password: ", BACKUP_PASSWORD)),
        )
        self._invoke(
            "vault change-password",
            self.original_config,
            ["vault", "change-password"],
            self._password_replies(
                (b"Current master password: ", ORIGINAL_MASTER),
                (b"New master password: ", NEW_MASTER),
                (b"Confirm password: ", NEW_MASTER),
            ),
        )
        self._invoke("lock", self.original_config, ["lock"])
        self._invoke(
            "unlock with replacement master",
            self.original_config,
            ["unlock"],
            self._password_replies((b"Master password: ", NEW_MASTER)),
        )
        self._invoke(
            "restored unlock with original master",
            self.restored_config,
            ["unlock"],
            self._password_replies((b"Master password: ", ORIGINAL_MASTER)),
        )
        self._invoke(
            "explicit TUI",
            self.original_config,
            ["tui"],
            [(b"Remxo", b"q")],
        )

        required_artifacts = (
            self.original_config,
            self.original / "vault.json",
            self.backup,
            self.restored_config,
            self.restored / "vault.json",
        )
        optional_audits = (
            self.original / "audit.jsonl",
            self.restored / "audit.jsonl",
        )
        encoded_passwords = tuple(password.encode("ascii") for password in TEST_PASSWORDS)
        for artifact in required_artifacts + optional_audits:
            try:
                contents = artifact.read_bytes()
            except FileNotFoundError:
                continue
            if any(password in contents for password in encoded_passwords):
                raise PhaseFailure("secret hygiene artifact {0}".format(artifact.name), 1)
        for index, transcript in enumerate(self.transcripts):
            if any(password in transcript for password in encoded_passwords):
                sanitized = transcript
                for password in encoded_passwords:
                    sanitized = sanitized.replace(password, b"<TEST-PASSWORD>")
                # No real/user data is present in these fixtures. Repr keeps control characters
                # escaped while retaining only password-free diagnostic output.
                raise PhaseFailure(
                    "secret hygiene transcript {0}: {1!r}".format(index, sanitized[-8000:]), 1
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
