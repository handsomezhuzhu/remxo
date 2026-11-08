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
from collections.abc import Callable
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
SSH_PASSWORD = "TEST-ONLY-ssh-login-password-63b91d-not-real"
KEY_PASSPHRASE = "TEST-ONLY-private-key-passphrase-52ad7e-not-real"
TEST_PASSWORDS = (
    ORIGINAL_MASTER,
    NEW_MASTER,
    BACKUP_PASSWORD,
    SSH_PASSWORD,
    KEY_PASSPHRASE,
)


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


def _safe_fixture_transcript(transcript: bytes) -> str:
    redacted = transcript[-16000:]
    for password in TEST_PASSWORDS:
        redacted = redacted.replace(password.encode("ascii"), b"<TEST-PASSWORD>")
    terminal_controls = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
    redacted = terminal_controls.sub(b" ", redacted)
    redacted = re.sub(rb"[^\x09\x0a\x0d\x20-\x7e]", b"", redacted)
    return redacted.decode("ascii", "replace")


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
        completion: Callable[[], bool] | None = None,
        with_config: bool = True,
    ) -> None:
        self.binary = binary
        self.arguments = (
            [binary, "--config", str(config), *arguments]
            if with_config
            else [binary, *arguments]
        )
        self.environment = environment
        self.working_directory = working_directory
        self.stage = stage
        self.replies = replies or []
        self.completion = completion

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
                    if self.completion is not None and reply_index == len(self.replies) - 1:
                        if not self.completion():
                            time.sleep(0.02)
                            continue
                    reply = self.replies[reply_index]
                    prompt, response = reply[:2]
                    prompt_at = output.find(prompt, search_offset)
                    if prompt_at < 0:
                        break
                    # Tuple replies are (prompt, response) for hidden input or
                    # (prompt, response, False) for ordinary visible input.
                    if len(reply) == 2 or reply[2]:
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
            raise PhaseFailure(
                f"{failure.stage}; transcript={_safe_fixture_transcript(bytes(output))}",
                failure.exit_code,
                failure.timed_out,
            )
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
            ["init", "--lang", "en"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        if b"New master password: *" not in self.transcripts[-1]:
            raise PhaseFailure("masked password feedback was not rendered", 1)
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

    def test_interactive_chinese_init_keeps_password_hidden(self) -> None:
        self._invoke(
            "interactive Chinese init",
            self.original_config,
            ["init"],
            [
                (b"Select / ", b"2\n", False),
                ("新主密码：".encode("utf-8"), ORIGINAL_MASTER.encode("ascii") + b"\n"),
                ("确认主密码：".encode("utf-8"), ORIGINAL_MASTER.encode("ascii") + b"\n"),
            ],
        )
        saved = self.original_config.read_bytes()
        if b"zh-CN" not in saved:
            raise PhaseFailure("Chinese language was not persisted", 1)
        self._invoke(
            "localized Chinese unlock",
            self.original_config,
            ["unlock"],
            self._password_replies(("主密码：".encode("utf-8"), ORIGINAL_MASTER)),
        )
        if "本地 Broker 中的 Vault 已解锁。".encode("utf-8") not in self.transcripts[-1]:
            raise PhaseFailure("Chinese unlock output was not localized", 1)
        if ORIGINAL_MASTER.encode("ascii") in saved:
            raise PhaseFailure("master password entered configuration", 1)
        for transcript in self.transcripts:
            for password in TEST_PASSWORDS:
                if password.encode("ascii") in transcript:
                    raise PhaseFailure("Chinese init leaked a hidden password", 1)

    def test_host_wizard_saves_valid_host_after_a_fake_connection_check(self) -> None:
        self._invoke(
            "init for host wizard",
            self.original_config,
            ["init", "--lang", "en"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        fake = self.root / "fake-ssh"
        fake.write_text("#!/bin/sh\nprintf 'transport-ready\\n'\n", encoding="utf-8")
        fake.chmod(0o700)
        # The connection check is explicitly against a fake process, never a real host.
        _stop_broker(self.original)
        environment = dict(self.environment)
        environment["REMXO_SSH"] = str(fake)
        result = PtyCommand(
            self.binary,
            self.original_config,
            ["host", "add", "styled", "--interactive"],
            environment,
            self.root,
            "interactive host form",
            [
                (b"styled", b"\x1b[B\x1b[Bexample.invalid" + b"\x1b[B" * 15 + b"\r"),
                (b"", b"\x1b[B\x1b[B\r"),
            ],
            completion=lambda: (self.original / "audit.jsonl").exists(),
        ).run()
        self.transcripts.append(result.output)
        saved = self.original_config.read_text(encoding="utf-8")
        if "[hosts.styled]" not in saved:
            raise PhaseFailure("wizard did not save the host", 1)
        if "example.invalid" not in saved:
            raise PhaseFailure("wizard did not preserve its address", 1)
        doctor = PtyCommand(
            self.binary,
            self.original_config,
            ["doctor", "styled"],
            environment,
            self.root,
            "doctor saved host",
            [],
        ).run()
        self.transcripts.append(doctor.output)
        if b"Connection test passed" not in doctor.output:
            raise PhaseFailure("doctor did not test the registered host", 1)
        if any(ORIGINAL_MASTER.encode("ascii") in transcript for transcript in self.transcripts):
            raise PhaseFailure("wizard leaked master password", 1)
    def test_host_edit_preserves_form_state_and_supports_cursor_editing(self) -> None:
        self._invoke(
            "init for cursor-based host edit",
            self.original_config,
            ["init", "--lang", "en"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        self._invoke(
            "host add for cursor-based edit",
            self.original_config,
            [
                "host", "add", "styled", "--ssh-alias", "fake-test", "--approval", "never",
            ],
        )
        keys = (
            b"\x1b[B\x1b[B"
            + b"\x1b[H\x1b[3~\x1b[F.new"
            + b"\x1b[B" * 17
            + b"\r"
        )
        result = PtyCommand(
            self.binary,
            self.original_config,
            ["host", "edit", "styled"],
            self.environment,
            self.root,
            "cursor-based host edit",
            [(b"styled", keys)],
        ).run()
        self.transcripts.append(result.output)
        saved = self.original_config.read_text(encoding="utf-8")
        if "ake-test.new" not in saved or "fake-test" in saved:
            raise PhaseFailure("host edit did not apply cursor insertion/deletion", 1)
        for transcript in self.transcripts:
            for password in TEST_PASSWORDS:
                if password.encode("ascii") in transcript:
                    raise PhaseFailure("host edit leaked hidden input", 1)

    def test_vault_password_wizard_can_test_then_save_without_leaking(self) -> None:
        self._invoke(
            "init for Vault password wizard",
            self.original_config,
            ["init", "--lang", "en"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        self._invoke(
            "unlock for Vault password wizard",
            self.original_config,
            ["unlock"],
            self._password_replies((b"Master password: ", ORIGINAL_MASTER)),
        )
        fake = self.root / "fake-vault-password-ssh"
        fake.write_text(
            "#!/bin/sh\n"
            "[ \"$REMXO_ASKPASS_TARGET\" = wizardpass ] || exit 41\n"
            "[ -n \"$REMXO_ASKPASS_PENDING_HOST\" ] || exit 42\n"
            "reply=$(\"$SSH_ASKPASS\" \"wizardpass's password: \") || exit 43\n"
            "[ -n \"$reply\" ] || exit 44\n"
            "unset reply\n"
            "printf '%s\\n' \"$REMXO_ASKPASS_TARGET\" \"$SSH_ASKPASS_REQUIRE\" > vault-context\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        environment = dict(self.environment)
        environment["REMXO_SSH"] = str(fake)
        first_keys = (
            b"\x1b[B" * 2
            + b"example.invalid"
            + b"\x1b[B" * 3
            + b"\x1b[C" * 2
            + b"\x1b[B" * 8
            + SSH_PASSWORD.encode("ascii")
            + b"\x1b[B" * 4
            + b"\r"
        )
        result = PtyCommand(
            self.binary,
            self.original_config,
            ["host", "add", "wizardpass", "--interactive"],
            environment,
            self.root,
            "Vault password wizard test then save",
            [
                (b"wizardpass", first_keys),
                (b"", b"\x1b[B\x1b[B\r"),
            ],
            completion=lambda: (self.original / "audit.jsonl").exists(),
        ).run()
        self.transcripts.append(result.output)
        saved = self.original_config.read_bytes()
        if b"[hosts.wizardpass]" not in saved or b"vault-password" not in saved:
            raise PhaseFailure("Vault password wizard did not save Test then Save", 1)
        for artifact in [self.original_config, self.original / "vault.json", self.original / "audit.jsonl"]:
            if SSH_PASSWORD.encode("ascii") in artifact.read_bytes():
                raise PhaseFailure("Vault password was stored in plaintext", 1)
        for transcript in self.transcripts:
            for password in TEST_PASSWORDS:
                if password.encode("ascii") in transcript:
                    raise PhaseFailure("Vault password wizard leaked hidden input", 1)
        context = (self.root / "vault-context").read_text(encoding="ascii")
        if context != "wizardpass\nforce\n":
            raise PhaseFailure("wizard did not use its controlled ASKPASS context", 1)

    def test_vault_key_wizard_imports_path_without_persisting_plaintext_key(self) -> None:
        self._invoke(
            "init for Vault key wizard",
            self.original_config,
            ["init", "--lang", "en"],
            self._password_replies(
                (b"New master password: ", ORIGINAL_MASTER),
                (b"Confirm password: ", ORIGINAL_MASTER),
            ),
        )
        self._invoke(
            "unlock for Vault key wizard",
            self.original_config,
            ["unlock"],
            self._password_replies((b"Master password: ", ORIGINAL_MASTER)),
        )
        source_key = self.root / "id_test_only"
        pem = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "dGVzdC1vbmx5LW5vdC1hLXJlYWwta2V5\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        source_key.write_text(pem, encoding="ascii")
        source_key.chmod(0o600)
        fake = self.root / "fake-vault-key-ssh"
        fake.write_text(
            "#!/bin/sh\n"
            "identity=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = -i ]; then identity=$2; break; fi\n"
            "  shift\n"
            "done\n"
            "[ -n \"$identity\" ] && [ -f \"$identity\" ] || exit 41\n"
            "[ \"$(stat -c %a \"$identity\")\" = 600 ] || exit 42\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        environment = dict(self.environment)
        environment["REMXO_SSH"] = str(fake)
        first_keys = (
            b"\x1b[B" * 2
            + b"example.invalid"
            + b"\x1b[B" * 3
            + b"\x1b[C" * 3
            + b"\x1b[B" * 9
            + b"id_test_only"
            + b"\x1b[B" * 3
            + b"\r"
        )
        result = PtyCommand(
            self.binary,
            self.original_config,
            ["host", "add", "wizardkey", "--interactive"],
            environment,
            self.root,
            "Vault private key wizard test then save",
            [
                (b"wizardkey", first_keys),
                (b"", b"\x1b[B\x1b[B\r"),
            ],
            completion=lambda: (self.original / "audit.jsonl").exists(),
        ).run()
        self.transcripts.append(result.output)
        saved = self.original_config.read_bytes()
        if b"[hosts.wizardkey]" not in saved or b"vault-key" not in saved:
            raise PhaseFailure("Vault key wizard did not save Test then Save", 1)
        if str(source_key).encode("ascii") in saved:
            raise PhaseFailure("private key source path was saved in Host", 1)
        if pem.encode("ascii") in (self.original / "vault.json").read_bytes():
            raise PhaseFailure("private key was stored without encryption", 1)
        runtime = self.original / "runtime"
        if runtime.exists() and any(runtime.iterdir()):
            raise PhaseFailure("temporary wizard private key survived completion", 1)
        if KEY_PASSPHRASE.encode("ascii") in result.output:
            raise PhaseFailure("wizard leaked private key passphrase", 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
