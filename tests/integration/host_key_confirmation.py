#!/usr/bin/env python3
"""Isolated CLI human-confirmation binding tests; never uses the real home or network."""
import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import time

import fcntl
import struct
import termios
from pathlib import Path

HOST = "192.0.2.10"
A = "AAAAC3NzaC1lZDI1NTE5AAAAINMQ87JJskPp8Dx9BOCQgB/o/QEfIbo20d6/qzHHWDrP"
B = "AAAAC3NzaC1lZDI1NTE5AAAAIKiL6VQDMroBdzGVw3hYYR91ODaGIT6prxY5CJh99aMY"


def cli(binary: Path, config: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary), "--config", str(config), "--json", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=15,
        check=False,
    )


def close_pty(process: subprocess.Popen, master: int, output: bytearray) -> int:
    while process.poll() is None:
        readable, _, _ = select.select([master], [], [], 15)
        if not readable:
            process.kill()
            raise AssertionError("interactive host-key confirmation timed out")
        try:
            output.extend(os.read(master, 4096))
        except OSError:
            pass
    try:
        while data := os.read(master, 4096):
            output.extend(data)
    except OSError:
        pass
    os.close(master)
    return process.returncode


def interactive_trust(binary: Path, config: Path, env: dict[str, str]) -> bytes:
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [str(binary), "--config", str(config), "host", "key", "trust", "prod"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    while b"Type TRUST" not in bytes(output):
        readable, _, _ = select.select([master], [], [], 15)
        if not readable:
            process.kill()
            close_pty(process, master, output)
            raise AssertionError(f"missing host-key prompt: {output.decode(errors='replace')}")
        try:
            output.extend(os.read(master, 4096))
        except OSError:
            break
    os.write(master, b"TRUST\r")
    status = close_pty(process, master, output)
    if status != 0:
        raise AssertionError(f"stable key trust failed ({status}): {output.decode(errors='replace')}")
    return bytes(output)


def changing_trust(binary: Path, config: Path, env: dict[str, str]) -> tuple[int, bytes]:
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [str(binary), "--config", str(config), "host", "key", "trust", "prod"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    while b"Type TRUST" not in bytes(output):
        readable, _, _ = select.select([master], [], [], 15)
        if not readable:
            process.kill()
            close_pty(process, master, output)
            raise AssertionError(f"missing changing-key prompt: {output.decode(errors='replace')}")
        try:
            output.extend(os.read(master, 4096))
        except OSError:
            break
    os.write(master, b"TRUST\r")
    status = close_pty(process, master, output)
    return status, bytes(output)


def keyscan(path: Path, outputs: list[list[str]]) -> None:
    functions = []
    for index, lines in enumerate(outputs):
        quoted = "\n".join(lines).replace("'", "'\\''")
        functions.append(f"key_{index}() {{\nprintf '%s\\n' '{quoted}'\n}}")
    path.write_text("#!/bin/sh\nset -eu\n[ \"$#\" -eq 5 ] && [ \"$1\" = -p ] && [ \"$2\" = 2222 ] && [ \"$3\" = -T ] && [ \"$4\" = 10 ] && [ \"$5\" = 192.0.2.10 ] || exit 97\n" + "\n".join(functions) + f"""
i=0
if [ -f '{path.with_suffix('.count')}' ]; then IFS= read -r i < '{path.with_suffix('.count')}'; fi
key_"$i"
i=$((i + 1))
if [ "$i" -lt {len(outputs)} ]; then printf '%s\\n' "$i" > '{path.with_suffix('.count')}'; fi
""", encoding="utf-8")
    path.chmod(0o700)


def wizard_reject_changed(binary: Path, env: dict[str, str], home: Path, count: Path) -> None:
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execve(str(binary), [str(binary), "host", "edit", "prod"], env)
        finally:
            os._exit(127)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    output = bytearray()
    reaped = False
    try:
        steps = [
            (b"Fetch host key", b"\x1b[B" * 15 + b"\r"),
            (b"SHA256:Psw7YO69", b"\t\r"),
            (b"Trust rejected a changed host key", None),
        ]
        rejection = b"Trust rejected a changed host key"
        for token, response in steps:
            deadline = time.monotonic() + 15
            while token not in output and rejection not in output:
                readable, _, _ = select.select([master], [], [], 0.05)
                if readable:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        pass
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    reaped = True
                    raise AssertionError(f"wizard exit {status} before {token!r}: {output.decode(errors='replace')[-1800:]}")
                if time.monotonic() >= deadline:
                    raise AssertionError(f"wizard missing {token!r}, keyscans={count.read_text().strip() if count.exists() else '0'}: {output.decode(errors='replace')[-1400:]}")
            if token == b"SHA256:Psw7YO69":
                time.sleep(0.5)
            if rejection in output:
                break
            if response:
                os.write(master, response)
                if token == b"SHA256:Psw7YO69":
                    time.sleep(0.5)
                os.write(master, b"\r")
        assert not (home / ".ssh" / "known_hosts").exists(), "wizard trusted unconfirmed key"
        assert count.read_text().strip() == "2", "confirmation and stable re-fetch should be exactly two keyscans"
    finally:
        if not reaped:
            waited = os.waitpid(pid, os.WNOHANG)[0]
            if waited == 0:
                deadline = time.monotonic() + 2
                while waited == 0 and time.monotonic() < deadline:
                    time.sleep(0.05)
                    waited = os.waitpid(pid, os.WNOHANG)[0]
                if waited == 0:
                    os.kill(pid, 15)
                    time.sleep(0.1)
                    waited = os.waitpid(pid, os.WNOHANG)[0]
                if waited == 0:
                    os.kill(pid, 9)
            if waited == 0:
                os.waitpid(pid, 0)
        try:
            os.close(master)
        except OSError:
            pass
    print(json.dumps({"host_key_confirmation": "wizard-changing", "status": "passed", "isolated_home": True}))


def main() -> None:
    if os.name != "posix":
        print("NOT_RUN: interactive host-key fixtures require POSIX")
        return
    binary = Path(os.environ["REMXO_BIN"]).resolve()
    kind = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="remxo-host-key-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir(mode=0o700)
        config = root / "config.toml"
        config.write_text(
            "version = 1\nsettings = { language = \"en\" }\n"
            f"[hosts.prod]\ntransport = \"ssh\"\nhostname = \"{HOST}\"\nport = 2222\nnumber = 1\n",
            encoding="utf-8",
        )
        scanner = root / ("keyscan-changing" if "changing" in kind else "keyscan-stable")
        outputs = [[f"[{HOST}]:2222 ssh-ed25519 {A}", f"[{HOST}]:2222 ssh-ed25519 {B}"]]
        if kind == "wizard-changing":
            outputs = [[f"[{HOST}]:2222 ssh-ed25519 {A}"], [f"[{HOST}]:2222 ssh-ed25519 {B}"], [f"[{HOST}]:2222 ssh-ed25519 {B}"]]
        elif kind == "changing":
            outputs.append([f"[{HOST}]:2222 ssh-ed25519 {B}"])
            outputs.append(outputs[-1])
        else:
            outputs.append(outputs[0])
            outputs.append(outputs[0])
        keyscan(scanner, outputs)
        env = {key: value for key, value in os.environ.items() if key not in {"REMXO_SSH", "REMXO_SSH_KEYGEN"}}
        known_home = home / "known"
        known_home.mkdir(parents=True, mode=0o700)
        (known_home / ".ssh").mkdir(mode=0o700)
        keygen = root / "ssh-keygen"
        keygen.write_text(f"""#!/bin/sh
set -eu
if [ "$1" = '-F' ] && [ "$#" -eq 4 ] && [ "$3" = '-f' ]; then
    [ "$4" = '{known_home / '.ssh' / 'known_hosts'}' ] || exit 96
    exec /usr/bin/ssh-keygen "$@"
fi
exit 98
""", encoding="utf-8")
        keygen.chmod(0o700)
        if kind == "wizard-changing":
            env.update({
                "HOME": str(known_home),
                "XDG_CONFIG_HOME": str(root / "wizard"),
                "TERM": "xterm",
                "REMXO_SSH_KEYSCAN": str(scanner),
                "REMXO_SSH_KEYGEN": str(keygen),
            })
            (root / "wizard" / "remxo").mkdir(parents=True)
            (root / "wizard" / "remxo" / "config.toml").write_text(config.read_text(encoding="utf-8"), encoding="utf-8")
            wizard_reject_changed(binary, env, known_home, scanner.with_suffix(".count"))
            return
        if kind == "partial":
            known_file = known_home / ".ssh" / "known_hosts"
            known_file.write_text(f"[{HOST}]:2222 ssh-ed25519 {A}\n", encoding="utf-8")
            subprocess.run(["/usr/bin/ssh-keygen", "-H", "-f", str(known_file)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        env.update({"HOME": str(known_home), "REMXO_SSH_KEYSCAN": str(scanner), "REMXO_SSH_KEYGEN": str(keygen)})
        env.pop("REMXO_ASKPASS_CONFIG", None)
        env.pop("REMXO_ASKPASS_TARGET", None)
        if kind == "changing":
            code, output = changing_trust(binary, config, env)
            known = home / ".ssh" / "known_hosts"
            if os.environ.get("REMXO_EXPECT_ORIGINAL_R02_BUG") == "1":
                assert code == 0, f"old bug reproduction returned {code}: {output.decode(errors='replace')}"
                assert known.is_symlink() is False and known.exists(), "old version wrote no fixture key"
                assert B in known.read_text(encoding="utf-8"), "unconfirmed key B was not reproduced"
            else:
                assert code != 0, "changed post-confirmation fetch was trusted"
                assert b"changed after confirmation" in output, output.decode(errors="replace")
                assert not known.exists(), "changed host key reached known_hosts"
        else:
            output = interactive_trust(binary, config, env)
            known = (known_home / ".ssh" / "known_hosts").read_text(encoding="utf-8")
            records = [line.split() for line in known.splitlines()]
            identities = {(record[1], record[2]) for record in records}
            assert identities == {("ssh-ed25519", A), ("ssh-ed25519", B)}, f"unexpected host keys: {known!r}"
            assert len(records) == 2, "duplicate host keys appended"
            if kind == "partial":
                assert b"already known" in output and b"added keys" in output, "partial trust report is not precise"
        print(json.dumps({"host_key_confirmation": kind, "status": "passed", "isolated_home": True}))


if __name__ == "__main__":
    main()
