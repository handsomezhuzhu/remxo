#!/usr/bin/env python3
"""Self-contained, real-OpenSSH integration tests; no user servers or credentials."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

DOCKERFILE = r'''FROM alpine:3.22
RUN apk add --no-cache openssh-server openssh-sftp-server socat bash sudo \
    && adduser -D -s /bin/sh rxuser \
    && passwd -d rxuser \
    && printf 'rxuser ALL=(root) /usr/bin/id, /bin/sh\n' > /etc/sudoers.d/rxuser \
    && chmod 600 /etc/sudoers.d/rxuser
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
'''

ENTRYPOINT = r'''#!/bin/sh
set -eu
install -d -m 700 -o rxuser -g rxuser /home/rxuser/.ssh
install -m 600 -o rxuser -g rxuser /test/id_ed25519.pub /home/rxuser/.ssh/authorized_keys
if [ -f /test/sudo_credential ]; then
    chpasswd < /test/sudo_credential
fi
exec /usr/sbin/sshd -D -e -f /test/sshd_config
'''


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def run(args, env=None, timeout=25):
    return subprocess.run(
        [str(value) for value in args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
        check=False,
    )


class SshdFixture:
    def __init__(self, binary):
        self.binary = Path(binary)
        self.dir = tempfile.TemporaryDirectory(prefix="remxo-real-sshd-")
        self.root = Path(self.dir.name)
        self.home = self.root / "home"
        self.config_home = self.home / ".config"
        self.ssh_home = self.home / ".ssh"
        self.data = self.root / "data"
        for directory in (self.home, self.config_home, self.ssh_home, self.data):
            directory.mkdir(mode=0o700)
        self.name = "remxo-test-" + secrets.token_hex(10)
        self.image = "remxo-test-sshd:" + secrets.token_hex(8)
        self.port = free_port()
        self.container = None
        self.config = self.data / "config.toml"
        self.known_hosts = self.root / "known_hosts"
        self.openssh_config = self.ssh_home / "config"
        self.env = os.environ.copy()
        self.env.update({"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.config_home)})
        self.env.pop("SSH_AUTH_SOCK", None)
        self.keygen("ssh_host_ed25519_key")
        self.keygen("id_ed25519")
        image_dir = self.root / "image"
        image_dir.mkdir()
        (image_dir / "Dockerfile").write_text(DOCKERFILE)
        (image_dir / "entrypoint.sh").write_text(ENTRYPOINT)
        (image_dir / "entrypoint.sh").chmod(0o755)
        config = """
ListenAddress 127.0.0.1
Port {port}
HostKey /test/ssh_host_ed25519_key
PidFile /tmp/remxo-test-sshd.pid
UsePAM no
AllowUsers rxuser
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
AllowTcpForwarding yes
PermitTTY yes
StrictModes yes
LogLevel VERBOSE
Subsystem sftp internal-sftp
""".format(port=self.port)
        (self.root / "sshd_config").write_text(config.lstrip())
        target = "[127.0.0.1]:{0}".format(self.port)
        host_key = (self.root / "ssh_host_ed25519_key.pub").read_text().split()
        self.known_hosts.write_text("{0} {1} {2}\n".format(target, host_key[0], host_key[1]))
        self.known_hosts.chmod(0o600)
        self.openssh_config.write_text(
            "Host remxo-test\n"
            "  HostName 127.0.0.1\n"
            "  Port {0}\n"
            "  User rxuser\n"
            "  IdentityFile {1}/id_ed25519\n"
            "  IdentitiesOnly yes\n"
            "  IdentityAgent none\n"
            "  UserKnownHostsFile {1}/known_hosts\n"
            "  StrictHostKeyChecking yes\n"
            "  BatchMode yes\n"
            "  ForwardAgent no\n".format(self.port, self.root)
        )
        for variable, executable in (("REMXO_SSH", "/usr/bin/ssh"), ("REMXO_SCP", "/usr/bin/scp")):
            wrapper = self.root / (variable.lower() + "-with-config")
            wrapper.write_text(
                "#!{0}\nimport os\nimport sys\n"
                "os.execv({1!r}, [{1!r}, '-F', {2!r}] + sys.argv[1:])\n".format(
                    sys.executable, executable, str(self.openssh_config)
                )
            )
            wrapper.chmod(0o700)
            self.env[variable] = str(wrapper)
        (self.config).write_text(
            "version = 1\n\n"
            "[settings]\n"
            "allow_ad_hoc = false\n"
            "timeout_seconds = 15\n"
            "max_output = 1048576\n"
            "allow_overwrite = false\n"
            "audit_output = false\n\n"
            "[hosts.prod]\n"
            "number = 1\n"
            "transport = 'ssh'\n"
            "ssh_alias = 'remxo-test'\n"
            "platform = 'linux'\n"
            "shell = 'posix'\n"
            "auth = 'openssh-config'\n"
            "environment = 'test'\n"
            "tags = []\n"
            "raw_mode = 'allow'\n"
            "approval = 'never'\n"
            "insecure_acknowledged = false\n"
        )
        self.config.chmod(0o600)

    def keygen(self, name):
        result = run([
            "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "remxo-test",
            "-f", self.root / name,
        ], timeout=15)
        if result.returncode:
            raise RuntimeError("test key generation failed with exit code {0}".format(result.returncode))
        (self.root / name).chmod(0o600)

    def docker(self, args, timeout=25, check=True):
        result = run(["docker"] + list(args), timeout=timeout)
        if check and result.returncode:
            raise RuntimeError("docker operation failed with exit code {0}".format(result.returncode))
        return result

    def start(self):
        self.docker(["info", "--format", "{{.ServerVersion}}"], timeout=20)
        self.docker(["build", "--quiet", "--tag", self.image, str(self.root / "image")], timeout=360)
        result = self.docker([
            "run", "--detach", "--name", self.name, "--network", "host",
            "--volume", "{0}:/test:ro".format(self.root), self.image,
        ], timeout=30)
        self.container = result.stdout.decode().strip()
        last_error = None
        for _ in range(100):
            check = run([
                "ssh", "-F", self.openssh_config, "-T", "remxo-test", "true"
            ], env=self.env, timeout=3)
            if check.returncode == 0:
                return
            last_error = check.returncode
            time.sleep(0.1)
        raise RuntimeError("real sshd did not become ready (last exit {0})".format(last_error))

    def remxo(self, args, timeout=25):
        return run([self.binary, "--config", self.config, "--json"] + list(args), env=self.env, timeout=timeout)

    def expect(self, args, code=0, timeout=25):
        process = self.remxo(args, timeout=timeout)
        try:
            document = json.loads(process.stdout)
        except (ValueError, UnicodeDecodeError) as error:
            raise AssertionError("invalid single JSON document") from error
        self.assert_code(process.returncode, code, document)
        return document

    @staticmethod
    def assert_code(actual, expected, document):
        if actual != expected:
            error = document.get("error")
            raise AssertionError("exit {0} != {1}, error={2}".format(actual, expected, error))

    def docker_exec(self, args, check=True):
        return self.docker(["exec", self.name] + list(args), check=check)

    def stop_broker(self):
        endpoint = self.data / "broker.json"
        try:
            pid = int(json.loads(endpoint.read_text()).get("pid", 0))
            if pid > 0:
                os.kill(pid, 15)
        except (FileNotFoundError, ProcessLookupError, ValueError, KeyError, TypeError):
            pass

    def close(self):
        self.stop_broker()
        if self.container:
            self.docker(["rm", "-f", self.name], check=False)
        if self.image:
            self.docker(["image", "rm", self.image], check=False)
        self.dir.cleanup()


class RealSshAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get("REMXO_BIN")
        if not binary:
            raise unittest.SkipTest("REMXO_BIN was not set; real SSH tests were not run")
        cls.fixture = SshdFixture(binary)
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

    def assert_no_remote_file(self, path):
        result = self.fixture.docker_exec(["test", "!", "-e", path], check=False)
        self.assertEqual(result.returncode, 0, "unexpected remote marker exists")

    def test_01_exec_cwd_injection_and_ssh_failures(self):
        fixture = self.fixture
        payload = "hello;$(touch /tmp/remxo-arg-pwned);' \" spaces"
        report = fixture.expect(["prod", "printf", "%s", payload])
        self.assertEqual(report["stdout"], payload)
        self.assert_no_remote_file("/tmp/remxo-arg-pwned")

        unusual = "/tmp/work '; touch /tmp/remxo-cwd-pwned; echo '"
        fixture.docker_exec(["mkdir", "-p", "--", unusual])
        report = fixture.expect(["--cwd", unusual, "prod", "pwd"])
        self.assertIn(unusual, report["stdout"])
        self.assert_no_remote_file("/tmp/remxo-cwd-pwned")
        report = fixture.expect(["prod", "pwd"])
        self.assertIn("/home/rxuser", report["stdout"])
        report = fixture.expect(["prod", "--profile", "disk"])
        self.assertTrue(report["stdout"].strip())

        good_hosts = fixture.known_hosts.read_bytes()
        wrong = (fixture.root / "id_ed25519.pub").read_text().split()
        fixture.known_hosts.write_text("[127.0.0.1]:{0} {1} {2}\n".format(fixture.port, wrong[0], wrong[1]))
        fixture.known_hosts.chmod(0o600)
        report = fixture.expect(["prod", "true"], code=1)
        self.assertEqual(report["error"]["code"], "host_key_failed")
        fixture.known_hosts.write_bytes(good_hosts)
        fixture.known_hosts.chmod(0o600)
        fixture.expect(["prod", "true"])
        fixture.stop_broker()
        time.sleep(0.1)

    def test_02_real_sftp_roundtrip_special_paths_and_overwrite(self):
        fixture = self.fixture
        content = bytes(range(256)) * 32 + b"remxo-real-sftp\x00\xff"
        upload = fixture.root / "upload.bin"
        download = fixture.root / "download.bin"
        upload.write_bytes(content)
        remote = "/tmp/remxo $(touch remxo-sftp-pwned); ' data.bin"
        fixture.expect(["put", upload, "prod:" + remote])
        self.assert_no_remote_file("/tmp/remxo-sftp-pwned")
        fixture.expect(["get", "prod:" + remote, download])
        self.assertEqual(hashlib.sha256(content).digest(), hashlib.sha256(download.read_bytes()).digest())
        report = fixture.expect(["put", upload, "prod:" + remote], code=1)
        self.assertEqual(report["error"]["code"], "policy_denied")
        before = download.read_bytes()
        report = fixture.expect(["get", "prod:" + remote, download], code=1)
        self.assertEqual(report["error"]["code"], "policy_denied")
        self.assertEqual(download.read_bytes(), before)
        fixture.expect(["--overwrite", "put", upload, "prod:" + remote])
        fixture.stop_broker()
        time.sleep(0.1)

    def test_03_real_tunnel_lifecycle_and_port_conflict(self):
        fixture = self.fixture
        service_port = free_port()
        fixture.docker(["exec", "-d", fixture.name, "socat",
                        "TCP-LISTEN:{0},bind=127.0.0.1,reuseaddr,fork".format(service_port),
                        "EXEC:/bin/cat"])
        local_port = free_port()
        tunnel = fixture.expect(["tunnel", "start", "prod", "--local",
                                 "{0}:127.0.0.1:{1}".format(local_port, service_port)])
        connected = None
        for _ in range(80):
            try:
                connected = socket.create_connection(("127.0.0.1", local_port), timeout=0.2)
                break
            except OSError:
                time.sleep(0.05)
        self.assertIsNotNone(connected, "local forward did not open")
        connected.sendall(b"through-real-ssh\n")
        connected.settimeout(3)
        received = connected.recv(128)
        connected.close()
        self.assertEqual(received, b"through-real-ssh\n")
        tunnel_id = tunnel["id"]
        fixture.expect(["tunnel", "stop", tunnel_id])
        report = fixture.expect(["tunnel", "start", "prod", "--local",
                                 "0.0.0.0:{0}:127.0.0.1:{1}".format(free_port(), service_port)], code=2)
        self.assertEqual(report["error"]["code"], "policy_denied")

        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            conflict_port = occupied.getsockname()[1]
            report = fixture.expect(["tunnel", "start", "prod", "--local",
                                     "{0}:127.0.0.1:{1}".format(conflict_port, service_port)],
                                    code=2, timeout=30)
            self.assertEqual(report["error"]["code"], "connection_failed")
        fixture.stop_broker()
        time.sleep(0.1)

    def test_04_real_task_completion_cancel_and_no_retry(self):
        fixture = self.fixture
        script = "for i in 1 2 3; do printf '%s ' \"$i\"; sleep 1; done"
        task = fixture.expect(["task", "start", "prod", "--", script])
        task_id = task["id"]
        summary = None
        for _ in range(80):
            summary = fixture.expect(["task", "status", task_id])
            if summary["state"] == "succeeded":
                break
            time.sleep(0.1)
        self.assertEqual(summary["state"], "succeeded")
        self.assertEqual(summary["remote_exit_code"], 0)
        logs = fixture.expect(["task", "logs", task_id])
        self.assertEqual(logs["stdout"], "1 2 3 ")
        task = fixture.expect(["--timeout", "30s", "task", "start", "prod", "--", "sleep 30"])
        task_id = task["id"]
        stopped = fixture.expect(["task", "stop", task_id])
        self.assertIn(stopped["state"], ("cancelling", "cancelled", "running"))
        for _ in range(30):
            summary = fixture.expect(["task", "status", task_id])
            if summary["state"] == "cancelled":
                break
            time.sleep(0.1)
        self.assertEqual(summary["state"], "cancelled")
        fixture.stop_broker()
        time.sleep(0.1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
