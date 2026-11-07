#!/usr/bin/env python3
"""One-command, self-contained Remxo test driver using only Python's stdlib."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
SUITES = ("checks", "fake", "pty", "real", "sudo")


def execute(label, args, env, timeout=700):
    started = time.monotonic()
    process = subprocess.Popen(
        [str(value) for value in args],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
        else:
            process.kill()
            stdout, stderr = process.communicate()
    return {
        "suite": label,
        "status": "failed" if process.returncode or timed_out else "passed",
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout_tail": stdout[-24_000:].decode("utf-8", "replace"),
        "stderr_tail": stderr[-8_000:].decode("utf-8", "replace"),
    }


def skipped(suite, reason):
    return {"suite": suite, "status": "skipped", "reason": reason, "duration_seconds": 0}


def docker_available(env):
    if shutil.which("docker") is None:
        return False
    process = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
        check=False,
    )
    return process.returncode == 0


def binary():
    name = "remxo.exe" if os.name == "nt" else "remxo"
    return ROOT / "target" / "debug" / name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, help="run only this suite")
    parser.add_argument("--no-real-ssh", action="store_true", help="do not attempt Docker/sshd tests")
    parser.add_argument("--require-real-ssh", action="store_true", help="fail rather than skip when Docker/sshd is unavailable")
    parser.add_argument("--report", type=Path, help="write machine-readable suite results to this path")
    args = parser.parse_args()
    if args.only and args.no_real_ssh:
        parser.error("--no-real-ssh cannot be combined with --only")
    if args.require_real_ssh and args.only and args.only not in ("real", "sudo"):
        parser.error("--require-real-ssh requires --only real or --only sudo")

    requested = (args.only,) if args.only else SUITES
    env = os.environ.copy()
    # No user servers or real SSH/Vault secrets are read by integration fixtures.
    env["REMXO_BIN"] = str(binary())
    if args.require_real_ssh:
        env["REMXO_REQUIRE_REAL_SSH"] = "1"
    else:
        env.pop("REMXO_REQUIRE_REAL_SSH", None)
    results = []

    if "checks" not in requested and not binary().is_file():
        if not shutil.which("cargo"):
            print("target/debug/remxo is missing; run with --only checks first")
            raise SystemExit(2)
        results.append(execute("checks/build", ["cargo", "build"], env))
        if results[-1]["status"] != "passed":
            requested = ()

    for suite in requested:
        if suite == "checks":
            if not shutil.which("cargo"):
                results.append(skipped(suite, "cargo was not found; all Rust checks were NOT_RUN"))
                break
            if not shutil.which("rustfmt"):
                results.append(skipped(suite, "rustfmt was not found; Rust checks were NOT_RUN"))
                break
            for phase, command in (
                ("fmt", ["cargo", "fmt", "--all", "--", "--check"]),
                ("clippy", ["cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]),
                ("unit", ["cargo", "test", "--all-targets", "--", "--test-threads=1"]),
                ("build", ["cargo", "build"]),
            ):
                result = execute("checks/" + phase, command, env)
                results.append(result)
                if result["status"] != "passed":
                    break
            if any(item["suite"].startswith("checks/") and item["status"] != "passed" for item in results):
                break
        elif not sys.platform.startswith("linux"):
            results.append(skipped(suite, "Linux is required for this integration suite"))
        elif suite in ("real", "sudo") and args.no_real_ssh:
            results.append(skipped(suite, "real SSH was explicitly disabled"))
        elif suite in ("real", "sudo") and not docker_available(env):
            results.append(skipped(suite, "Docker daemon unavailable; real SSH tests were NOT_RUN"))
        else:
            scripts = {
                "fake": ["fault_and_stress.py"],
                "pty": ["pty_acceptance.py"],
                "real": ["sshd_acceptance.py", "vault_auth_acceptance.py"],
                "sudo": ["sudo_acceptance.py"],
            }[suite]
            for script in scripts:
                results.append(execute(suite, [sys.executable, ROOT / "tests" / "integration" / script], env))
                if results[-1]["status"] != "passed":
                    break
            if results[-1]["status"] != "passed":
                break

    if any(suite != "checks" for suite in requested) and sys.platform.startswith("linux"):
        results.append(execute("cleanup", [sys.executable, ROOT / "tests" / "integration" / "check_cleanup.py"], env))

    for result in results:
        suffix = " ({0})".format(result["reason"]) if "reason" in result else ""
        print("[{0}] {1}{2}".format(result["status"].upper(), result["suite"], suffix))
        if result.get("status") == "failed":
            print(result.get("stdout_tail", ""))
            print(result.get("stderr_tail", ""), file=sys.stderr)

    summary = {
        "schema_version": 1,
        "results": results,
        "real_credentials_used": False,
        "user_owned_servers_used": False,
        "generated_test_sshd_used": any(result["suite"] in ("real", "sudo") and result["status"] == "passed" for result in results),
        "note": "Only generated process failures were injected. Skips never count as passes.",
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, indent=2) + "\n")
    failed = any(result["status"] == "failed" for result in results)
    if args.require_real_ssh and any(result["suite"] in ("real", "sudo") and result["status"] != "passed" for result in results):
        failed = True
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
