#!/usr/bin/env python3
"""Report test remnants on a dedicated Remxo test worker. Never kill anything."""
import json
from pathlib import Path
import subprocess
import sys


def remxo_processes():
    found = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() == "remxo":
                found.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
            continue
    return sorted(found)


def docker_names(arguments):
    try:
        process = subprocess.run(
            ["docker"] + arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
    except FileNotFoundError:
        return ["DOCKER_UNAVAILABLE"]
    if process.returncode:
        return ["DOCKER_QUERY_FAILED"]
    return process.stdout.decode("utf-8", "replace").splitlines()


def main():
    report = {
        "remxo_process_pids": remxo_processes(),
        "test_containers": docker_names(["ps", "--filter", "name=remxo-test-", "--format", "{{.Names}}"]),
        "test_images": docker_names(["image", "ls", "--filter=reference=remxo-test-sshd", "--format", "{{.Repository}}:{{.Tag}}"]),
        "note": "Read-only check on a dedicated test worker; no process or Docker object was killed or removed.",
    }
    print(json.dumps(report, sort_keys=True))
    clean = not any(report[key] for key in ("remxo_process_pids", "test_containers", "test_images"))
    raise SystemExit(0 if clean else 1)


if __name__ == "__main__":
    main()
