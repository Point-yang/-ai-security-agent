"""Crash/restart checks ONLY for the zhidu-week6-check Compose project."""

import json
import subprocess
import time
import urllib.request
from pathlib import Path

from zhidu.models import now_utc

NAME = "zhidu-week6-check-api-1"
BASE = "http://127.0.0.1:18000"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def get(path):
    with HTTP.open(BASE + path, timeout=3) as response:
        return response.read().decode()


def ready():
    for _ in range(25):
        try:
            if json.loads(get("/health/ready"))["status"] == "ready":
                return True
        except (OSError, ValueError):
            pass
        time.sleep(1)
    return False


def main():
    info = json.loads(docker("inspect", NAME))[0]
    assert info["Config"]["Labels"]["com.docker.compose.project"] == "zhidu-week6-check"
    checks = {"ready_before": ready()}
    checks["version"] = json.loads(get("/health"))["version"] == "0.9.0"
    # docker cp cannot copy into a read-only rootfs; write only the tmpfs instead.
    subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            NAME,
            "python",
            "-c",
            "import sys; from pathlib import Path; Path('/tmp/week6-fixture.json').write_text(sys.stdin.read())",
        ],
        input=Path("examples/ghsa-demo-v1.json").read_text(),
        text=True,
        check=True,
    )
    first = json.loads(
        docker("exec", NAME, "python", "-m", "zhidu", "import-json", "/tmp/week6-fixture.json")
    )
    second = json.loads(
        docker("exec", NAME, "python", "-m", "zhidu", "import-json", "/tmp/week6-fixture.json")
    )
    checks["import_fixture"] = first["created"] + first["unchanged"] == 1
    checks["deduplication"] = second["unchanged"] == 1
    checks["metrics"] = "zhidu_events_total 1" in get("/metrics")
    checks["operations_page"] = "运行健康与待处理项" in get("/")
    checks["non_root"] = info["Config"]["User"] == "app"
    checks["read_only_rootfs"] = info["HostConfig"]["ReadonlyRootfs"]
    checks["restart_policy"] = info["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
    previous = info["RestartCount"]
    kill_code = (
        "import os,signal; from pathlib import Path; me=os.getpid(); "
        "ids=[int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit() "
        "and int(p.name)!=me and b'zhidu\\x00serve' in (p/'cmdline').read_bytes()]; "
        "assert len(ids)==1,ids; os.kill(ids[0],signal.SIGKILL)"
    )
    # Stopping the main service can terminate this exec as the container exits.
    crash = subprocess.run(
        ["docker", "exec", NAME, "python", "-c", kill_code],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert crash.returncode in {0, 137}, crash.stderr
    time.sleep(1)
    checks["automatic_restart"] = ready()
    checks["restart_count_incremented"] = (
        json.loads(docker("inspect", NAME))[0]["RestartCount"] > previous
    )
    checks["data_survived_api_crash"] = json.loads(get("/health"))["events"] == 1
    report = {
        "checked_at": now_utc().isoformat(),
        "status": "passed" if all(checks.values()) else "failed",
        "project": "zhidu-week6-check",
        "scope": "isolated API + PostgreSQL containers, synthetic replay fixture",
        "checks": checks,
        "image_id": info["Image"],
        "python_base": "public.ecr.aws/docker/library/python:3.12-slim",
        "api_container_build_verified": True,
        "long_running_monitor_sla_verified": False,
    }
    Path("docs/member-a-week6-container-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(checks.values()) else 1)


if __name__ == "__main__":
    main()
