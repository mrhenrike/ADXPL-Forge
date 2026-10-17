"""ATExec — remote command execution via Windows Task Scheduler."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lateral.atexec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["remote_execution", "scheduled_task_creation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1053.005"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    command = getattr(args, "command", "whoami")

    print("[*] ATExec: Task Scheduler execution on {}".format(target))

    import subprocess, shutil
    atexec = shutil.which("atexec.py") or shutil.which("impacket-atexec")
    if not atexec:
        print("[!] atexec.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [atexec, auth + "@" + (target or ""), command]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
