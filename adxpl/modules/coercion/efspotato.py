"""EfsPotato — MS-EFSR local privesc → SYSTEM (2008-2019)."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.coercion.efspotato.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["privilege_escalation", "token_impersonation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.001"],
}


def run(args: Any) -> int:
    command = getattr(args, "command", None) or "cmd.exe"

    print("[*] EfsPotato: EfsRpc local privilege escalation")
    print("[*] Combines JuicyPotato + PrintSpoofer techniques via MS-EFSR")
    print("[*] Target OS: Windows Server 2008-2019, Windows 7-10")

    print(f"\n[*] Usage: EfsPotato.exe {command}")
    print("[*] Requires: SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege")
    print("[*] Source: https://github.com/zcgonvh/EfsPotato")

    return 0
