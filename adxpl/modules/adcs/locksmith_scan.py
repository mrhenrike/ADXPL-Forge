"""Locksmith  -  ADCS vulnerability scanner for ESC1-ESC16."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.adcs.locksmith_scan.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] Locksmith: ADCS vulnerability scanner")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    locksmith = shutil.which("Invoke-Locksmith.ps1") or shutil.which("locksmith")
    certipy = shutil.which("certipy") or shutil.which("certipy-ad")

    if certipy:
        cmd = [certipy, "find", "-vulnerable",
               "-u", "{}@{}".format(cred.username or "", cred.domain)]
        if cred.password:
            cmd += ["-p", cred.password]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    if locksmith:
        print("[*] Using Locksmith PowerShell scanner")
        cmd = ["pwsh", "-File", locksmith]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] Neither certipy nor Locksmith found")
    return 1
