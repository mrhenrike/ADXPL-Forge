"""SCCM/MECM enumeration — sites, NAA credentials, collections."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.sccm.sccm_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries", "http_requests"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] SCCM/MECM Enumeration")
    print("[*] Domain: {}".format(cred.domain))

    import subprocess, shutil
    sccmhunter = shutil.which("sccmhunter") or shutil.which("sccmhunter.py")
    if sccmhunter:
        cmd = [sccmhunter, "find", "-u", "{}\\{}".format(cred.domain, cred.username or ""),
               "-p", cred.password or "", "-dc-ip", dc_ip or ""]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] sccmhunter not found")
    print("[*] LDAP enum: search for (objectClass=mSSMSManagementPoint)")
    print("[*] Alternate: SharpSCCM.exe local secretsdump (for NAA creds)")
    return 1
