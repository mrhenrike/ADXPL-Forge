"""ADACLScanner — ACL scanner with comprehensive reporting."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.adacl_scanner.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] ADACLScanner: comprehensive ACL audit")
    print("[*] Domain: {}".format(cred.domain))

    import subprocess
    import shutil
    scanner = shutil.which("ADACLScan.ps1") or shutil.which("adaclscanner")
    if scanner:
        cmd = ["pwsh", "-File", scanner, "-Base",
               "DC={}".format(",DC=".join(cred.domain.split("."))),
               "-Server", dc_ip or cred.domain, "-Output", "HTML"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] ADACLScanner not found")
    print("[*] Alternative: Use bloodyAD or dacl-edit for ACL enumeration")
    return 1
