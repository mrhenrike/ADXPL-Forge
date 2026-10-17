"""BloodHound data collection via bloodhound-python or SharpHound equivalent."""
from __future__ import annotations
import subprocess, sys, shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.bloodhound_collect.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_query", "smb_session", "rpc_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    collection = getattr(args, "collection", "Default")
    output_dir = getattr(args, "output", ".")

    if not shutil.which("bloodhound-python") and not shutil.which("bloodhound"):
        print("[!] bloodhound-python not found: pip install bloodhound", file=sys.stderr)
        return 1

    bh_cmd = shutil.which("bloodhound-python") or "bloodhound"
    cmd = [
        bh_cmd, "-d", args.domain, "-u", cred.username,
        "-c", collection, "--dns-tcp", "-ns", dc_ip, "--zip",
    ]
    if cred.password:
        cmd.extend(["-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["--hashes", "{}:{}".format(cred.lm_hash, cred.nt_hash)])

    print("[*] BloodHound collection: {} (method: {})".format(args.domain, collection))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=output_dir)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
        else:
            print("[+] BloodHound data collected → {}".format(output_dir))
        return result.returncode
    except Exception as exc:
        print("[-] BloodHound error: {}".format(exc), file=sys.stderr)
        return 1
