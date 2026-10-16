"""SPN (Service Principal Name) scan — enumerate Kerberoastable accounts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from adxpl.core.credential import ADCredential
from adxpl.core.ldap_session import connect, get_base_dn


MANIFEST = {
    "capability_id": "adxpl.enumeration.spn_scan.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    print(f"[*] SPN scan → {args.target} ({args.domain})")

    conn.search(
        base_dn,
        "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName", "servicePrincipalName", "memberOf", "adminCount", "pwdLastSet"],
        search_scope=2,
        paged_size=1000,
    )

    accounts = []
    for entry in conn.entries:
        data = json.loads(entry.entry_to_json())
        attrs = data.get("attributes", {})
        accounts.append({
            "username": attrs.get("sAMAccountName", [""])[0] if isinstance(attrs.get("sAMAccountName"), list) else attrs.get("sAMAccountName", ""),
            "spns": attrs.get("servicePrincipalName", []),
            "admin": bool(attrs.get("adminCount")),
            "groups": attrs.get("memberOf", []),
        })

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"spn_scan_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(accounts, fh, indent=2, default=str)

    high_value = [a for a in accounts if a["admin"]]
    print(f"[+] {len(accounts)} Kerberoastable accounts found ({len(high_value)} with adminCount=1)")
    print(f"[+] Output: {out_path}")
    return 0
