"""LDAP enumeration — users, groups, SPNs, delegation, password policy."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import ldap3

from adxpl.core.credential import ADCredential
from adxpl.core.ldap_session import connect, get_base_dn


MANIFEST = {
    "capability_id": "adxpl.enumeration.ldap.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002", "T1069.002"],
}


def _search(conn: ldap3.Connection, base_dn: str, filt: str, attrs: list[str]) -> list[dict]:
    conn.search(base_dn, filt, attributes=attrs, search_scope=ldap3.SUBTREE, paged_size=1000)
    return [json.loads(e.entry_to_json()) for e in conn.entries]


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    print(f"[*] LDAP enumeration → {args.target} ({args.domain})")
    results: dict[str, Any] = {}

    results["domain_policy"] = _search(conn, base_dn, "(objectClass=domainDNS)", [
        "minPwdLength", "lockoutThreshold", "lockoutDuration",
        "pwdHistoryLength", "maxPwdAge", "minPwdAge",
    ])

    results["users"] = _search(conn, base_dn, "(&(objectClass=user)(objectCategory=person))", [
        "sAMAccountName", "userPrincipalName", "memberOf",
        "userAccountControl", "lastLogon", "pwdLastSet", "adminCount",
        "servicePrincipalName", "msDS-AllowedToDelegateTo",
    ])

    results["admins"] = _search(conn, base_dn,
        "(&(objectClass=user)(adminCount=1))",
        ["sAMAccountName", "memberOf", "userAccountControl"],
    )

    results["spn_accounts"] = _search(conn, base_dn,
        "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))",
        ["sAMAccountName", "servicePrincipalName", "memberOf"],
    )

    results["asrep_vulnerable"] = _search(conn, base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        ["sAMAccountName", "userPrincipalName"],
    )

    results["unconstrained_delegation"] = _search(conn, base_dn,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        ["sAMAccountName", "dNSHostName"],
    )

    results["constrained_delegation"] = _search(conn, base_dn,
        "(msDS-AllowedToDelegateTo=*)",
        ["sAMAccountName", "msDS-AllowedToDelegateTo"],
    )

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"ldap_enum_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    print(f"[+] {len(results['users'])} users, {len(results['admins'])} admins, "
          f"{len(results['spn_accounts'])} SPN accounts, "
          f"{len(results['asrep_vulnerable'])} AS-REP vulnerable")
    print(f"[+] Output: {out_path}")
    return 0
