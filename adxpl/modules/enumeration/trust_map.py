"""AD trust enumeration — map inter-domain and inter-forest trusts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from adxpl.core.credential import ADCredential
from adxpl.core.ldap_session import connect, get_base_dn


MANIFEST = {
    "capability_id": "adxpl.enumeration.trust_map.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1482"],
}

TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Windows NT", 2: "AD", 3: "MIT Kerberos", 4: "DCE"}
TRUST_ATTRS = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    print(f"[*] Trust mapping → {args.target} ({args.domain})")

    conn.search(
        base_dn,
        "(objectClass=trustedDomain)",
        attributes=["trustPartner", "trustDirection", "trustType",
                     "trustAttributes", "flatName", "whenCreated"],
        search_scope=2,
        paged_size=100,
    )

    trusts = []
    for entry in conn.entries:
        data = json.loads(entry.entry_to_json())
        attrs = data.get("attributes", {})
        direction = int(attrs.get("trustDirection", [0])[0]) if isinstance(attrs.get("trustDirection"), list) else int(attrs.get("trustDirection", 0))
        ttype = int(attrs.get("trustType", [0])[0]) if isinstance(attrs.get("trustType"), list) else int(attrs.get("trustType", 0))
        tattrs = int(attrs.get("trustAttributes", [0])[0]) if isinstance(attrs.get("trustAttributes"), list) else int(attrs.get("trustAttributes", 0))

        flags = [v for k, v in TRUST_ATTRS.items() if tattrs & k]

        trusts.append({
            "partner": attrs.get("trustPartner", ""),
            "flat_name": attrs.get("flatName", ""),
            "direction": TRUST_DIRECTION.get(direction, f"Unknown({direction})"),
            "type": TRUST_TYPE.get(ttype, f"Unknown({ttype})"),
            "attributes": flags,
            "sid_filtering": "QUARANTINED_DOMAIN" in flags,
        })

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"trust_map_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(trusts, fh, indent=2, default=str)

    print(f"[+] {len(trusts)} trust relationships found → {out_path}")
    for t in trusts:
        sid_flag = " [!SID-FILTER-OFF]" if not t["sid_filtering"] else ""
        print(f"    {args.domain} ←{t['direction']}→ {t['partner']} ({t['type']}) {','.join(t['attributes'])}{sid_flag}")
    return 0
