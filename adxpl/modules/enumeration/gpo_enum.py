"""GPO enumeration — list Group Policy Objects and their links."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from adxpl.core.credential import ADCredential
from adxpl.core.ldap_session import connect, get_base_dn


MANIFEST = {
    "capability_id": "adxpl.enumeration.gpo.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1615"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    print(f"[*] GPO enumeration → {args.target} ({args.domain})")

    conn.search(
        base_dn,
        "(objectClass=groupPolicyContainer)",
        attributes=["displayName", "gPCFileSysPath", "gPCMachineExtensionNames",
                     "gPCUserExtensionNames", "whenCreated", "whenChanged"],
        search_scope=2,
        paged_size=1000,
    )

    gpos = [json.loads(e.entry_to_json()) for e in conn.entries]

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"gpo_enum_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(gpos, fh, indent=2, default=str)

    print(f"[+] {len(gpos)} GPOs enumerated → {out_path}")
    return 0
