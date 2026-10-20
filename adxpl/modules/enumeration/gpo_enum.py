"""GPO enumeration — list GPOs, linked OUs, and abuse paths."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.gpo_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1615"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)

    print(f"[*] GPO enumeration → {dc_ip}")
    try:
        from impacket.ldap import ldap as imp_ldap
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        conn = imp_ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)

        entries = conn.search(
            searchBase=base_dn,
            searchFilter="(objectClass=groupPolicyContainer)",
            attributes=["cn", "displayName", "gPCFileSysPath", "flags"],
        )
        gpos = []
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                attrs = entry["attributes"]
                gpos.append({
                    "guid": str(attrs.get("cn", "")),
                    "name": str(attrs.get("displayName", "")),
                    "path": str(attrs.get("gPCFileSysPath", "")),
                    "flags": str(attrs.get("flags", "")),
                })

        print(f"[+] Found {len(gpos)} GPOs:")
        for g in gpos:
            status = "enabled" if g["flags"] == "0" else "disabled"
            print("  {} — {} [{}]".format(g["guid"], g["name"], status))
        return 0
    except Exception as exc:
        print(f"[-] GPO enum error: {exc}", file=sys.stderr)
        return 1
