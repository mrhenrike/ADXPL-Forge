"""Delegation enumeration  -  unconstrained, constrained, RBCD detection."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.delegation_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)

    print(f"[*] Delegation enumeration → {dc_ip}")
    try:
        from impacket.ldap import ldap as imp_ldap
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        conn = imp_ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)

        print("\n=== Unconstrained Delegation ===")
        entries = conn.search(searchBase=base_dn,
            searchFilter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            attributes=["sAMAccountName", "dNSHostName"])
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                print("  [!] {} ({})".format(
                    entry["attributes"].get("sAMAccountName", ""),
                    entry["attributes"].get("dNSHostName", "")))

        print("\n=== Constrained Delegation ===")
        entries = conn.search(searchBase=base_dn,
            searchFilter="(&(objectClass=*)(msDS-AllowedToDelegateTo=*))",
            attributes=["sAMAccountName", "msDS-AllowedToDelegateTo"])
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                sam = str(entry["attributes"].get("sAMAccountName", ""))
                spns = entry["attributes"].get("msDS-AllowedToDelegateTo", [])
                print(f"  {sam} → {spns}")

        print("\n=== RBCD ===")
        entries = conn.search(searchBase=base_dn,
            searchFilter="(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            attributes=["sAMAccountName"])
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                print("  [!] {} has RBCD".format(entry["attributes"].get("sAMAccountName", "")))
        return 0
    except Exception as exc:
        print(f"[-] Delegation enum error: {exc}", file=sys.stderr)
        return 1
