"""Validação de credenciais em massa contra AD (SMB/LDAP/Kerberos)."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.campaign.cred_validator.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["authentication_attempts"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    protocol = getattr(args, "spray_protocol", "smb")

    print(f"[*] Credential Validator: {protocol} protocol against {target or cred.domain}")

    import subprocess
    import shutil
    nxc = shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")
    if not nxc:
        print("[!] NetExec/CrackMapExec not found")
        return 1

    proto_map = {"smb": "smb", "ldap": "ldap", "kerberos": "smb", "winrm": "winrm"}
    nxc_proto = proto_map.get(protocol, "smb")

    cmd = [nxc, nxc_proto, target or getattr(args, "dc_ip", cred.domain)]
    if cred.username:
        cmd += ["-u", cred.username]
    if cred.password:
        cmd += ["-p", cred.password]
    elif cred.nthash:
        cmd += ["-H", cred.nthash]
    cmd += ["-d", cred.domain]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)

    if "[+]" in result.stdout or "Pwn3d" in result.stdout:
        print("\n[+] Valid credentials confirmed!")
    else:
        print("\n[-] Credentials invalid or access denied")

    return 0
