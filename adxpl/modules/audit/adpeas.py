"""adPEAS — AD Privilege Escalation Attack Scanner."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.audit.adpeas.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] adPEAS: AD Privilege Escalation Attack Scanner")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    adpeas = shutil.which("adPEAS.ps1") or shutil.which("adpeas")
    if adpeas:
        cmd = ["pwsh", "-ep", "bypass", "-File", adpeas,
               "-Domain", cred.domain]
        if dc_ip:
            cmd += ["-Server", dc_ip]
        if cred.username:
            cmd += ["-Username", f"{cred.username}@{cred.domain}"]
        if cred.password:
            cmd += ["-Password", cred.password]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] adPEAS not found")
    print("[*] Install: git clone https://github.com/61106960/adPEAS")
    print("[*] Checks: Delegation, ADCS, LAPS, GPO, AS-REP, Kerberoast, ACL, Trust")
    return 1
