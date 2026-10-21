"""AD DNS enumeration via LDAP  -  adidnsdump."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.dns_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1018"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)

    print(f"[*] AD DNS Enumeration: {cred.domain}")

    import subprocess
    import shutil
    adidnsdump = shutil.which("adidnsdump")
    if adidnsdump:
        cmd = [adidnsdump, "-u", "{}\\{}".format(cred.domain, cred.username or "")]
        if cred.password:
            cmd += ["-p", cred.password]
        if dc_ip:
            cmd.append(dc_ip)
        cmd += ["--include-tombstoned", "-r"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] adidnsdump not found")
    print("[*] Install: pip install adidnsdump")
    return 1
