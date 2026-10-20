"""Machine Account Quota enumeration  -  check ms-DS-MachineAccountQuota."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.maq_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1136.002"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)

    print("[*] Machine Account Quota Enumeration")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    nxc = shutil.which("nxc") or shutil.which("netexec") or shutil.which("crackmapexec")
    if nxc:
        cmd = [nxc, "ldap", dc_ip or cred.domain, "-u", cred.username or "",
               "-d", cred.domain]
        if cred.password:
            cmd += ["-p", cred.password]
        elif cred.nthash:
            cmd += ["-H", cred.nthash]
        cmd += ["-M", "maq"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[*] Falling back to LDAP query")
    print("[*] ldapsearch -x -H ldap://{} -b 'DC={}' '(objectClass=domain)' ms-DS-MachineAccountQuota".format(
        dc_ip or cred.domain, ",DC=".join(cred.domain.split("."))))
    return 0
