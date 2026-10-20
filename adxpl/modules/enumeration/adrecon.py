"""adREcon  -  AD security audit and reconnaissance report."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.adrecon.v1",
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
    output = getattr(args, "output", ".")

    print("[*] adREcon: comprehensive AD reconnaissance")
    print("[*] Domain: {}  DC: {}".format(cred.domain, dc_ip or "auto"))

    import subprocess
    import shutil
    adrecon = shutil.which("adrecon") or shutil.which("adrecon.ps1") or shutil.which("ADRecon.ps1")
    if adrecon:
        cmd = ["pwsh", "-File", adrecon, "-DomainController", dc_ip or "",
               "-Creds", "{}/{}".format(cred.domain, cred.username or ""),
               "-OutputDir", output]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    nxc = shutil.which("nxc") or shutil.which("netexec")
    if nxc:
        print("[*] adREcon not found, using NetExec for AD enum")
        modules = ["users", "groups", "shares"]
        for mod in modules:
            cmd = [nxc, "smb", dc_ip or cred.domain, "-u", cred.username or "",
                   "-d", cred.domain]
            if cred.password:
                cmd += ["-p", cred.password]
            elif cred.nthash:
                cmd += ["-H", cred.nthash]
            cmd += [f"--{mod}"]
            print(f"[*] Enum: {mod}")
            subprocess.run(cmd, capture_output=False, text=True)
        return 0

    print("[!] Neither adREcon nor NetExec found")
    return 1
