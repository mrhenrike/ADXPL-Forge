"""linWinPwn — all-in-one AD autopwn from Linux."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.audit.linwinpwn.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["full_ad_enum", "vulnerability_scan", "credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
              "TA0006", "TA0007", "TA0008"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)

    print("[*] linWinPwn: automated AD audit from Linux")
    print("[*] Domain: {}  DC: {}".format(cred.domain, dc_ip or "auto"))

    import subprocess
    import shutil
    import os
    lwp = shutil.which("linWinPwn.sh") or shutil.which("linwinpwn")

    if not lwp:
        for p in [os.path.expanduser("~/tools/linWinPwn/linWinPwn.sh"),
                  "/opt/linWinPwn/linWinPwn.sh"]:
            if os.path.exists(p):
                lwp = p
                break

    if lwp:
        cmd = ["bash", lwp, "-t", dc_ip or "", "-d", cred.domain,
               "-u", cred.username or "", "-p", cred.password or ""]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] linWinPwn not found")
    print("[*] Install: git clone https://github.com/lefayjey/linWinPwn")
    print("[*] Performs: enum, vuln scan, spray, kerberoast, ADCS, delegation, bloodhound")
    return 1
