"""Azure AD/Entra ID enumeration  -  users, groups, apps, service principals."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.azuread.azuread_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["api_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    print("[*] Azure AD / Entra ID Enumeration")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    roadrecon = shutil.which("roadrecon")
    if roadrecon:
        cmd = [roadrecon, "gather", "-d", cred.domain]
        if cred.username and cred.password:
            cmd += ["-u", f"{cred.username}@{cred.domain}",
                    "-p", cred.password]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        print("[*] View: roadrecon gui")
        return result.returncode

    print("[!] ROADrecon not found")
    print("[*] Tools: ROADrecon, AADInternals, AzureHound")
    print("[*] Install: pip install roadrecon")
    return 1
