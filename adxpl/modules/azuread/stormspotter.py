"""Stormspotter — Azure AD attack graph exploration and visualization."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.azuread.stormspotter.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["api_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.004"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    print("[*] Stormspotter: Azure AD attack graph exploration")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    stormspotter = shutil.which("stormspotter")
    if stormspotter:
        print(f"[*] Stormspotter found: {stormspotter}")
        print(f"[*] Usage: stormspotter --tenant {cred.domain}")
    else:
        print("[!] Stormspotter not found")
        print("[*] Source: https://github.com/Azure/Stormspotter")
        print("[*] Alternative: AzureHound for BloodHound CE")
    return 0
