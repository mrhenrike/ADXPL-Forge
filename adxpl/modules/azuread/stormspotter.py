"""Stormspotter — Azure AD attack graph exploration and visualization."""

from __future__ import annotations
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
    print("[*] Domain: {}".format(cred.domain))

    import subprocess, shutil
    stormspotter = shutil.which("stormspotter")
    if stormspotter:
        print("[*] Stormspotter found: {}".format(stormspotter))
        print("[*] Usage: stormspotter --tenant {}".format(cred.domain))
    else:
        print("[!] Stormspotter not found")
        print("[*] Source: https://github.com/Azure/Stormspotter")
        print("[*] Alternative: AzureHound for BloodHound CE")
    return 0
