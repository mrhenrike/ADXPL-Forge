"""ADCS ESC9-ESC16 — extended certificate abuse techniques."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.adcs.adcs_esc_extended.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["certificate_abuse", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)
    esc = getattr(args, "esc", None)

    print("[*] ADCS Extended ESC Exploitation (ESC9-ESC16)")
    print("[*] Domain: {}".format(cred.domain))

    esc_map = {
        "9": "CT_FLAG_NO_SECURITY_EXTENSION — no szOID_NTDS_CA_SECURITY_EXT",
        "10": "Weak Certificate Mapping — StrongCertificateBindingEnforcement=0",
        "11": "ICPR over RPC without encryption — relay NTLM to RPC CA",
        "12": "CA on compromised host — issue arbitrary certs",
        "13": "OID Group Link — issuancePolicyLink for auto group membership",
        "14": "Explicit Key Mapping — GenericWrite on altSecurityIdentities",
        "15": "EKUwu — schema v1 EKU injection for client auth",
        "16": "CT_FLAG disabled at CA level — CA-level ESC9 equivalent",
    }

    if esc and esc in esc_map:
        print("[*] ESC{}: {}".format(esc, esc_map[esc]))
    else:
        print("[*] Extended ESC techniques:")
        for num, desc in esc_map.items():
            print("  ESC{}: {}".format(num, desc))

    import subprocess, shutil
    certipy = shutil.which("certipy") or shutil.which("certipy-ad")
    if certipy:
        print("\n[*] Certipy enumeration: certipy find -u {}@{} -dc-ip {}".format(
            cred.username or "user", cred.domain, dc_ip or "DC"))
    return 0
