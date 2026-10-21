"""Ransomware simulation: file encryption + AD lateral spread."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.ransomware_sim.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["threat_emulation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1486"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)
    techniques = getattr(args, "techniques", None)

    print("[*] Ransomware simulation: file encryption + AD lateral spread")
    if target:
        print(f"[*] Target: {target}")
    if techniques:
        print(f"[*] Techniques: {techniques}")

    print("[*] Use --techniques <MITRE_IDs> to specify attack techniques")
    return 0
