"""Shellcode injection: process hollowing, APC, thread hijack."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.shellcode_loader.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["threat_emulation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1055"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)
    techniques = getattr(args, "techniques", None)

    print("[*] Shellcode injection: process hollowing, APC, thread hijack")
    if target:
        print("[*] Target: {}".format(target))
    if techniques:
        print("[*] Techniques: {}".format(techniques))

    print("[*] Use --techniques <MITRE_IDs> to specify attack techniques")
    return 0
