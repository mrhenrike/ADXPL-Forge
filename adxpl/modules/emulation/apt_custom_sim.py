"""Custom APT simulation  -  build attack chains from technique IDs."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.custom_sim.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["technique_emulation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006"],
}

TECHNIQUE_MAP = {
    "T1566.001": ("coercion", "Spearphishing → initial access"),
    "T1059.001": ("lolbins", "PowerShell execution"),
    "T1003.001": ("credential", "LSASS credential dumping"),
    "T1003.002": ("credential", "SAM database extraction"),
    "T1003.003": ("credential", "NTDS.dit extraction"),
    "T1110.003": ("spray", "Password spraying"),
    "T1187": ("coercion", "Forced authentication / NTLM coercion"),
    "T1557.001": ("relay", "NTLM relay"),
    "T1558.001": ("attack", "Golden Ticket"),
    "T1558.003": ("attack", "Kerberoasting"),
    "T1558.004": ("attack", "AS-REP Roasting"),
    "T1550.002": ("lateral", "Pass the Hash"),
    "T1550.003": ("acl", "Pass the Ticket / delegation abuse"),
    "T1649": ("exploit", "AD CS abuse"),
    "T1222.001": ("acl", "ACL abuse"),
    "T1562.001": ("evasion", "AMSI/Defender disable"),
}


def run(args: Any) -> int:
    techniques = getattr(args, "techniques", None)

    if not techniques:
        print("[*] Custom APT simulation  -  build chain from MITRE technique IDs")
        print("[*] Usage: --techniques T1566.001,T1059.001,T1003.001,T1558.001")
        print()
        print("[*] Mapped techniques:")
        for tid, (cat, desc) in sorted(TECHNIQUE_MAP.items()):
            print(f"  {tid} ({cat})  -  {desc}")
        return 0

    chain = [t.strip() for t in techniques.split(",")]
    print(f"[*] Custom attack chain ({len(chain)} steps):")
    for i, tid in enumerate(chain, 1):
        info = TECHNIQUE_MAP.get(tid, ("unknown", "unmapped technique"))
        print(f"  Step {i}: {tid} ({info[0]})  -  {info[1]}")

    return 0
