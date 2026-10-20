"""DLL search order hijacking — sideloading and phantom DLL injection."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.dll_hijack.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_write", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1574.001"],
}


def run(args: Any) -> int:
    print("[*] DLL Search Order Hijacking")

    print("\n[*] Windows DLL search order:")
    print("  1. Application directory")
    print("  2. System directory (C:\\Windows\\System32)")
    print("  3. 16-bit system directory")
    print("  4. Windows directory")
    print("  5. Current directory")
    print("  6. PATH directories")

    print("\n[*] Discovery tools:")
    print("  - Process Monitor: filter Operation=CreateFile, Result=NAME NOT FOUND, Path ends with .dll")
    print("  - PowerUp: Find-PathDLLHijack, Find-ProcessDLLHijack")
    print("  - WinPEAS: checks for writable PATH directories")

    print("\n[*] Phantom DLL targets (commonly missing):")
    phantoms = ["wlbsctrl.dll", "wgatray.dll", "ualapi.dll", "tsmsisrv.dll",
                "TSVIPSrv.dll", "fxsst.dll", "msdmo.dll"]
    for dll in phantoms:
        print(f"  - {dll}")

    return 0
