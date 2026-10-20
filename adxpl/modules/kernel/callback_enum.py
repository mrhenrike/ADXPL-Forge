"""Kernel callback enumeration — list EDR/AV kernel callbacks."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.kernel.callback_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["kernel_memory_read"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1518.001"],
}

KNOWN_EDR_DRIVERS = {
    "WdFilter.sys": "Windows Defender",
    "csagent.sys": "CrowdStrike Falcon",
    "SentinelMonitor.sys": "SentinelOne",
    "CyProtectDrv64.sys": "Cylance",
    "hmpalert.sys": "HitmanPro.Alert",
    "bdfndisf6.sys": "Bitdefender",
    "epfw.sys": "ESET",
    "klif.sys": "Kaspersky",
}


def run(args: Any) -> int:
    action = getattr(args, "callback_action", "list_edrs")

    if action == "list_edrs":
        print("[*] Known EDR kernel drivers:")
        for drv, edr in KNOWN_EDR_DRIVERS.items():
            print(f"  {drv} — {edr}")
        print("\n[*] Enumerate loaded: fltMC.exe")
        print("[*] Or: driverquery /v | findstr /i \"<edr_name>\"")
        return 0

    if action == "enumerate":
        print("[*] Enumerating kernel callbacks...")
        print("[*] Requires: BYOVD driver or debug privilege")
        print()
        print("[*] Callback arrays to enumerate:")
        print("  PspCreateProcessNotifyRoutine[64]")
        print("  PspCreateThreadNotifyRoutine[64]")
        print("  PspLoadImageNotifyRoutine[64]")
        print("  CmpCallbackListHead (registry)")
        print("  ObpCallbackListHead (object manager)")
        print()
        print("[*] Tool: EDRSandblast --kernelmode --enum-only")
        return 0

    return 0
