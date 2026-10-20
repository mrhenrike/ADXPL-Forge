"""Coleta e persistência de artefatos/flags de auditoria."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.campaign.flag_collector.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": False,
    "side_effects": ["file_write"],
    "output_schema": "xpl.finding.v1",
    "mitre": [],
}


def run(args: Any) -> int:
    output = getattr(args, "output", ".")

    print("[*] Flag Collector: artifact persistence and tracking")

    import os
    import json
    import time
    flags_file = os.path.join(output, "flags.json")

    flags = {}
    if os.path.exists(flags_file):
        with open(flags_file) as fh:
            flags = json.load(fh)

    flag_name = getattr(args, "step", None)
    if flag_name:
        flags[flag_name] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "domain": getattr(args, "domain", "unknown"),
        }
        with open(flags_file, "w") as fh:
            json.dump(flags, fh, indent=2)
        print(f"[+] Flag '{flag_name}' recorded")
    else:
        if flags:
            print("[*] Collected flags:")
            for name, info in flags.items():
                print("  [+] {} — {} ({})".format(name, info.get("domain"), info.get("timestamp")))
        else:
            print("[*] No flags collected yet. Use --step <flag_name> to record.")

    return 0
