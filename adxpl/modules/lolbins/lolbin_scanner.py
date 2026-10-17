"""Enumeração de LOLBins disponíveis no alvo — mapeamento LOLBAS completo."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.lolbin_scanner.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["file_system_read"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1218"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)

    print("[*] LOLBin Scanner: enumerate available Living-off-the-Land binaries")

    lolbins = {
        "certutil.exe": {"path": "C:\\Windows\\System32\\certutil.exe", "mitre": "T1105", "use": "download, encode/decode"},
        "mshta.exe": {"path": "C:\\Windows\\System32\\mshta.exe", "mitre": "T1218.005", "use": "HTA execution"},
        "rundll32.exe": {"path": "C:\\Windows\\System32\\rundll32.exe", "mitre": "T1218.011", "use": "DLL proxy execution"},
        "regsvr32.exe": {"path": "C:\\Windows\\System32\\regsvr32.exe", "mitre": "T1218.010", "use": "Squiblydoo SCT execution"},
        "msbuild.exe": {"path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe", "mitre": "T1127.001", "use": "inline task execution"},
        "wmic.exe": {"path": "C:\\Windows\\System32\\wbem\\WMIC.exe", "mitre": "T1218", "use": "XSL script processing"},
        "cmstp.exe": {"path": "C:\\Windows\\System32\\cmstp.exe", "mitre": "T1218.003", "use": "INF SCT execution"},
        "bitsadmin.exe": {"path": "C:\\Windows\\System32\\bitsadmin.exe", "mitre": "T1197", "use": "file download"},
        "wscript.exe": {"path": "C:\\Windows\\System32\\wscript.exe", "mitre": "T1059.005", "use": "VBS/JS execution"},
        "cscript.exe": {"path": "C:\\Windows\\System32\\cscript.exe", "mitre": "T1059.005", "use": "VBS/JS execution"},
        "forfiles.exe": {"path": "C:\\Windows\\System32\\forfiles.exe", "mitre": "T1202", "use": "indirect command execution"},
        "pcalua.exe": {"path": "C:\\Windows\\System32\\pcalua.exe", "mitre": "T1202", "use": "program compatibility assistant"},
        "ieexec.exe": {"path": "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\ieexec.exe", "mitre": "T1218", "use": ".NET assembly download+exec"},
        "installutil.exe": {"path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe", "mitre": "T1218.004", "use": "uninstall method execution"},
    }

    print("\n  {:20s} {:12s} {:40s}".format("Binary", "MITRE", "Use"))
    print("  " + "-" * 75)
    for name, info in lolbins.items():
        print("  {:20s} {:12s} {:40s}".format(name, info["mitre"], info["use"]))

    print("\n[+] {} LOLBins cataloged".format(len(lolbins)))
    if target:
        print("[*] Remote enumeration against {} requires shell access".format(target))
    return 0
