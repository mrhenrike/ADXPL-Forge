"""Purple team detection checks — validate if blue team detects each technique."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.purple_team.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0040"],
}

DETECTION_CHECKS = {
    "kerberoasting": {
        "technique": "T1558.003",
        "detection": "Event 4769 with 0x17 encryption, abnormal TGS volume",
        "siem_query": 'EventID=4769 TicketEncryptionType=0x17 | stats count by ServiceName',
    },
    "dcsync": {
        "technique": "T1003.006",
        "detection": "Event 4662 with DS-Replication-Get-Changes from non-DC",
        "siem_query": 'EventID=4662 Properties="*Replication*" | where NOT src_host IN dc_list',
    },
    "golden_ticket": {
        "technique": "T1558.001",
        "detection": "TGT with unusual lifetime, Event 4768 anomalies",
        "siem_query": 'EventID=4768 | where TicketLifetime > 10h',
    },
    "pass_the_hash": {
        "technique": "T1550.002",
        "detection": "Event 4624 LogonType=9 (NewCredentials), NTLM auth",
        "siem_query": 'EventID=4624 LogonType=9 AuthenticationPackageName=NTLM',
    },
    "password_spray": {
        "technique": "T1110.003",
        "detection": "Multiple 4625 events with same password, different users",
        "siem_query": 'EventID=4625 | stats dc(TargetUserName) as users by TimeWindow(5m)',
    },
}


def run(args: Any) -> int:
    check = getattr(args, "check", None)

    if not check:
        print("[*] Purple Team Detection Checks:")
        for name, info in DETECTION_CHECKS.items():
            print("\n  [{}] — {}".format(name, info["technique"]))
            print("    Detection: {}".format(info["detection"]))
            print("    SIEM: {}".format(info["siem_query"]))
        return 0

    info = DETECTION_CHECKS.get(check)
    if not info:
        print("[!] Unknown check: {}".format(check))
        return 1

    print("[*] Detection check: {}".format(check))
    print("  Technique: {}".format(info["technique"]))
    print("  Detection: {}".format(info["detection"]))
    print("  SIEM query: {}".format(info["siem_query"]))
    return 0
