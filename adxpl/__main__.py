"""ADXPL-Forge CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from adxpl import __version__, __product__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="axf",
        description=f"{__product__} v{__version__} — Active Directory attack and audit framework",
    )
    p.add_argument("--version", action="version", version=f"{__product__} {__version__}")

    sub = p.add_subparsers(dest="command")

    enum_p = sub.add_parser("enum", help="AD enumeration modules")
    enum_p.add_argument("module", choices=[
        "bloodhound", "ldap-enum", "spn-scan", "gpo-enum", "trust-map",
    ])
    enum_p.add_argument("--target", "-t", required=True, help="Domain controller IP/hostname")
    enum_p.add_argument("--domain", "-d", required=True, help="AD domain (e.g. corp.local)")
    enum_p.add_argument("--username", "-u", help="Domain username")
    enum_p.add_argument("--password", "-p", help="Domain password")
    enum_p.add_argument("--hashes", help="NTLM hash (LM:NT)")
    enum_p.add_argument("--output", "-o", default=".", help="Output directory")

    attack_p = sub.add_parser("attack", help="AD attack modules")
    attack_p.add_argument("module", choices=[
        "kerberoast", "asreproast", "adcs", "dcsync", "zerologon",
    ])
    attack_p.add_argument("--target", "-t", required=True)
    attack_p.add_argument("--domain", "-d", required=True)
    attack_p.add_argument("--username", "-u")
    attack_p.add_argument("--password", "-p")
    attack_p.add_argument("--hashes")
    attack_p.add_argument("--output", "-o", default=".")

    lateral_p = sub.add_parser("lateral", help="Lateral movement modules")
    lateral_p.add_argument("module", choices=[
        "pth", "ptt", "overpass-the-hash", "wmi-exec", "psexec", "smbexec",
    ])
    lateral_p.add_argument("--target", "-t", required=True)
    lateral_p.add_argument("--domain", "-d", required=True)
    lateral_p.add_argument("--username", "-u")
    lateral_p.add_argument("--password", "-p")
    lateral_p.add_argument("--hashes")

    persist_p = sub.add_parser("persist", help="Persistence modules")
    persist_p.add_argument("module", choices=[
        "golden-ticket", "silver-ticket", "skeleton-key", "dsrm-backdoor", "sid-history",
    ])
    persist_p.add_argument("--target", "-t", required=True)
    persist_p.add_argument("--domain", "-d", required=True)
    persist_p.add_argument("--krbtgt-hash", help="krbtgt NTLM hash for golden ticket")
    persist_p.add_argument("--service-hash", help="Service account hash for silver ticket")
    persist_p.add_argument("--domain-sid", help="Domain SID")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    from adxpl.core.dispatcher import dispatch
    return dispatch(args)


if __name__ == "__main__":
    sys.exit(main())
