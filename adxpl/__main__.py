"""ADXPL-Forge CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from adxpl import __version__, __product__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="axf",
        description="{} v{} — Active Directory attack and audit framework".format(
            __product__, __version__),
    )
    p.add_argument("--version", action="version",
                   version="{} {}".format(__product__, __version__))

    sub = p.add_subparsers(dest="command")

    # -- enum --
    enum_p = sub.add_parser("enum", help="AD enumeration modules")
    enum_p.add_argument("module", choices=[
        "bloodhound", "ldap-enum", "spn-scan", "gpo-enum", "trust-map",
    ])
    enum_p.add_argument("--target", "-t", required=True,
                        help="Domain controller IP/hostname")
    enum_p.add_argument("--domain", "-d", required=True,
                        help="AD domain (e.g. corp.local)")
    enum_p.add_argument("--username", "-u", help="Domain username")
    enum_p.add_argument("--password", "-p", help="Domain password")
    enum_p.add_argument("--hashes", help="NTLM hash (LM:NT)")
    enum_p.add_argument("--output", "-o", default=".", help="Output directory")

    # -- attack --
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

    # -- lateral --
    lateral_p = sub.add_parser("lateral", help="Lateral movement modules")
    lateral_p.add_argument("module", choices=[
        "pth", "ptt", "overpass-the-hash", "wmi-exec", "psexec", "smbexec",
        "evil-winrm", "dcomexec",
    ])
    lateral_p.add_argument("--target", "-t", required=True)
    lateral_p.add_argument("--domain", "-d", required=True)
    lateral_p.add_argument("--username", "-u")
    lateral_p.add_argument("--password", "-p")
    lateral_p.add_argument("--hashes")
    lateral_p.add_argument("--shell", action="store_true",
                           help="Spawn interactive reverse shell after execution")
    lateral_p.add_argument("--lhost", help="Listener IP for reverse shell")
    lateral_p.add_argument("--lport", type=int, default=4444,
                           help="Listener port (default: 4444)")
    lateral_p.add_argument("--shell-type", dest="shell_type", default="powershell",
                           help="Shell payload type (default: powershell)")
    lateral_p.add_argument("--winrm-port", type=int, default=5985,
                           help="WinRM port for evil-winrm (default: 5985)")
    lateral_p.add_argument("--ssl", action="store_true",
                           help="Use HTTPS for WinRM")
    lateral_p.add_argument("--dcom-object", dest="dcom_object", default="mmc",
                           choices=["mmc", "shellbrowserwindow"],
                           help="DCOM object for dcomexec (default: mmc)")

    # -- persist --
    persist_p = sub.add_parser("persist", help="Persistence modules")
    persist_p.add_argument("module", choices=[
        "golden-ticket", "silver-ticket", "skeleton-key",
        "dsrm-backdoor", "sid-history",
    ])
    persist_p.add_argument("--target", "-t", required=True)
    persist_p.add_argument("--domain", "-d", required=True)
    persist_p.add_argument("--krbtgt-hash",
                           help="krbtgt NTLM hash for golden ticket")
    persist_p.add_argument("--service-hash",
                           help="Service account hash for silver ticket")
    persist_p.add_argument("--domain-sid", help="Domain SID")

    # -- shell (session management) --
    shell_p = sub.add_parser("shell", help="Shell session management")
    shell_p.add_argument("module", choices=["sessions"])
    shell_p.add_argument("session_action", nargs="?", default="list",
                         choices=["list", "interact", "kill", "background"],
                         help="Session action (default: list)")
    shell_p.add_argument("session_id", nargs="?", type=int, default=0,
                         help="Session ID for interact/kill/background")

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
