"""ADXPL-Forge CLI entrypoint."""


import argparse
import sys

from adxpl import __product__, __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="axf",
        description=f"{__product__} v{__version__}  -  Active Directory attack and audit framework",
    )
    p.add_argument("--version", action="version",
                   version=f"{__product__} {__version__}")

    sub = p.add_subparsers(dest="command")

    def _add_common(sp: argparse.ArgumentParser, *, target_required: bool = True) -> None:
        sp.add_argument("--target", "-t", required=target_required,
                        help="Target IP/hostname")
        sp.add_argument("--domain", "-d", required=True,
                        help="AD domain (e.g. corp.local)")
        sp.add_argument("--username", "-u", help="Domain username")
        sp.add_argument("--password", "-p", help="Domain password")
        sp.add_argument("--hashes", help="NTLM hash (LM:NT)")
        sp.add_argument("--dc-ip", help="Domain controller IP")
        sp.add_argument("--output", "-o", default=".", help="Output path")

    # -- enum --
    enum_p = sub.add_parser("enum", help="AD enumeration modules")
    enum_p.add_argument("module", choices=[
        "bloodhound", "bloodhound-collect", "ldap-enum", "spn-scan",
        "gpo-enum", "trust-map", "adcs-enum", "delegation-enum",
        "laps-dump", "gmsa-dump", "adrecon", "dns-enum", "maq-enum",
        "plumhound", "ad-miner", "adacl-scanner",
        "windapsearch", "ldapdomaindump", "pywerview",
        "acl-scanner", "adalanche",
    ])
    _add_common(enum_p)
    enum_p.add_argument("--collection", default="Default",
                        help="BloodHound collection method")
    enum_p.add_argument("--target-computer", help="Target computer for LAPS")

    # -- attack --
    attack_p = sub.add_parser("attack", help="AD attack modules")
    attack_p.add_argument("module", choices=[
        "kerberoast", "kerberoast-adv", "asreproast", "adcs", "dcsync",
        "zerologon", "golden-ticket", "silver-ticket", "diamond-ticket",
        "sapphire-ticket", "bad-successor",
        "unconstrained-deleg", "constrained-deleg",
    ])
    _add_common(attack_p)
    attack_p.add_argument("--krbtgt-hash", help="krbtgt hash")
    attack_p.add_argument("--service-hash", help="Service account hash")
    attack_p.add_argument("--domain-sid", help="Domain SID")
    attack_p.add_argument("--spn", help="Target SPN")
    attack_p.add_argument("--impersonate", default="Administrator")
    attack_p.add_argument("--target-user", help="Target specific user")
    attack_p.add_argument("--etype", default="23", help="Encryption type")
    attack_p.add_argument("--opsec", action="store_true",
                          help="OPSEC-safe mode (adminCount=1 only)")
    attack_p.add_argument("--users-file", help="User list file")

    # -- lateral --
    lateral_p = sub.add_parser("lateral", help="Lateral movement modules")
    lateral_p.add_argument("module", choices=[
        "pth", "ptt", "overpass-the-hash", "wmi-exec", "psexec", "smbexec",
        "evil-winrm", "dcomexec", "mssql-exec", "atexec", "rdp-hijack",
        "ssh-lateral",
    ])
    _add_common(lateral_p)
    lateral_p.add_argument("--shell", action="store_true",
                           help="Spawn interactive reverse shell")
    lateral_p.add_argument("--lhost", help="Listener IP")
    lateral_p.add_argument("--lport", type=int, default=4444)
    lateral_p.add_argument("--shell-type", dest="shell_type", default="powershell")
    lateral_p.add_argument("--command", help="Command to execute")
    lateral_p.add_argument("--mssql-method", default="xp_cmdshell",
                           choices=["xp_cmdshell", "sp_oacreate"])

    # -- persist --
    persist_p = sub.add_parser("persist", help="Persistence modules")
    persist_p.add_argument("module", choices=[
        "golden-ticket", "silver-ticket", "skeleton-key",
        "dsrm-backdoor", "dsrm-password", "sid-history",
        "diamond-ticket-persist", "dcshadow", "gpo-abuse",
        "admin-sd-holder", "machine-account",
    ])
    _add_common(persist_p)
    persist_p.add_argument("--krbtgt-hash", help="krbtgt hash")
    persist_p.add_argument("--domain-sid", help="Domain SID")
    persist_p.add_argument("--dsrm-action", default="info",
                           choices=["info", "enable", "pth"])
    persist_p.add_argument("--target-dn", help="Target DN for GPO abuse")
    persist_p.add_argument("--command", help="Command for GPO backdoor")

    # -- credential --
    cred_p = sub.add_parser("credential", help="Credential extraction modules")
    cred_p.add_argument("module", choices=[
        "lsassy", "donpapi", "dploot", "pypykatz", "secretsdump",
        "dpapi-decrypt", "gpp-decrypt", "lsass-methods",
        "ntds-extract", "sam-dump", "cached-creds", "vault-extract",
        "wifi-creds",
    ])
    _add_common(cred_p, target_required=False)
    cred_p.add_argument("--method", default="comsvcs", help="Dump method")
    cred_p.add_argument("--dump-file", help="LSASS minidump file")
    cred_p.add_argument("--dpapi-path", help="DPAPI blob path")
    cred_p.add_argument("--cpassword", help="GPP cpassword hash")
    cred_p.add_argument("--sysvol-path", help="SYSVOL path for GPP")
    cred_p.add_argument("--lsass-method", default="comsvcs")
    cred_p.add_argument("--generate", action="store_true",
                        help="Generate command only")

    # -- coercion --
    coerce_p = sub.add_parser("coercion", help="NTLM coercion modules")
    coerce_p.add_argument("module", choices=[
        "petitpotam", "printerbug", "dfscoerce", "shadowcoerce",
        "coercer", "webclient", "cheeseounce", "remotepotato",
        "efspotato", "coerce-scanner",
    ])
    _add_common(coerce_p)
    coerce_p.add_argument("--listener", help="Capture/relay host")
    coerce_p.add_argument("--scan-only", action="store_true")
    coerce_p.add_argument("--command", help="Command for Potato exploits")

    # -- relay --
    relay_p = sub.add_parser("relay", help="NTLM/Kerberos relay modules")
    relay_p.add_argument("module", choices=[
        "ntlmrelayx", "krbrelayx", "adcs-relay", "mitm6", "ntlm-theft",
        "responder",
    ])
    _add_common(relay_p, target_required=False)
    relay_p.add_argument("--relay-target", help="Relay target host")
    relay_p.add_argument("--relay-attack", default="socks",
                         choices=["ldap_delegate", "ldap_shadow", "ldap_rbcd",
                                  "smb_exec", "http_adcs", "socks"])
    relay_p.add_argument("--targets-file", help="Targets file")
    relay_p.add_argument("--adcs-template", default="DomainController")
    relay_p.add_argument("--interface", help="Network interface")
    relay_p.add_argument("--listener", help="Listener host")

    # -- acl --
    acl_p = sub.add_parser("acl", help="ACL abuse modules")
    acl_p.add_argument("module", choices=[
        "dacl-edit", "writedacl", "writeowner", "add-computer",
        "rbcd", "shadow-cred", "generic-write",
        "force-change-pwd", "bloodyad-ops",
    ])
    _add_common(acl_p)
    acl_p.add_argument("--target-dn", help="Target distinguished name")
    acl_p.add_argument("--principal", help="Principal to grant rights to")
    acl_p.add_argument("--right", default="genericall",
                       help="ACL right to grant")
    acl_p.add_argument("--target-computer", help="Target computer for RBCD")
    acl_p.add_argument("--attacker-computer", help="Attacker machine account")
    acl_p.add_argument("--target-account", help="Target for shadow credentials")
    acl_p.add_argument("--computer-name", default="EVILPC$")
    acl_p.add_argument("--computer-pass", default="P@ssw0rd123!")

    # -- trust --
    trust_p = sub.add_parser("trust", help="Trust abuse modules")
    trust_p.add_argument("module", choices=[
        "sid-history-inject", "trust-ticket", "extrasids",
        "raise-child", "forest-trust", "trustpoc",
    ])
    _add_common(trust_p)
    trust_p.add_argument("--target-sid", help="SID to inject")
    trust_p.add_argument("--parent-domain", help="Parent domain")
    trust_p.add_argument("--trust-key", help="Inter-realm trust key")
    trust_p.add_argument("--child-sid", help="Child domain SID")
    trust_p.add_argument("--parent-sid", help="Parent domain SID")
    trust_p.add_argument("--krbtgt-hash", help="krbtgt hash")
    trust_p.add_argument("--aes-key", help="AES256 key for tickets")

    # -- spray --
    spray_p = sub.add_parser("spray", help="Password spray modules")
    spray_p.add_argument("module", choices=[
        "password-spray", "kerberos-spray", "kerbrute", "username-gen",
    ])
    _add_common(spray_p, target_required=False)
    spray_p.add_argument("--users-file", help="User list file")
    spray_p.add_argument("--passwords", help="Comma-separated passwords")
    spray_p.add_argument("--password-list", help="Password list file")
    spray_p.add_argument("--delay", type=int, default=30,
                         help="Delay between rounds (seconds)")
    spray_p.add_argument("--spray-protocol", default="ldap",
                         choices=["ldap", "smb", "kerberos"])

    # -- campaign --
    campaign_p = sub.add_parser("campaign", help="Attack campaign orchestration")
    campaign_p.add_argument("module", choices=[
        "domain-takeover", "cert-abuse", "kill-chain",
        "cred-validator", "flag-collector",
    ])
    _add_common(campaign_p, target_required=False)
    campaign_p.add_argument("--auto", action="store_true",
                            help="Run automated attack chain")
    campaign_p.add_argument("--step", help="Execute specific step")
    campaign_p.add_argument("--esc", help="ESC technique for cert-abuse")
    campaign_p.add_argument("--spray-protocol", default="smb",
                            choices=["smb", "ldap", "kerberos", "winrm"])

    # -- lolbins --
    lol_p = sub.add_parser("lolbins", help="LOLBin payload generation")
    lol_p.add_argument("module", choices=[
        "certutil", "mshta", "rundll32", "wmic", "regsvr32", "msbuild",
        "bitsadmin", "lolbin-scanner", "applocker-bypass",
    ])
    lol_p.add_argument("--target", "-t")
    lol_p.add_argument("--domain", "-d", default=".")
    lol_p.add_argument("--lhost", help="Listener host")
    lol_p.add_argument("--lport", default="8080")
    lol_p.add_argument("--command", default="calc.exe")
    lol_p.add_argument("--generate", action="store_true")

    # -- evasion --
    evasion_p = sub.add_parser("evasion", help="Defense evasion modules")
    evasion_p.add_argument("module", choices=[
        "amsi-bypass", "etw-disable", "defender-disable",
        "ppid-spoof", "clm-bypass", "scriptblock-bypass", "ps-cradle",
    ])
    evasion_p.add_argument("--target", "-t")
    evasion_p.add_argument("--domain", "-d", default=".")
    evasion_p.add_argument("--amsi-technique", default="patch_amsi_dll")
    evasion_p.add_argument("--etw-technique", default="patch_etw")
    evasion_p.add_argument("--defender-tech", default="add_exclusion")
    evasion_p.add_argument("--clm-technique", default="msbuild")
    evasion_p.add_argument("--encode", action="store_true",
                           help="Base64 encode payload")
    evasion_p.add_argument("--ppid", type=int, help="Parent PID to spoof")
    evasion_p.add_argument("--lhost", help="Listener host for cradles")
    evasion_p.add_argument("--lport", default="8080")

    # -- byovd --
    byovd_p = sub.add_parser("byovd", help="Bring Your Own Vulnerable Driver")
    byovd_p.add_argument("module", choices=[
        "driver-load", "pplfault", "callback-kill",
    ])
    byovd_p.add_argument("--target", "-t")
    byovd_p.add_argument("--domain", "-d", default=".")
    byovd_p.add_argument("--driver", help="Driver name")
    byovd_p.add_argument("--driver-path", help="Path to driver file")
    byovd_p.add_argument("--byovd-action", default="list",
                         choices=["list", "load", "exploit"])

    # -- privesc --
    privesc_p = sub.add_parser("privesc", help="Privilege escalation modules")
    privesc_p.add_argument("module", choices=[
        "potato", "sebackup", "uac-bypass", "service-abuse",
        "seimpersonate", "samaccountname", "setcb-priv",
        "always-install-elevated", "unquoted-svc-path", "dll-hijack",
    ])
    privesc_p.add_argument("--target", "-t")
    privesc_p.add_argument("--domain", "-d", default=".")
    privesc_p.add_argument("--dc-ip", help="Domain controller IP")
    privesc_p.add_argument("--username", "-u", help="Username")
    privesc_p.add_argument("--password", "-p", help="Password")
    privesc_p.add_argument("--hashes", help="NTLM hash")
    privesc_p.add_argument("--potato", default="godpotato",
                           help="Potato variant")
    privesc_p.add_argument("--uac-technique", default="fodhelper")
    privesc_p.add_argument("--command", default="cmd.exe")
    privesc_p.add_argument("--service-name", help="Target service")
    privesc_p.add_argument("--service-action", default="enumerate",
                           choices=["enumerate", "exploit", "unquoted"])
    privesc_p.add_argument("--dc-name", help="DC NetBIOS name")
    privesc_p.add_argument("--lhost", help="Listener host")
    privesc_p.add_argument("--lport", default="4444")

    # -- exploit --
    exploit_p = sub.add_parser("exploit", help="Windows/AD exploit modules")
    exploit_p.add_argument("module", choices=[
        "zerologon", "printnightmare", "smbghost", "nopac",
        "certifried", "petitpotam-unauth", "adcs-esc", "coerce-to-shell",
        "ms03-026", "ms06-040", "ms08-067", "ms14-068",
        "ms15-034", "ms15-011", "ms16-032", "ms16-075",
        "ms17-010", "eternalromance", "ms17-010-check",
        "bluekeep", "drop-the-mic", "sigred",
        "outlook-ntlm-leak", "ldapnightmare",
        "kerb-session-abuse", "pac-abuse",
        "kerb-dns-relay", "smb-reflection",
        "netlogon-rce-2026", "adds-rce-2026",
        "ms09-050",
    ])
    _add_common(exploit_p)
    exploit_p.add_argument("--listener", help="Capture/relay host")
    exploit_p.add_argument("--dc-name", help="DC NetBIOS name")
    exploit_p.add_argument("--dc-host", help="DC hostname")
    exploit_p.add_argument("--dll-path", help="DLL path for PrintNightmare")
    exploit_p.add_argument("--ca", help="Certificate Authority")
    exploit_p.add_argument("--template", help="Certificate template")
    exploit_p.add_argument("--esc", help="ESC technique number")
    exploit_p.add_argument("--chain", default="coerce-rbcd-s4u",
                           choices=["coerce-rbcd-s4u", "coerce-shadow-pkinit",
                                    "coerce-adcs-esc8"])

    # -- kernel --
    kernel_p = sub.add_parser("kernel", help="Kernel exploitation modules")
    kernel_p.add_argument("module", choices=[
        "token-steal", "driver-exploit", "callback-enum",
        "kernel-cve-scanner", "hivenightmare",
        "ms16-135", "cve-2018-8120", "cve-2021-1732",
        "cve-2022-21882", "cve-2023-36874", "cve-2024-30088",
    ])
    kernel_p.add_argument("--target", "-t")
    kernel_p.add_argument("--domain", "-d", default=".")
    kernel_p.add_argument("--driver", default="RTCore64")
    kernel_p.add_argument("--kernel-action", default="info",
                          choices=["info", "read", "write", "enumerate"])

    # -- emulation --
    emul_p = sub.add_parser("emulation", help="Threat emulation modules")
    emul_p.add_argument("module", choices=[
        "apt29", "custom", "purple-team", "atomic", "caldera",
        "ransomware-sim", "worm-spread-sim", "cred-stealer",
        "ad-persistence-implant", "edr-evasion", "shellcode-loader",
        "atomic-ad-tests", "caldera-ad-ops", "c2-bridge",
        "malware-bazaar-intel",
    ])
    emul_p.add_argument("--target", "-t")
    emul_p.add_argument("--domain", "-d", default=".")
    emul_p.add_argument("--techniques", help="Comma-separated MITRE IDs")
    emul_p.add_argument("--step", help="Emulation step number")
    emul_p.add_argument("--check", help="Purple team check name")
    emul_p.add_argument("--art-technique", help="Atomic Red Team technique")
    emul_p.add_argument("--caldera-url", default="http://localhost:8888")
    emul_p.add_argument("--caldera-action", default="info",
                        choices=["info", "status", "agents", "operations"])

    # -- adcs --
    adcs_p = sub.add_parser("adcs", help="AD Certificate Services modules")
    adcs_p.add_argument("module", choices=[
        "pass-the-cert", "pkinit-tools", "adcs-esc-extended", "locksmith-scan",
    ])
    _add_common(adcs_p)
    adcs_p.add_argument("--ca", help="Certificate Authority")
    adcs_p.add_argument("--template", help="Certificate template/PFX path")
    adcs_p.add_argument("--esc", help="ESC technique number (9-16)")

    # -- audit --
    audit_p = sub.add_parser("audit", help="AD security audit modules")
    audit_p.add_argument("module", choices=[
        "pingcastle", "adpeas", "linwinpwn", "deathstar",
    ])
    _add_common(audit_p, target_required=False)

    # -- exchange --
    exchange_p = sub.add_parser("exchange", help="Exchange / infrastructure modules")
    exchange_p.add_argument("module", choices=[
        "privexchange", "proxylogon", "proxyshell", "wsus-abuse",
    ])
    _add_common(exchange_p)
    exchange_p.add_argument("--listener", help="Attacker listener IP")

    # -- sccm --
    sccm_p = sub.add_parser("sccm", help="SCCM/MECM modules")
    sccm_p.add_argument("module", choices=[
        "sccm-enum", "sccm-abuse",
    ])
    _add_common(sccm_p, target_required=False)

    # -- azuread --
    azure_p = sub.add_parser("azuread", help="Azure AD / Entra ID modules")
    azure_p.add_argument("module", choices=[
        "azuread-enum", "azuread-tokens", "stormspotter",
    ])
    _add_common(azure_p, target_required=False)

    # -- impacket --
    impacket_p = sub.add_parser("impacket", help="Impacket arsenal modules")
    impacket_p.add_argument("module", choices=[
        "reg", "dacledit", "addcomputer", "finddeleg", "ntlmrelayx",
    ])
    _add_common(impacket_p)

    # -- shell (session management) --
    shell_p = sub.add_parser("shell", help="Shell session management")
    shell_p.add_argument("module", choices=["sessions"])
    shell_p.add_argument("session_action", nargs="?", default="list",
                         choices=["list", "interact", "kill", "background"])
    shell_p.add_argument("session_id", nargs="?", type=int, default=0)

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
