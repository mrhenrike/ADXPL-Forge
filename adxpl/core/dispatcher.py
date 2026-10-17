"""Route CLI commands to the appropriate module."""

from __future__ import annotations

import importlib
import sys
from typing import Any


_MODULE_MAP = {
    "enum": {
        "bloodhound": "adxpl.modules.enumeration.bloodhound_ingestor",
        "bloodhound-collect": "adxpl.modules.enumeration.bloodhound_collect",
        "ldap-enum": "adxpl.modules.enumeration.ldap_enum",
        "spn-scan": "adxpl.modules.enumeration.spn_scan",
        "gpo-enum": "adxpl.modules.enumeration.gpo_enum",
        "trust-map": "adxpl.modules.enumeration.trust_map",
        "adcs-enum": "adxpl.modules.enumeration.adcs_enum",
        "delegation-enum": "adxpl.modules.enumeration.delegation_enum",
        "laps-dump": "adxpl.modules.enumeration.laps_dump",
        "gmsa-dump": "adxpl.modules.enumeration.gmsa_dump",
    },
    "attack": {
        "kerberoast": "adxpl.modules.attack.kerberoast",
        "kerberoast-adv": "adxpl.modules.attack.kerberoast_adv",
        "asreproast": "adxpl.modules.attack.asreproast",
        "adcs": "adxpl.modules.attack.adcs_abuse",
        "dcsync": "adxpl.modules.attack.dcsync",
        "zerologon": "adxpl.modules.attack.zerologon",
        "golden-ticket": "adxpl.modules.attack.golden_ticket",
        "silver-ticket": "adxpl.modules.attack.silver_ticket",
        "diamond-ticket": "adxpl.modules.attack.diamond_ticket",
    },
    "lateral": {
        "pth": "adxpl.modules.lateral.pass_the_hash",
        "ptt": "adxpl.modules.lateral.pass_the_ticket",
        "overpass-the-hash": "adxpl.modules.lateral.overpass_the_hash",
        "wmi-exec": "adxpl.modules.lateral.wmi_exec",
        "psexec": "adxpl.modules.lateral.psexec",
        "smbexec": "adxpl.modules.lateral.smbexec",
        "evil-winrm": "adxpl.modules.lateral.evil_winrm",
        "dcomexec": "adxpl.modules.lateral.dcomexec",
        "mssql-exec": "adxpl.modules.lateral.mssql_exec",
    },
    "persist": {
        "golden-ticket": "adxpl.modules.persistence.golden_ticket",
        "silver-ticket": "adxpl.modules.persistence.silver_ticket",
        "skeleton-key": "adxpl.modules.persistence.skeleton_key",
        "dsrm-backdoor": "adxpl.modules.persistence.dsrm_backdoor",
        "dsrm-password": "adxpl.modules.persistence.dsrm_password",
        "sid-history": "adxpl.modules.persistence.sid_history",
    },
    "credential": {
        "lsassy": "adxpl.modules.credential.lsassy_dump",
        "donpapi": "adxpl.modules.credential.donpapi_dump",
        "dploot": "adxpl.modules.credential.dploot_dump",
        "pypykatz": "adxpl.modules.credential.pypykatz_dump",
        "secretsdump": "adxpl.modules.credential.secretsdump_exec",
        "dpapi-decrypt": "adxpl.modules.credential.dpapi_decrypt",
        "gpp-decrypt": "adxpl.modules.credential.gpp_decrypt",
        "lsass-methods": "adxpl.modules.credential.lsass_methods",
    },
    "coercion": {
        "petitpotam": "adxpl.modules.coercion.petitpotam",
        "printerbug": "adxpl.modules.coercion.printerbug",
        "dfscoerce": "adxpl.modules.coercion.dfscoerce",
        "shadowcoerce": "adxpl.modules.coercion.shadowcoerce",
        "coercer": "adxpl.modules.coercion.coercer_multi",
        "webclient": "adxpl.modules.coercion.webclient_coerce",
    },
    "relay": {
        "ntlmrelayx": "adxpl.modules.relay.ntlmrelayx_auto",
        "krbrelayx": "adxpl.modules.relay.krbrelayx_exec",
        "adcs-relay": "adxpl.modules.relay.adcs_relay",
        "mitm6": "adxpl.modules.relay.mitm6_relay",
    },
    "acl": {
        "dacl-edit": "adxpl.modules.acl.dacl_edit",
        "writedacl": "adxpl.modules.acl.writedacl_abuse",
        "writeowner": "adxpl.modules.acl.writeowner_abuse",
        "add-computer": "adxpl.modules.acl.add_computer",
        "rbcd": "adxpl.modules.acl.rbcd_abuse",
        "shadow-cred": "adxpl.modules.acl.shadow_credentials",
    },
    "trust": {
        "sid-history-inject": "adxpl.modules.trust.sid_history_inject",
        "trust-ticket": "adxpl.modules.trust.trust_ticket",
    },
    "spray": {
        "password-spray": "adxpl.modules.spray.password_spray",
        "kerberos-spray": "adxpl.modules.spray.kerberos_spray",
    },
    "campaign": {
        "domain-takeover": "adxpl.modules.campaign.domain_takeover",
        "cert-abuse": "adxpl.modules.campaign.cert_abuse_chain",
    },
    "lolbins": {
        "certutil": "adxpl.modules.lolbins.certutil_ops",
        "mshta": "adxpl.modules.lolbins.mshta_exec",
        "rundll32": "adxpl.modules.lolbins.rundll32_exec",
        "wmic": "adxpl.modules.lolbins.wmic_exec",
        "regsvr32": "adxpl.modules.lolbins.regsvr32_exec",
        "msbuild": "adxpl.modules.lolbins.msbuild_exec",
    },
    "evasion": {
        "amsi-bypass": "adxpl.modules.evasion.amsi_bypass",
        "etw-disable": "adxpl.modules.evasion.etw_disable",
        "defender-disable": "adxpl.modules.evasion.defender_disable",
        "ppid-spoof": "adxpl.modules.evasion.ppid_spoof",
        "clm-bypass": "adxpl.modules.evasion.clm_bypass",
    },
    "byovd": {
        "driver-load": "adxpl.modules.byovd.driver_load",
        "pplfault": "adxpl.modules.byovd.pplfault_exploit",
        "callback-kill": "adxpl.modules.byovd.callback_kill",
    },
    "privesc": {
        "potato": "adxpl.modules.privesc.token_impersonation",
        "sebackup": "adxpl.modules.privesc.sebackup_abuse",
        "uac-bypass": "adxpl.modules.privesc.uac_bypass",
        "service-abuse": "adxpl.modules.privesc.service_abuse",
    },
    "exploit": {
        "zerologon": "adxpl.modules.exploit.zerologon",
        "printnightmare": "adxpl.modules.exploit.printnightmare",
        "smbghost": "adxpl.modules.exploit.smbghost",
        "nopac": "adxpl.modules.exploit.nopac",
        "certifried": "adxpl.modules.exploit.certifried",
        "petitpotam-unauth": "adxpl.modules.exploit.petitpotam_unauthenticated",
        "adcs-esc": "adxpl.modules.exploit.adcs_esc_exploit",
        "coerce-to-shell": "adxpl.modules.exploit.coerce_to_shell",
    },
    "kernel": {
        "token-steal": "adxpl.modules.kernel.token_steal",
        "driver-exploit": "adxpl.modules.kernel.driver_exploit",
        "callback-enum": "adxpl.modules.kernel.callback_enum",
    },
    "emulation": {
        "apt29": "adxpl.modules.emulation.apt29_sim",
        "custom": "adxpl.modules.emulation.apt_custom_sim",
        "purple-team": "adxpl.modules.emulation.purple_team_checks",
        "atomic": "adxpl.modules.emulation.atomic_red_team",
        "caldera": "adxpl.modules.emulation.caldera_integration",
    },
    "shell": {
        "sessions": "adxpl.modules.lateral._sessions_cmd",
    },
}


def dispatch(args: Any) -> int:
    command = args.command
    module_name = args.module

    module_path = _MODULE_MAP.get(command, {}).get(module_name)
    if not module_path:
        print("[!] Unknown module: {}/{}".format(command, module_name), file=sys.stderr)
        return 1

    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        print("[!] Failed to load {}: {}".format(module_path, exc), file=sys.stderr)
        print("[*] Some modules require optional dependencies. Install with: pip install adxpl-forge[full]", file=sys.stderr)
        return 1

    return mod.run(args)
