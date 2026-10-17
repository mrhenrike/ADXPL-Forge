"""Route CLI commands to the appropriate module."""

from __future__ import annotations

import importlib
import sys
from typing import Any


_MODULE_MAP = {
    "enum": {
        "bloodhound": "adxpl.modules.enumeration.bloodhound_ingestor",
        "ldap-enum": "adxpl.modules.enumeration.ldap_enum",
        "spn-scan": "adxpl.modules.enumeration.spn_scan",
        "gpo-enum": "adxpl.modules.enumeration.gpo_enum",
        "trust-map": "adxpl.modules.enumeration.trust_map",
    },
    "attack": {
        "kerberoast": "adxpl.modules.attack.kerberoast",
        "asreproast": "adxpl.modules.attack.asreproast",
        "adcs": "adxpl.modules.attack.adcs_abuse",
        "dcsync": "adxpl.modules.attack.dcsync",
        "zerologon": "adxpl.modules.attack.zerologon",
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
    },
    "persist": {
        "golden-ticket": "adxpl.modules.persistence.golden_ticket",
        "silver-ticket": "adxpl.modules.persistence.silver_ticket",
        "skeleton-key": "adxpl.modules.persistence.skeleton_key",
        "dsrm-backdoor": "adxpl.modules.persistence.dsrm_backdoor",
        "sid-history": "adxpl.modules.persistence.sid_history",
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
