"""PlumHound  -  BloodHound query automation and reporting."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.plumhound.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["neo4j_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002"],
}


def run(args: Any) -> int:
    output = getattr(args, "output", ".")

    print("[*] PlumHound: BloodHound data mining and reporting")

    import subprocess
    import shutil
    plumhound = shutil.which("PlumHound.py") or shutil.which("plumhound")
    if plumhound:
        cmd = [plumhound, "-x", "tasks/default.tasks", "-p", "neo4jneo4j",
               "--op", output]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] PlumHound not found")
    print("[*] Install: git clone https://github.com/PlumHound/PlumHound")
    print("[*] Requires: BloodHound data imported into Neo4j")
    return 1
