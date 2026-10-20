"""AD Miner — BloodHound data mining, scoring and attack path analysis."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.enumeration.ad_miner.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["neo4j_queries", "report_generation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002"],
}


def run(args: Any) -> int:
    output = getattr(args, "output", ".")

    print("[*] AD Miner: BloodHound data mining and risk scoring")

    import subprocess
    import shutil
    adminer = shutil.which("AD-miner") or shutil.which("ad-miner") or shutil.which("ad_miner")
    if adminer:
        cmd = [adminer, "-b", "bolt://localhost:7687", "-u", "neo4j", "-p", "neo4jneo4j",
               "--output-dir", output]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] AD-Miner not found")
    print("[*] Install: pip install ad-miner")
    return 1
