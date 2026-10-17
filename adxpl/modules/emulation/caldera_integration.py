"""MITRE Caldera integration — orchestrate adversary emulation plans."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.caldera.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["caldera_api_call"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0001"],
}


def run(args: Any) -> int:
    caldera_url = getattr(args, "caldera_url", "http://localhost:8888")
    api_key = getattr(args, "caldera_key", None)
    action = getattr(args, "caldera_action", "info")

    if action == "info":
        print("[*] MITRE Caldera integration")
        print("[*] Caldera URL: {}".format(caldera_url))
        print("[*] Actions: status, agents, operations, run")
        return 0

    if not api_key:
        print("[!] --caldera-key required", file=sys.stderr)
        return 1

    import urllib.request, json
    headers = {"KEY": api_key, "Content-Type": "application/json"}

    if action == "status":
        req = urllib.request.Request("{}/api/v2/health".format(caldera_url), headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        print("[+] Caldera status: {}".format(json.loads(resp.read())))
        return 0

    if action == "agents":
        req = urllib.request.Request("{}/api/v2/agents".format(caldera_url), headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        agents = json.loads(resp.read())
        print("[+] {} active agents:".format(len(agents)))
        for a in agents:
            print("  {} — {} ({})".format(a.get("paw", "?"), a.get("host", "?"), a.get("platform", "?")))
        return 0

    return 0
