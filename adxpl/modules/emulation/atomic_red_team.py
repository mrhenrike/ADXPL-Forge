"""Atomic Red Team integration — run atomic tests by technique ID."""
from __future__ import annotations
import subprocess
import sys
import shutil
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.emulation.atomic_red_team.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["technique_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0001"],
}


def run(args: Any) -> int:
    technique = getattr(args, "art_technique", None)
    test_number = getattr(args, "test_number", None)
    art_path = getattr(args, "art_path", None)

    if not technique:
        print("[*] Atomic Red Team runner")
        print("[*] Usage: --art-technique T1003.001 [--test-number 1]")
        print("[*] Requires Invoke-AtomicRedTeam or atomics/ directory")
        return 0

    print("[*] Atomic Red Team: {} (test #{})".format(technique, test_number or "all"))

    if shutil.which("powershell"):
        cmd = 'Invoke-AtomicTest {} {} -Confirm:$false'.format(
            technique, "-TestNumbers {}".format(test_number) if test_number else "")
        print("[*] PowerShell: {}".format(cmd))
    elif art_path:
        import json
        from pathlib import Path
        yaml_path = Path(art_path) / "atomics" / technique / "{}.yaml".format(technique)
        print("[*] Atomic YAML: {}".format(yaml_path))
    else:
        print("[*] Download: https://github.com/redcanaryco/atomic-red-team")

    return 0
