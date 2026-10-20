"""Orquestração de kill chain AD automática — fase a fase com fallback."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.campaign.kill_chain.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["full_attack_chain", "credential_extraction", "lateral_movement"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
              "TA0007", "TA0008", "TA0009", "TA0010"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    step = getattr(args, "step", None)
    auto = getattr(args, "auto", False)

    print("[*] AD Kill Chain Orchestrator")
    print("[*] Domain: {}  Target: {}".format(cred.domain, target or "auto"))

    phases = [
        ("1. Reconnaissance", "enum bloodhound"),
        ("2. Credential Access", "credential secretsdump"),
        ("3. Privilege Escalation", "attack kerberoast"),
        ("4. Lateral Movement", "lateral pth"),
        ("5. Domain Dominance", "attack dcsync"),
        ("6. Trust Escalation", "trust extrasids"),
        ("7. Persistence", "persist golden-ticket"),
        ("8. Objective", "campaign domain-takeover"),
    ]

    if step:
        phase_num = int(step) if step.isdigit() else 0
        if 1 <= phase_num <= len(phases):
            name, cmd = phases[phase_num - 1]
            print(f"[*] Executing phase: {name}")
            print(f"[*] Command: axf {cmd}")
        else:
            print(f"[!] Invalid step: {step} (1-{len(phases)})")
            return 1
    else:
        print("[*] Kill chain phases:")
        for name, cmd in phases:
            status = "PENDING" if not auto else "QUEUED"
            print(f"  [{status}] {name} -> axf {cmd}")

    if auto:
        print("\n[!] Automated kill chain execution requires explicit operator control")
        print("[*] Use --step <N> to execute individual phases")

    return 0
