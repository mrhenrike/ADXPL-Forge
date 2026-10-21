"""CVE-2023-36874  -  Windows Error Reporting EoP."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.kernel.cve_2023_36874.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kernel_exploitation", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1068"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)

    print("[*] CVE-2023-36874  -  Windows Error Reporting EoP")
    print("[*] Root cause: WER service impersonation via directory junction")
    print("[*] Requires local code execution on target")

    print("\n[*] Check: systeminfo | findstr /i 'OS Version'")
    print("[*] References: SecWiki/windows-kernel-exploits, GitHub PoC repos")
    if target:
        print(f"[*] Target: {target}")

    return 0
