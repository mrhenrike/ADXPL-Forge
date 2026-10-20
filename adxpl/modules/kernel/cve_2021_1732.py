"""CVE-2021-1732  -  Win32k EoP (in-the-wild)."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.kernel.cve_2021_1732.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kernel_exploitation", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1068"],
}


def run(args: Any) -> int:
    target = getattr(args, "target", None)

    print("[*] CVE-2021-1732  -  Win32k EoP (in-the-wild)")
    print("[*] Root cause: Win32k type confusion callback via xxxClientAllocWindowClassExtraBytes")
    print("[*] Requires local code execution on target")

    print("\n[*] Check: systeminfo | findstr /i 'OS Version'")
    print("[*] References: SecWiki/windows-kernel-exploits, GitHub PoC repos")
    if target:
        print(f"[*] Target: {target}")

    return 0
