"""PingCastle — AD security audit, risk scoring, compliance check."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.audit.pingcastle.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_queries", "report_generation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] PingCastle: AD Security Health Check")
    print(f"[*] Domain: {cred.domain}")

    import subprocess
    import shutil
    pingcastle = shutil.which("PingCastle.exe") or shutil.which("pingcastle")
    if pingcastle:
        cmd = [pingcastle, "--healthcheck", "--server", dc_ip or cred.domain]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] PingCastle not found")
    print("[*] Download: https://github.com/netwrix/pingcastle")
    print("[*] Run: PingCastle.exe --healthcheck --server <DC>")
    print("[*] Output: HTML report with risk scores (Stale Objects, Privileged Accounts, Trust, Anomalies)")
    return 1
