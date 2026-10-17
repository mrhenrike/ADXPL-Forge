"""AD CS enumeration — certificate templates, CAs, ESC1-ESC8 detection."""
from __future__ import annotations
import subprocess, sys, shutil
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.enum.adcs_enum.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["ldap_query"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", args.target)
    output_dir = getattr(args, "output", ".")

    print("[*] AD CS enumeration → {}".format(dc_ip))

    if shutil.which("certipy"):
        cmd = [
            "certipy", "find",
            "-u", "{}@{}".format(cred.username, args.domain),
            "-dc-ip", dc_ip, "-vulnerable",
        ]
        if cred.password:
            cmd.extend(["-p", cred.password])
        elif cred.has_hash:
            cmd.extend(["-hashes", "{}:{}".format(cred.lm_hash, cred.nt_hash)])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=output_dir)
        print(result.stdout)
        if "ESC" in result.stdout:
            print("\n[+] Vulnerable templates found!")
        return result.returncode

    print("[*] Falling back to LDAP enumeration...")
    try:
        from impacket.ldap import ldap as imp_ldap
        base_dn = "CN=Configuration,DC=" + ",DC=".join(args.domain.split("."))
        conn = imp_ldap.LDAPConnection("ldap://{}".format(dc_ip), base_dn)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)

        entries = conn.search(
            searchBase="CN=Certificate Templates,CN=Public Key Services,CN=Services," + base_dn,
            searchFilter="(objectClass=pKICertificateTemplate)",
            attributes=["cn", "msPKI-Certificate-Name-Flag", "pKIExtendedKeyUsage"],
        )
        templates = []
        for entry in entries:
            if hasattr(entry, "getComponentByName"):
                templates.append(str(entry["attributes"].get("cn", "")))

        print("[+] Found {} certificate templates".format(len(templates)))
        for t in templates:
            print("  - {}".format(t))
        return 0
    except Exception as exc:
        print("[-] ADCS enum error: {}".format(exc), file=sys.stderr)
        return 1
