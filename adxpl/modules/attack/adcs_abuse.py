"""ADCS abuse — ESC1-ESC12 via Certipy adapter or native LDAP enumeration."""


import json
import os
import subprocess
import sys
from datetime import datetime, timezone, UTC
from typing import Any

from adxpl.core.credential import ADCredential
from adxpl.core.ldap_session import connect, get_base_dn


MANIFEST = {
    "capability_id": "adxpl.attack.adcs.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries", "certificate_requests"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}

ESC_DESCRIPTIONS = {
    "ESC1": "Template allows enrollee to specify SAN (Subject Alternative Name)",
    "ESC2": "Template allows any purpose EKU or no EKU",
    "ESC3": "Certificate Request Agent template + enrollment agent",
    "ESC4": "Template ACL allows low-priv user to modify template",
    "ESC5": "PKI object ACL (e.g., CA server object) misconfigured",
    "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA",
    "ESC7": "CA officer or manager rights for low-priv user",
    "ESC8": "NTLM relay to AD CS HTTP enrollment endpoint",
    "ESC9": "No security extension (szOID_NTDS_CA_SECURITY_EXT) on certificates",
    "ESC10": "Weak certificate mappings (registry or AD flags)",
    "ESC11": "NTLM relay to RPC enrollment endpoint (no encryption)",
    "ESC12": "ADCS CA on YubiHSM — shell access allows key extraction",
}


def _try_certipy(target: str, domain: str, cred: ADCredential, output: str) -> int:
    cmd = ["certipy", "find", "-dc-ip", target, "-target", domain, "-json", "-output", output]
    if cred.has_password:
        cmd.extend(["-u", f"{cred.username}@{domain}", "-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["-u", f"{cred.username}@{domain}", "-hashes", cred.impacket_hash])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print(f"[+] Certipy enumeration complete: {output}")
            return 0
        print(f"[-] Certipy failed: {result.stderr.strip()}", file=sys.stderr)
        return result.returncode
    except FileNotFoundError:
        return -1
    except subprocess.TimeoutExpired:
        print("[!] Certipy timed out", file=sys.stderr)
        return 1


def _native_adcs_enum(target: str, domain: str, cred: ADCredential, output: str) -> int:
    import ldap3

    conn = connect(target, cred)
    base_dn = get_base_dn(domain)
    config_dn = f"CN=Configuration,{base_dn}"

    conn.search(
        f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
        "(objectClass=pKICertificateTemplate)",
        attributes=["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                     "pKIExtendedKeyUsage", "msPKI-RA-Signature",
                     "nTSecurityDescriptor", "msPKI-Certificate-Application-Policy"],
        search_scope=ldap3.SUBTREE,
    )

    templates = []
    findings = []

    for entry in conn.entries:
        data = json.loads(entry.entry_to_json())
        attrs = data.get("attributes", {})
        name = attrs.get("cn", [""])[0] if isinstance(attrs.get("cn"), list) else attrs.get("cn", "")

        name_flag = int(attrs.get("msPKI-Certificate-Name-Flag", [0])[0]) if isinstance(attrs.get("msPKI-Certificate-Name-Flag"), list) else int(attrs.get("msPKI-Certificate-Name-Flag", 0))
        enrollment_flag = int(attrs.get("msPKI-Enrollment-Flag", [0])[0]) if isinstance(attrs.get("msPKI-Enrollment-Flag"), list) else int(attrs.get("msPKI-Enrollment-Flag", 0))
        ekus = attrs.get("pKIExtendedKeyUsage", [])
        ra_sig = int(attrs.get("msPKI-RA-Signature", [0])[0]) if isinstance(attrs.get("msPKI-RA-Signature"), list) else int(attrs.get("msPKI-RA-Signature", 0))

        template = {"name": name, "name_flag": name_flag, "enrollment_flag": enrollment_flag, "ekus": ekus, "ra_signature": ra_sig}
        templates.append(template)

        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
        if name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
            findings.append({"template": name, "esc": "ESC1", "description": ESC_DESCRIPTIONS["ESC1"]})

        if not ekus or "2.5.29.37.0" in ekus:
            findings.append({"template": name, "esc": "ESC2", "description": ESC_DESCRIPTIONS["ESC2"]})

        CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
        if ra_sig == 0 and not (enrollment_flag & CT_FLAG_PEND_ALL_REQUESTS):
            pass

    conn.search(
        f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
        "(objectClass=pKIEnrollmentService)",
        attributes=["cn", "cACertificate", "certificateTemplates", "dNSHostName"],
        search_scope=ldap3.SUBTREE,
    )

    cas = [json.loads(e.entry_to_json()) for e in conn.entries]

    os.makedirs(output, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    report = {
        "domain": domain,
        "cas": cas,
        "templates": templates,
        "findings": findings,
        "timestamp": ts,
    }

    out_path = os.path.join(output, f"adcs_enum_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"[+] {len(templates)} templates, {len(cas)} CAs, {len(findings)} potential ESC findings")
    for f in findings:
        print(f"  [!] {f['template']}: {f['esc']} — {f['description']}")
    print(f"[+] Output: {out_path}")
    return 0


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    output = os.path.join(args.output, "adcs")
    os.makedirs(output, exist_ok=True)

    print(f"[*] ADCS abuse enumeration → {args.target} ({args.domain})")

    rc = _try_certipy(args.target, args.domain, cred, output)
    if rc == 0:
        return 0

    print("[*] Falling back to native LDAP ADCS enumeration")
    return _native_adcs_enum(args.target, args.domain, cred, output)
