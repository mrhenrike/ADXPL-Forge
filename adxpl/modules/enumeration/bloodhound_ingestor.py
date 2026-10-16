"""BloodHound data collection via SharpHound/RustHound adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

from adxpl.core.credential import ADCredential


MANIFEST = {
    "capability_id": "adxpl.enumeration.bloodhound.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ldap_queries", "dns_resolution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002", "T1069.002", "T1482"],
}


def _try_rusthound(target: str, domain: str, cred: ADCredential, output: str) -> int:
    cmd = ["rusthound", "-d", domain, "--dc", target, "-o", output, "--zip"]
    if cred.has_password:
        cmd.extend(["-u", f"{cred.username}@{domain}", "-p", cred.password])
    elif cred.has_hash:
        cmd.extend(["-u", f"{cred.username}@{domain}", "--ntlm", cred.nt_hash])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"[+] RustHound collection complete: {output}")
            return 0
        print(f"[-] RustHound failed: {result.stderr.strip()}", file=sys.stderr)
        return result.returncode
    except FileNotFoundError:
        return -1
    except subprocess.TimeoutExpired:
        print("[!] RustHound timed out after 300s", file=sys.stderr)
        return 1


def _try_bloodhound_python(target: str, domain: str, cred: ADCredential, output: str) -> int:
    try:
        from bloodhound import BloodHound
        from bloodhound.ad.domain import AD
    except ImportError:
        print("[!] bloodhound-python not installed: pip install adxpl-forge[bloodhound]", file=sys.stderr)
        return -1

    auth = {}
    if cred.has_password:
        auth = {"username": cred.username, "password": cred.password, "domain": domain}
    elif cred.has_hash:
        auth = {"username": cred.username, "hashes": cred.impacket_hash, "domain": domain}

    try:
        ad = AD(domain=domain, auth=auth, nameserver=target, dns_tcp=True)
        bh = BloodHound(ad)
        bh.connect()
        bh.run(
            collect=["group", "localadmin", "session", "trusts", "objectprops", "acl"],
            zip_output=True,
            output_dir=output,
        )
        print(f"[+] BloodHound-python collection complete: {output}")
        return 0
    except Exception as exc:
        print(f"[-] BloodHound-python failed: {exc}", file=sys.stderr)
        return 1


def _fallback_ldap(target: str, domain: str, cred: ADCredential, output: str) -> int:
    from adxpl.core.ldap_session import connect, get_base_dn
    import ldap3

    conn = connect(target, cred)
    base_dn = get_base_dn(domain)

    os.makedirs(output, exist_ok=True)
    results = {"users": [], "groups": [], "computers": [], "trusts": []}

    for obj_class, key in [
        ("(objectClass=user)", "users"),
        ("(objectClass=group)", "groups"),
        ("(objectClass=computer)", "computers"),
        ("(objectClass=trustedDomain)", "trusts"),
    ]:
        conn.search(
            base_dn, obj_class,
            attributes=["*"],
            search_scope=ldap3.SUBTREE,
            paged_size=1000,
        )
        for entry in conn.entries:
            results[key].append(json.loads(entry.entry_to_json()))

    out_path = os.path.join(output, f"adxpl_enum_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    total = sum(len(v) for v in results.values())
    print(f"[+] LDAP enumeration complete: {total} objects → {out_path}")
    return 0


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    output = os.path.join(args.output, "bloodhound")
    os.makedirs(output, exist_ok=True)

    print(f"[*] BloodHound ingestor → {args.target} ({args.domain})")

    rc = _try_rusthound(args.target, args.domain, cred, output)
    if rc == 0:
        return 0

    rc = _try_bloodhound_python(args.target, args.domain, cred, output)
    if rc == 0:
        return 0

    print("[*] Falling back to native LDAP enumeration")
    return _fallback_ldap(args.target, args.domain, cred, output)
