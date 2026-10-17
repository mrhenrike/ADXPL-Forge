"""Kernel token steal — steal SYSTEM token via driver or exploit."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.kernel.token_steal.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["kernel_memory_access", "token_manipulation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1134.001"],
}


def run(args: Any) -> int:
    method = getattr(args, "token_method", "driver")

    print("[*] Kernel token steal (method: {})".format(method))

    if method == "driver":
        print("[*] Via BYOVD driver (r/w physical memory):")
        print("  1. Load vulnerable driver (RTCore64, gdrv, DBUtil)")
        print("  2. Find System EPROCESS (PID 4)")
        print("  3. Read System token from EPROCESS.Token")
        print("  4. Find current process EPROCESS")
        print("  5. Copy System token to current process")
        print("  6. Current process now runs as SYSTEM")
    elif method == "exploit":
        print("[*] Via kernel exploit (overflow/UAF):")
        print("  1. Trigger vulnerability to get kernel code execution")
        print("  2. Shellcode: find EPROCESS list")
        print("  3. Swap token pointer: current ← System")
        print("  4. Return to user mode with SYSTEM token")
    elif method == "named_pipe":
        print("[*] Via named pipe impersonation:")
        print("  1. Create named pipe with SecurityImpersonation")
        print("  2. Trigger SYSTEM process to connect (service, scheduled task)")
        print("  3. ImpersonateNamedPipeClient()")
        print("  4. Current thread impersonates SYSTEM")

    return 0
