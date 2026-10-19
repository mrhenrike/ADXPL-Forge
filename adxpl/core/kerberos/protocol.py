"""Kerberos protocol primitives (ASN.1 construction and parsing)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class EncryptionType(IntEnum):
    DES_CBC_CRC = 1
    DES_CBC_MD5 = 3
    RC4_HMAC = 23
    AES128_CTS_HMAC_SHA1 = 17
    AES256_CTS_HMAC_SHA1 = 18


class KerberosError(Exception):
    def __init__(self, error_code: int, message: str = "") -> None:
        self.error_code = error_code
        super().__init__(f"KRB_ERROR {error_code}: {message}")


# KDC error codes (RFC 4120 section 7.5.9)
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
KDC_ERR_KEY_EXPIRED = 23
KDC_ERR_S_PRINCIPAL_UNKNOWN = 7


@dataclass
class PrincipalName:
    name_type: int = 1  # KRB_NT_PRINCIPAL
    components: list[str] = field(default_factory=list)

    @property
    def realm_string(self) -> str:
        return "/".join(self.components)


@dataclass
class ASReq:
    client: PrincipalName
    realm: str
    server: PrincipalName
    nonce: int = 0
    etypes: list[EncryptionType] = field(default_factory=list)
    pa_data: list[dict[str, Any]] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize to raw bytes for network transmission.

        Actual ASN.1 DER encoding requires pyasn1 or a similar library.
        This stub returns a minimal tag so callers can test wiring.
        """
        header = b"\x6a"  # APPLICATION 10 (AS-REQ)
        body = self.realm.encode() + b"\x00" + struct.pack(">I", self.nonce)
        length = len(body)
        return header + struct.pack(">H", length) + body


@dataclass
class ASRep:
    client: PrincipalName
    realm: str
    ticket_data: bytes = b""
    enc_part: bytes = b""
    encryption_type: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1
    error_code: int | None = None


@dataclass
class TGSReq:
    client: PrincipalName
    realm: str
    server: PrincipalName
    tgt: bytes = b""
    nonce: int = 0
    etypes: list[EncryptionType] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        header = b"\x6c"  # APPLICATION 12 (TGS-REQ)
        body = self.realm.encode() + b"\x00" + struct.pack(">I", self.nonce)
        length = len(body)
        return header + struct.pack(">H", length) + body


@dataclass
class TGSRep:
    server: PrincipalName
    realm: str
    ticket_data: bytes = b""
    enc_part: bytes = b""
    encryption_type: EncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1


def build_as_req(
    username: str,
    realm: str,
    etypes: list[EncryptionType] | None = None,
    pa_enc_timestamp: bytes | None = None,
) -> ASReq:
    """Build an AS-REQ for the given principal."""
    if etypes is None:
        etypes = [EncryptionType.AES256_CTS_HMAC_SHA1, EncryptionType.RC4_HMAC]

    client = PrincipalName(name_type=1, components=[username])
    server = PrincipalName(name_type=2, components=["krbtgt", realm])
    nonce = struct.unpack(">I", struct.pack(">I", hash(username) & 0xFFFFFFFF))[0]

    pa_data: list[dict[str, Any]] = []
    if pa_enc_timestamp is not None:
        pa_data.append({"type": 2, "value": pa_enc_timestamp})

    return ASReq(
        client=client,
        realm=realm.upper(),
        server=server,
        nonce=nonce,
        etypes=etypes,
        pa_data=pa_data,
    )


def build_tgs_req(
    username: str,
    realm: str,
    service: str,
    tgt: bytes,
    etypes: list[EncryptionType] | None = None,
) -> TGSReq:
    """Build a TGS-REQ for a service ticket."""
    if etypes is None:
        etypes = [EncryptionType.AES256_CTS_HMAC_SHA1, EncryptionType.RC4_HMAC]

    client = PrincipalName(name_type=1, components=[username])
    sname_parts = service.split("/")
    server = PrincipalName(name_type=2, components=sname_parts)

    nonce = struct.unpack(">I", struct.pack(">I", hash(service) & 0xFFFFFFFF))[0]

    return TGSReq(
        client=client,
        realm=realm.upper(),
        server=server,
        tgt=tgt,
        nonce=nonce,
        etypes=etypes,
    )


def parse_as_rep(data: bytes) -> ASRep:
    """Parse an AS-REP from raw bytes.

    Full ASN.1 decoding requires pyasn1; this stub validates the
    APPLICATION tag and extracts realm as proof-of-concept.
    """
    if not data or data[0] != 0x6B:
        code = data[0] if data else -1
        if data and data[0] == 0x7E:
            raise KerberosError(KDC_ERR_PREAUTH_REQUIRED, "pre-auth required")
        raise KerberosError(code, "unexpected tag")

    length = struct.unpack(">H", data[1:3])[0]
    body = data[3 : 3 + length]
    realm_end = body.index(b"\x00") if b"\x00" in body else len(body)
    realm = body[:realm_end].decode(errors="replace")

    return ASRep(
        client=PrincipalName(),
        realm=realm,
        ticket_data=body[realm_end + 1 :] if realm_end + 1 < len(body) else b"",
    )


def parse_tgs_rep(data: bytes) -> TGSRep:
    """Parse a TGS-REP from raw bytes."""
    if not data or data[0] != 0x6D:
        code = data[0] if data else -1
        raise KerberosError(code, "unexpected TGS-REP tag")

    length = struct.unpack(">H", data[1:3])[0]
    body = data[3 : 3 + length]
    realm_end = body.index(b"\x00") if b"\x00" in body else len(body)
    realm = body[:realm_end].decode(errors="replace")

    return TGSRep(
        server=PrincipalName(),
        realm=realm,
        ticket_data=body[realm_end + 1 :] if realm_end + 1 < len(body) else b"",
    )
