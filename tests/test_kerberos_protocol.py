"""Tests for adxpl.core.kerberos protocol engine."""

from __future__ import annotations

import struct

import pytest

from adxpl.core.kerberos.protocol import (
    ASReq,
    EncryptionType,
    KerberosError,
    PrincipalName,
    TGSReq,
    build_as_req,
    build_tgs_req,
    parse_as_rep,
    parse_tgs_rep,
)


class TestEncryptionType:
    def test_values(self) -> None:
        assert EncryptionType.RC4_HMAC == 23
        assert EncryptionType.AES256_CTS_HMAC_SHA1 == 18
        assert EncryptionType.AES128_CTS_HMAC_SHA1 == 17
        assert EncryptionType.DES_CBC_CRC == 1

    def test_from_int(self) -> None:
        et = EncryptionType(23)
        assert et is EncryptionType.RC4_HMAC


class TestPrincipalName:
    def test_realm_string(self) -> None:
        p = PrincipalName(name_type=1, components=["admin"])
        assert p.realm_string == "admin"

    def test_realm_string_multi(self) -> None:
        p = PrincipalName(name_type=2, components=["krbtgt", "CORP.LOCAL"])
        assert p.realm_string == "krbtgt/CORP.LOCAL"


class TestBuildASReq:
    def test_basic(self) -> None:
        req = build_as_req("jdoe", "CORP.LOCAL")
        assert isinstance(req, ASReq)
        assert req.realm == "CORP.LOCAL"
        assert req.client.components == ["jdoe"]
        assert req.server.components == ["krbtgt", "CORP.LOCAL"]
        assert EncryptionType.AES256_CTS_HMAC_SHA1 in req.etypes

    def test_custom_etypes(self) -> None:
        req = build_as_req("user", "TEST.COM", etypes=[EncryptionType.RC4_HMAC])
        assert req.etypes == [EncryptionType.RC4_HMAC]

    def test_with_pa_data(self) -> None:
        req = build_as_req("user", "TEST.COM", pa_enc_timestamp=b"\x01\x02")
        assert len(req.pa_data) == 1
        assert req.pa_data[0]["type"] == 2

    def test_to_bytes(self) -> None:
        req = build_as_req("user", "REALM.COM")
        data = req.to_bytes()
        assert data[0:1] == b"\x6a"
        assert b"REALM.COM" in data


class TestBuildTGSReq:
    def test_basic(self) -> None:
        req = build_tgs_req("user", "CORP.LOCAL", "cifs/dc01.corp.local", b"\x00" * 16)
        assert isinstance(req, TGSReq)
        assert req.server.components == ["cifs", "dc01.corp.local"]
        assert req.tgt == b"\x00" * 16

    def test_to_bytes(self) -> None:
        req = build_tgs_req("u", "R.COM", "HTTP/web", b"tgt")
        data = req.to_bytes()
        assert data[0:1] == b"\x6c"


class TestParseASRep:
    def test_valid(self) -> None:
        realm = b"TEST.COM"
        body = realm + b"\x00" + b"ticket_data"
        header = b"\x6b" + struct.pack(">H", len(body))
        data = header + body
        rep = parse_as_rep(data)
        assert rep.realm == "TEST.COM"
        assert rep.ticket_data == b"ticket_data"

    def test_preauth_required(self) -> None:
        data = b"\x7e\x00\x04test"
        with pytest.raises(KerberosError) as exc:
            parse_as_rep(data)
        assert "pre-auth required" in str(exc.value)

    def test_unexpected_tag(self) -> None:
        with pytest.raises(KerberosError):
            parse_as_rep(b"\xff\x00\x00")

    def test_empty(self) -> None:
        with pytest.raises(KerberosError):
            parse_as_rep(b"")


class TestParseTGSRep:
    def test_valid(self) -> None:
        realm = b"CORP"
        body = realm + b"\x00" + b"svc_ticket"
        header = b"\x6d" + struct.pack(">H", len(body))
        data = header + body
        rep = parse_tgs_rep(data)
        assert rep.realm == "CORP"

    def test_invalid_tag(self) -> None:
        with pytest.raises(KerberosError):
            parse_tgs_rep(b"\x6b\x00\x00")
