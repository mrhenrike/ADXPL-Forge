"""Tests for adxpl.core.kerberos ticket cache."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from adxpl.core.kerberos.ticket import (
    CachedTicket,
    TicketCache,
    export_kirbi,
    import_ccache,
)


class TestTicketCache:
    def test_empty(self) -> None:
        cache = TicketCache()
        assert len(cache) == 0
        assert cache.tickets == []
        assert cache.default_principal == ""

    def test_add_and_find(self) -> None:
        cache = TicketCache()
        t = CachedTicket(client="admin@CORP", server="krbtgt/CORP", realm="CORP")
        cache.add(t)
        assert len(cache) == 1
        assert cache.default_principal == "admin@CORP"
        assert cache.find("krbtgt/CORP") is t

    def test_find_missing(self) -> None:
        cache = TicketCache()
        cache.add(CachedTicket(server="a"))
        assert cache.find("b") is None

    def test_clear(self) -> None:
        cache = TicketCache()
        cache.add(CachedTicket(client="u", server="s"))
        cache.clear()
        assert len(cache) == 0
        assert cache.default_principal == ""

    def test_multiple_tickets(self) -> None:
        cache = TicketCache()
        cache.add(CachedTicket(client="u@R", server="svc1"))
        cache.add(CachedTicket(client="u@R", server="svc2"))
        assert len(cache) == 2
        assert cache.default_principal == "u@R"


class TestImportCcache:
    def test_valid_header(self, tmp_path: Path) -> None:
        ccache = struct.pack(">HH", 0x0504, 0x0004) + b"\x00" * 64
        path = tmp_path / "test.ccache"
        path.write_bytes(ccache)
        cache = import_ccache(path)
        assert isinstance(cache, TicketCache)
        assert "test.ccache" in cache.default_principal

    def test_invalid_magic(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.ccache"
        path.write_bytes(b"\x00\x01\x00\x02")
        with pytest.raises(ValueError, match="invalid ccache magic"):
            import_ccache(path)

    def test_too_small(self, tmp_path: Path) -> None:
        path = tmp_path / "tiny.ccache"
        path.write_bytes(b"\x00")
        with pytest.raises(ValueError, match="too small"):
            import_ccache(path)


class TestExportKirbi:
    def test_basic(self) -> None:
        t = CachedTicket(
            server="cifs/dc01",
            realm="CORP",
            ticket_data=b"\xaa\xbb",
        )
        kirbi = export_kirbi(t)
        assert kirbi[0:1] == b"\x76"
        assert b"CORP" in kirbi
        assert b"cifs/dc01" in kirbi
        assert b"\xaa\xbb" in kirbi

    def test_empty_ticket(self) -> None:
        t = CachedTicket(server="", realm="", ticket_data=b"")
        kirbi = export_kirbi(t)
        assert kirbi[0:1] == b"\x76"
