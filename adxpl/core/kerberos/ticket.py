"""Ticket cache management: ccache import/export and kirbi conversion."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CachedTicket:
    client: str = ""
    server: str = ""
    realm: str = ""
    key_type: int = 0
    key_data: bytes = b""
    auth_time: int = 0
    end_time: int = 0
    ticket_data: bytes = b""
    flags: int = 0


class TicketCache:
    """In-memory ticket cache compatible with MIT ccache format."""

    def __init__(self) -> None:
        self._tickets: list[CachedTicket] = []
        self._default_principal: str = ""

    @property
    def tickets(self) -> list[CachedTicket]:
        return list(self._tickets)

    @property
    def default_principal(self) -> str:
        return self._default_principal

    def add(self, ticket: CachedTicket) -> None:
        self._tickets.append(ticket)
        if not self._default_principal and ticket.client:
            self._default_principal = ticket.client

    def find(self, server: str) -> CachedTicket | None:
        for t in self._tickets:
            if t.server == server:
                return t
        return None

    def clear(self) -> None:
        self._tickets.clear()
        self._default_principal = ""

    def __len__(self) -> int:
        return len(self._tickets)


# ccache file format constants
_CCACHE_MAGIC = 0x0504
_CCACHE_VERSION = 0x0004


def import_ccache(path: str | Path) -> TicketCache:
    """Import tickets from a MIT ccache file."""
    data = Path(path).read_bytes()
    if len(data) < 4:
        raise ValueError("file too small for ccache")

    magic = struct.unpack(">HH", data[:4])
    if magic[0] != _CCACHE_MAGIC:
        raise ValueError(f"invalid ccache magic: 0x{magic[0]:04x}")

    cache = TicketCache()
    # Minimal parsing: real implementation would walk full ccache structure.
    # For now, validate header and return empty cache as proof-of-wiring.
    cache._default_principal = f"user@REALM (from {Path(path).name})"
    return cache


def export_kirbi(ticket: CachedTicket) -> bytes:
    """Export a single ticket to Rubeus .kirbi format (APPLICATION 22)."""
    # Kirbi is ASN.1 APPLICATION 22 wrapping a KRB-CRED
    # Stub: return tagged blob for downstream consumers
    tag = b"\x76"  # APPLICATION 22
    payload = (
        ticket.realm.encode()
        + b"\x00"
        + ticket.server.encode()
        + b"\x00"
        + ticket.ticket_data
    )
    length = len(payload)
    if length < 128:
        header = tag + struct.pack("B", length)
    else:
        header = tag + b"\x82" + struct.pack(">H", length)
    return header + payload
