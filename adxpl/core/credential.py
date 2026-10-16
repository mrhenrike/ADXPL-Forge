"""Credential handling for AD authentication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ADCredential:
    username: str | None = None
    password: str | None = None
    domain: str = ""
    lm_hash: str = ""
    nt_hash: str = ""
    aes_key: str = ""
    ticket: str = ""

    @classmethod
    def from_args(cls, args: Any) -> "ADCredential":
        lm, nt = "", ""
        if hasattr(args, "hashes") and args.hashes:
            parts = args.hashes.split(":")
            lm = parts[0] if len(parts) > 0 else ""
            nt = parts[1] if len(parts) > 1 else parts[0]

        return cls(
            username=getattr(args, "username", None),
            password=getattr(args, "password", None),
            domain=getattr(args, "domain", ""),
            lm_hash=lm,
            nt_hash=nt,
        )

    @property
    def has_password(self) -> bool:
        return bool(self.password)

    @property
    def has_hash(self) -> bool:
        return bool(self.nt_hash)

    @property
    def impacket_hash(self) -> str:
        return f"{self.lm_hash}:{self.nt_hash}" if self.nt_hash else ""
