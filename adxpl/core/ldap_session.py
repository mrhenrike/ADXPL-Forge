"""LDAP session management for AD enumeration."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adxpl.core.credential import ADCredential

import ldap3
from ldap3 import NTLM, SIMPLE, Server, Connection, ALL


def connect(
    target: str,
    credential: "ADCredential",
    use_ssl: bool = False,
    port: int | None = None,
) -> Connection:
    if port is None:
        port = 636 if use_ssl else 389

    server = Server(target, port=port, use_ssl=use_ssl, get_info=ALL)

    if credential.has_hash:
        conn = Connection(
            server,
            user=f"{credential.domain}\\{credential.username}",
            password=credential.impacket_hash,
            authentication=NTLM,
            auto_bind=True,
        )
    elif credential.has_password:
        conn = Connection(
            server,
            user=f"{credential.domain}\\{credential.username}",
            password=credential.password,
            authentication=NTLM,
            auto_bind=True,
        )
    else:
        conn = Connection(server, auto_bind=True)

    return conn


def get_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))
