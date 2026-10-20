"""Kerberos protocol engine for ADXPL-Forge.

Provides low-level AS-REQ/TGS-REQ construction, ticket parsing,
encryption type handling and credential conversion utilities.
Higher-level attack modules (kerberoast, AS-REP roast, delegation abuse)
consume this engine through stable public helpers.
"""


from .protocol import (
    EncryptionType,
    KerberosError,
    build_as_req,
    build_tgs_req,
    parse_as_rep,
    parse_tgs_rep,
)
from .ticket import TicketCache, import_ccache, export_kirbi

__all__ = [
    "EncryptionType",
    "KerberosError",
    "TicketCache",
    "build_as_req",
    "build_tgs_req",
    "export_kirbi",
    "import_ccache",
    "parse_as_rep",
    "parse_tgs_rep",
]
