"""Domain user enumeration via CLDAP NetLogon ping (UDP 389).

Unauthenticated user enumeration against Active Directory Domain Controllers
using CLDAP (Connectionless LDAP) NetLogon responses. Sends CLDAP search
requests containing candidate usernames; the DC's response opcode reveals
user existence: LOGON_SAM_USER_UNKNOWN_EX (0x13) indicates the user does not
exist; any other response means the account was found.

Zero-authentication technique: requires only UDP 389 access to a DC.
No credentials needed. No account lockout risk (no authentication attempts).

Technique: Reino Mostert / SensePost (2018).
Source: https://github.com/jonaslejon/ad-autopwn (vendored userenum-cldap.py)
Requires: asn1tools
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.enumeration.userenum_cldap.v1",
    "safety_class": "INFORMATIONAL",
    "requires_authorization": True,
    "side_effects": ["udp_cldap_queries"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1087.002"],
    "source": "https://github.com/jonaslejon/ad-autopwn",
}

# CLDAP NetLogon response opcodes (MS-ADTS 6.3.3)
LOGON_SAM_USER_UNKNOWN_EX = 0x13
LOGON_SAM_LOGON_RESPONSE_EX = 0x17
LOGON_SAM_PAUSE_RESPONSE_EX = 0x18


def _find_userenum_cldap() -> str | None:
    """Locate the userenum-cldap.py script."""
    for name in ("userenum-cldap", "userenum-cldap.py"):
        path = shutil.which(name)
        if path:
            return path
    for d in ("/opt/tools/ad-autopwn", os.path.expanduser("~/tools/ad-autopwn")):
        candidate = os.path.join(d, "userenum-cldap.py")
        if os.path.isfile(candidate):
            return candidate
    return None


def _cldap_check_user(dc_ip: str, domain: str, username: str,
                      timeout: float = 3.0) -> bool | None:
    """Check if a user exists via CLDAP NetLogon ping.

    Returns True if user exists, False if not, None on error.
    """
    try:
        import asn1tools
    except ImportError:
        return None

    spec_text = '''
Foo DEFINITIONS IMPLICIT TAGS ::= BEGIN
LDAPMessage3 ::= SEQUENCE {
    messageID INTEGER,
    protocolOp CHOICE {
        searchRequest [APPLICATION 3] SEQUENCE {
            baseObject OCTET STRING,
            scope ENUMERATED {baseObject(0)},
            derefAliases ENUMERATED {neverDerefAliases(0)},
            sizeLimit INTEGER,
            timeLimit INTEGER,
            typesOnly BOOLEAN,
            filter CHOICE {
                and [0] SET OF CHOICE {
                    equalityMatch [3] SEQUENCE {
                        attributeDesc OCTET STRING,
                        assertionValue OCTET STRING
                    }
                }
            },
            attributes SEQUENCE OF OCTET STRING
        }
    }
}
END
'''
    schema = asn1tools.compile_string(spec_text, 'ber')

    netlogon_filter = {
        'and': [
            {'equalityMatch': {
                'attributeDesc': b'DnsDomain',
                'assertionValue': domain.encode()
            }},
            {'equalityMatch': {
                'attributeDesc': b'NtVer',
                'assertionValue': b'\x06\x00\x00\x00'
            }},
            {'equalityMatch': {
                'attributeDesc': b'User',
                'assertionValue': username.encode()
            }},
        ]
    }

    msg = {
        'messageID': 1,
        'protocolOp': ('searchRequest', {
            'baseObject': b'',
            'scope': 'baseObject',
            'derefAliases': 'neverDerefAliases',
            'sizeLimit': 0,
            'timeLimit': 0,
            'typesOnly': False,
            'filter': netlogon_filter,
            'attributes': [b'Netlogon'],
        })
    }

    try:
        encoded = schema.encode('LDAPMessage3', msg)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(encoded, (dc_ip, 389))
        data, _ = sock.recvfrom(4096)
        sock.close()

        # Parse response opcode from Netlogon attribute
        # The opcode is at a fixed offset in the response
        if len(data) > 25:
            # Find the Netlogon attribute value
            opcode_offset = data.find(b'\x17') if b'\x17' in data else -1
            if opcode_offset >= 0:
                return True  # Got a valid response, user exists
            if LOGON_SAM_USER_UNKNOWN_EX.to_bytes(1, 'little') in data[-50:]:
                return False
            return True  # Non-unknown response = user exists
        return None
    except socket.timeout:
        return None
    except Exception:
        return None


def run(args: Any) -> int:
    """Enumerate domain users via CLDAP NetLogon ping.

    Zero-auth user enumeration using CLDAP (UDP 389). Checks each
    candidate username against the DC's NetLogon response to determine
    existence without authentication.

    Args:
        args.target / args.dc_ip: Domain Controller IP.
        args.domain: AD domain FQDN (e.g., corp.local).
        args.userlist: Path to username wordlist file.
        args.username: Single username to check.
        args.timeout: Socket timeout per query in seconds (default 3).
    """
    dc_ip = getattr(args, "dc_ip", None) or getattr(args, "target", None)
    domain = getattr(args, "domain", None)
    userlist = getattr(args, "userlist", None)
    single_user = getattr(args, "username", None)
    timeout = getattr(args, "timeout", 3.0)

    print("[*] CLDAP User Enumeration (UDP 389)")
    print(f"[*] DC: {dc_ip}")
    print(f"[*] Domain: {domain}")

    if not dc_ip or not domain:
        print("[!] Requires --dc-ip and --domain", file=sys.stderr)
        return 1

    # Try external script first
    script = _find_userenum_cldap()
    if script and userlist:
        cmd = [sys.executable, script, dc_ip, domain, userlist]
        print("[*] CMD: {}".format(" ".join(cmd)))
        result = subprocess.run(cmd, text=True)
        return result.returncode

    # Built-in implementation
    users_to_check = []
    if single_user:
        users_to_check = [single_user]
    elif userlist and os.path.isfile(userlist):
        with open(userlist) as f:
            users_to_check = [line.strip() for line in f if line.strip()]
    else:
        print("[!] Provide --userlist <file> or --username <user>", file=sys.stderr)
        return 1

    print(f"[*] Checking {len(users_to_check)} username(s)")
    found = []

    for user in users_to_check:
        result = _cldap_check_user(dc_ip, domain, user, timeout)
        if result is True:
            print(f"[+] {user} exists")
            found.append(user)
        elif result is False:
            pass  # user not found, silent
        else:
            print(f"[-] {user}: error/timeout")

    print(f"\n[*] Found {len(found)} valid user(s) out of {len(users_to_check)} checked")
    return 0
