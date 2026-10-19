"""Tests for adxpl.core.credential ADCredential handling."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adxpl.core.credential import ADCredential


def test_from_args_password():
    args = argparse.Namespace(
        username="admin", password="P@ssw0rd",
        domain="corp.local", hashes=None,
    )
    cred = ADCredential.from_args(args)
    assert cred.username == "admin"
    assert cred.password == "P@ssw0rd"
    assert cred.domain == "corp.local"
    assert cred.has_password
    assert not cred.has_hash


def test_from_args_hash():
    args = argparse.Namespace(
        username="admin", password=None,
        domain="corp.local",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    cred = ADCredential.from_args(args)
    assert cred.has_hash
    assert not cred.has_password
    assert cred.nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert cred.lm_hash == "aad3b435b51404eeaad3b435b51404ee"
    assert cred.impacket_hash == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_from_args_empty():
    args = argparse.Namespace(username=None, password=None, domain="test.local", hashes=None)
    cred = ADCredential.from_args(args)
    assert not cred.has_password
    assert not cred.has_hash
    assert cred.impacket_hash == ""


def test_frozen_dataclass():
    cred = ADCredential(username="user", domain="test.local")
    try:
        cred.username = "other"
        raise AssertionError("Should raise FrozenInstanceError")
    except AttributeError:
        pass


def test_default_values():
    cred = ADCredential()
    assert cred.username is None
    assert cred.password is None
    assert cred.domain == ""
    assert cred.lm_hash == ""
    assert cred.nt_hash == ""
    assert cred.aes_key == ""
    assert cred.ticket == ""


def test_from_args_hash_single_part():
    args = argparse.Namespace(
        username="admin", password=None,
        domain="corp.local", hashes="31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    cred = ADCredential.from_args(args)
    assert cred.has_hash
    assert cred.nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_from_args_missing_hashes_attr():
    args = argparse.Namespace(username="user", password="pass", domain="d.local")
    cred = ADCredential.from_args(args)
    assert cred.has_password
    assert not cred.has_hash
