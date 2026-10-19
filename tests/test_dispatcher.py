"""Tests for adxpl.core.dispatcher module routing."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adxpl.core.dispatcher import _MODULE_MAP, dispatch


def test_module_map_categories():
    expected = {
        "enum", "attack", "lateral", "persist", "credential",
        "coercion", "relay", "acl", "trust", "spray",
        "campaign", "lolbins", "evasion", "byovd", "privesc",
        "exploit", "kernel", "emulation", "adcs", "audit",
        "exchange", "sccm", "azuread", "impacket", "shell",
    }
    assert set(_MODULE_MAP.keys()) == expected


def test_module_map_not_empty():
    for category, modules in _MODULE_MAP.items():
        assert len(modules) > 0, f"Category {category} is empty"


def test_total_module_count():
    total = sum(len(m) for m in _MODULE_MAP.values())
    assert total >= 200


def test_known_modules_present():
    assert "bloodhound" in _MODULE_MAP["enum"]
    assert "kerberoast" in _MODULE_MAP["attack"]
    assert "pth" in _MODULE_MAP["lateral"]
    assert "golden-ticket" in _MODULE_MAP["persist"]
    assert "lsassy" in _MODULE_MAP["credential"]
    assert "petitpotam" in _MODULE_MAP["coercion"]
    assert "ntlmrelayx" in _MODULE_MAP["relay"]
    assert "dacl-edit" in _MODULE_MAP["acl"]
    assert "trust-ticket" in _MODULE_MAP["trust"]
    assert "password-spray" in _MODULE_MAP["spray"]
    assert "certutil" in _MODULE_MAP["lolbins"]
    assert "amsi-bypass" in _MODULE_MAP["evasion"]
    assert "zerologon" in _MODULE_MAP["exploit"]
    assert "token-steal" in _MODULE_MAP["kernel"]


def test_module_paths_valid_format():
    for category, modules in _MODULE_MAP.items():
        for name, path in modules.items():
            assert path.startswith("adxpl.modules."), f"{category}/{name}: {path}"
            assert ".." not in path


def test_dispatch_unknown_returns_1(capsys):
    import argparse
    args = argparse.Namespace(command="nonexistent", module="nope")
    rc = dispatch(args)
    assert rc == 1


def test_ldap_session_base_dn():
    from adxpl.core.ldap_session import get_base_dn
    assert get_base_dn("corp.local") == "DC=corp,DC=local"
    assert get_base_dn("sub.corp.example.com") == "DC=sub,DC=corp,DC=example,DC=com"
    assert get_base_dn("single") == "DC=single"
