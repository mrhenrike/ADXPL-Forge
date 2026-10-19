"""Tests for ADXPL-Forge core modules."""

from __future__ import annotations

import argparse
import ast
import importlib
import os


def test_version():
    from adxpl import __cli__, __product__, __version__
    assert __version__ == "2.0.0"
    assert __product__ == "ADXPL-Forge"
    assert __cli__ == "axf"


def test_credential_from_args():
    from adxpl.core.credential import ADCredential
    args = argparse.Namespace(
        username="admin", password="P@ssw0rd",
        domain="corp.local", hashes=None,
    )
    cred = ADCredential.from_args(args)
    assert cred.username == "admin"
    assert cred.has_password
    assert not cred.has_hash


def test_credential_from_hash():
    from adxpl.core.credential import ADCredential
    args = argparse.Namespace(
        username="admin", password=None,
        domain="corp.local",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    cred = ADCredential.from_args(args)
    assert cred.has_hash
    assert not cred.has_password
    assert cred.nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert cred.impacket_hash == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_credential_empty():
    from adxpl.core.credential import ADCredential
    args = argparse.Namespace(username=None, password=None, domain="test.local", hashes=None)
    cred = ADCredential.from_args(args)
    assert not cred.has_password
    assert not cred.has_hash


def test_dispatcher_module_map():
    from adxpl.core.dispatcher import _MODULE_MAP
    assert "enum" in _MODULE_MAP
    assert "attack" in _MODULE_MAP
    assert "lateral" in _MODULE_MAP
    assert "persist" in _MODULE_MAP
    assert "bloodhound" in _MODULE_MAP["enum"]
    assert "kerberoast" in _MODULE_MAP["attack"]
    assert "pth" in _MODULE_MAP["lateral"]
    assert "golden-ticket" in _MODULE_MAP["persist"]


def test_cli_help(capsys):
    from adxpl.__main__ import main
    rc = main([])
    assert rc == 0


def test_cli_version(capsys):
    from adxpl.__main__ import main
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0


def test_all_modules_parse():
    """Verify all module .py files are valid Python."""
    base = os.path.join(os.path.dirname(__file__), "..", "adxpl", "modules")
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(".py") and f != "__init__.py":
                path = os.path.join(root, f)
                with open(path) as fh:
                    ast.parse(fh.read(), filename=path)


def test_all_modules_have_manifest():
    """Every module must declare a MANIFEST dict."""
    from adxpl.core.dispatcher import _MODULE_MAP
    for category, modules in _MODULE_MAP.items():
        for name, path in modules.items():
            mod = importlib.import_module(path)
            assert hasattr(mod, "MANIFEST"), f"{path} missing MANIFEST"
            assert hasattr(mod, "run"), f"{path} missing run()"
            manifest = mod.MANIFEST
            assert "capability_id" in manifest
            assert "safety_class" in manifest
            assert isinstance(manifest["safety_class"], str) and len(manifest["safety_class"]) > 0


def test_ldap_session_base_dn():
    from adxpl.core.ldap_session import get_base_dn
    assert get_base_dn("corp.local") == "DC=corp,DC=local"
    assert get_base_dn("sub.corp.example.com") == "DC=sub,DC=corp,DC=example,DC=com"


def test_esc_descriptions():
    from adxpl.modules.attack.adcs_abuse import ESC_DESCRIPTIONS
    assert len(ESC_DESCRIPTIONS) == 12
    for esc_id in [f"ESC{i}" for i in range(1, 13)]:
        assert esc_id in ESC_DESCRIPTIONS
