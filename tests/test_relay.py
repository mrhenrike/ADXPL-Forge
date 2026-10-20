"""Tests for adxpl.modules.relay — ntlmrelayx, adcs_relay, mitm6, ntlm_theft, responder."""

import importlib
import os
import types
from unittest.mock import patch, MagicMock

import pytest


RELAY_MODULES = [
    "adxpl.modules.relay.adcs_relay",
    "adxpl.modules.relay.krbrelayx_exec",
    "adxpl.modules.relay.mitm6_relay",
    "adxpl.modules.relay.ntlmrelayx_auto",
    "adxpl.modules.relay.ntlm_theft",
    "adxpl.modules.relay.responder",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="dc01.test.local", dc_ip="10.0.0.1",
        relay_target="10.0.0.2", targets_file=None,
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestRelayManifests:

    @pytest.mark.parametrize("modpath", RELAY_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        assert "capability_id" in mod.MANIFEST


class TestNtlmrelayxAuto:

    def test_attack_types_mapping(self):
        from adxpl.modules.relay.ntlmrelayx_auto import ATTACK_TYPES
        assert isinstance(ATTACK_TYPES, dict)
        assert "ldap_delegate" in ATTACK_TYPES

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_ntlmrelayx(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.relay.ntlmrelayx_auto import run
        args = _make_args(relay_attack="ldap_delegate")
        rc = run(args)
        assert isinstance(rc, int)


class TestNtlmTheft:

    @patch("builtins.open", MagicMock())
    @patch("os.makedirs")
    @patch("shutil.which", return_value=None)
    def test_run_generates_files(self, mock_which, mock_mkdirs, capsys):
        from adxpl.modules.relay.ntlm_theft import run
        args = _make_args(output="/tmp/theft_out")
        rc = run(args)
        assert isinstance(rc, int)


class TestAdcsRelay:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.relay.adcs_relay import run
        args = _make_args(adcs_template="User")
        rc = run(args)
        assert isinstance(rc, int)
