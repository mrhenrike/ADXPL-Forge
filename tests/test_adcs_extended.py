"""Tests for adxpl.modules.adcs — extended ESC checks, locksmith, pass_the_cert, pkinit."""

import importlib
import types
from unittest.mock import patch, MagicMock

import pytest


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="dc01.test.local", dc_ip="10.0.0.1",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestADCSEscExtended:
    """Tests for adcs_esc_extended.py."""

    def test_manifest_exists(self):
        mod = importlib.import_module("adxpl.modules.adcs.adcs_esc_extended")
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")

    @patch("adxpl.core.credential.ADCredential.from_args")
    @patch("shutil.which", return_value=None)
    def test_run_no_certipy(self, mock_which, mock_cred, capsys):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.adcs.adcs_esc_extended import run
        args = _make_args(esc="ESC9")
        rc = run(args)
        assert isinstance(rc, int)

    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_unknown_esc(self, mock_cred, capsys):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.adcs.adcs_esc_extended import run
        args = _make_args(esc="ESC999")
        rc = run(args)
        assert isinstance(rc, int)


class TestLocksmithScan:
    """Tests for locksmith_scan.py."""

    def test_manifest_exists(self):
        mod = importlib.import_module("adxpl.modules.adcs.locksmith_scan")
        assert hasattr(mod, "MANIFEST")
        assert mod.MANIFEST["capability_id"]

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.adcs.locksmith_scan import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestPassTheCert:
    """Tests for pass_the_cert.py."""

    def test_manifest_exists(self):
        mod = importlib.import_module("adxpl.modules.adcs.pass_the_cert")
        assert hasattr(mod, "MANIFEST")

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.adcs.pass_the_cert import run
        rc = run(_make_args(template="/tmp/cert.pfx"))
        assert isinstance(rc, int)


class TestPkinitTools:
    """Tests for pkinit_tools.py."""

    def test_manifest_exists(self):
        mod = importlib.import_module("adxpl.modules.adcs.pkinit_tools")
        assert hasattr(mod, "MANIFEST")

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.adcs.pkinit_tools import run
        rc = run(_make_args())
        assert isinstance(rc, int)
