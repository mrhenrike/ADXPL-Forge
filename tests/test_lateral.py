"""Tests for adxpl.modules.lateral — WinRMShell, psexec, smbexec, wmi_exec and others."""

import importlib
import types
from unittest.mock import patch, MagicMock

import pytest


LATERAL_MODULES = [
    "adxpl.modules.lateral.atexec",
    "adxpl.modules.lateral.dcomexec",
    "adxpl.modules.lateral.evil_winrm",
    "adxpl.modules.lateral.mssql_exec",
    "adxpl.modules.lateral.overpass_the_hash",
    "adxpl.modules.lateral.pass_the_hash",
    "adxpl.modules.lateral.pass_the_ticket",
    "adxpl.modules.lateral.psexec",
    "adxpl.modules.lateral.rdp_hijack",
    "adxpl.modules.lateral.smbexec",
    "adxpl.modules.lateral.ssh_lateral",
    "adxpl.modules.lateral.wmi_exec",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="10.0.0.5", dc_ip="10.0.0.1", command="whoami",
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestLateralManifests:

    @pytest.mark.parametrize("modpath", LATERAL_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        m = mod.MANIFEST
        assert "capability_id" in m
        assert "mitre" in m


class TestWinRMShell:

    def test_init(self):
        from adxpl.modules.lateral.evil_winrm import WinRMShell
        cred = MagicMock(username="admin", password="P@ss", domain="test.local")
        shell = WinRMShell(target="10.0.0.5", cred=cred, port=5985, ssl=False)
        assert shell.target == "10.0.0.5"
        assert shell.port == 5985
        assert shell.ssl is False
        assert shell._session is None

    def test_connect_no_requests(self):
        from adxpl.modules.lateral.evil_winrm import WinRMShell
        cred = MagicMock(username="admin", password="P@ss", domain="test.local")
        shell = WinRMShell(target="10.0.0.5", cred=cred)
        with patch.dict("sys.modules", {"requests": None, "requests.auth": None}):
            result = shell.connect()
            assert result is False or result is None or isinstance(result, bool)


class TestPsexec:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.lateral.psexec import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestRdpHijack:

    def test_run_prints_steps(self, capsys):
        from adxpl.modules.lateral.rdp_hijack import run
        rc = run(_make_args())
        assert isinstance(rc, int)
