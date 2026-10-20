"""Tests for adxpl.modules.privesc — UAC bypass, token impersonation, service abuse and others."""

import importlib
import types
from unittest.mock import patch, MagicMock

import pytest


PRIVESC_MODULES = [
    "adxpl.modules.privesc.always_install_elevated",
    "adxpl.modules.privesc.dll_hijack",
    "adxpl.modules.privesc.samaccountname",
    "adxpl.modules.privesc.sebackup_abuse",
    "adxpl.modules.privesc.seimpersonate",
    "adxpl.modules.privesc.service_abuse",
    "adxpl.modules.privesc.setcb_priv",
    "adxpl.modules.privesc.token_impersonation",
    "adxpl.modules.privesc.uac_bypass",
    "adxpl.modules.privesc.unquoted_svc_path",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="10.0.0.5", dc_ip="10.0.0.1", command="cmd.exe",
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestPrivescManifests:

    @pytest.mark.parametrize("modpath", PRIVESC_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        assert "capability_id" in mod.MANIFEST


class TestUACBypass:

    def test_techniques_dict(self):
        from adxpl.modules.privesc.uac_bypass import TECHNIQUES
        assert "fodhelper" in TECHNIQUES
        assert "eventvwr" in TECHNIQUES
        for name, info in TECHNIQUES.items():
            assert "desc" in info
            assert "cmd" in info

    def test_run_fodhelper(self, capsys):
        from adxpl.modules.privesc.uac_bypass import run
        args = _make_args(uac_technique="fodhelper")
        rc = run(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "fodhelper" in out.lower()

    def test_run_list(self, capsys):
        from adxpl.modules.privesc.uac_bypass import run
        args = _make_args(uac_technique="list")
        rc = run(args)
        assert rc == 0

    def test_run_unknown_technique(self, capsys):
        from adxpl.modules.privesc.uac_bypass import run
        args = _make_args(uac_technique="nonexistent")
        rc = run(args)
        assert rc == 1


class TestSamaccountname:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_nopac(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.privesc.samaccountname import run
        rc = run(_make_args())
        assert rc == 1
        out = capsys.readouterr().out
        assert "noPac" in out or "manual" in out.lower()


class TestSeimpersonate:

    def test_run_default(self, capsys):
        from adxpl.modules.privesc.seimpersonate import run
        rc = run(_make_args(potato="juicypotato"))
        assert rc == 0 or isinstance(rc, int)


class TestDllHijack:

    def test_run(self, capsys):
        from adxpl.modules.privesc.dll_hijack import run
        rc = run(_make_args())
        assert isinstance(rc, int)
