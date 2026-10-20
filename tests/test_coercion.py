"""Tests for adxpl.modules.coercion — PetitPotam, PrinterBug, ShadowCoerce and others."""

import importlib
import types
from unittest.mock import patch, MagicMock

import pytest


COERCION_MODULES = [
    "adxpl.modules.coercion.petitpotam",
    "adxpl.modules.coercion.printerbug",
    "adxpl.modules.coercion.shadowcoerce",
    "adxpl.modules.coercion.dfscoerce",
    "adxpl.modules.coercion.coercer_multi",
    "adxpl.modules.coercion.coerce_scanner",
    "adxpl.modules.coercion.cheeseounce",
    "adxpl.modules.coercion.efspotato",
    "adxpl.modules.coercion.remotepotato",
    "adxpl.modules.coercion.webclient_coerce",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="dc01.test.local", listener="10.0.0.99",
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestCoercionManifests:
    """All coercion modules must expose MANIFEST and run."""

    @pytest.mark.parametrize("modpath", COERCION_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        assert "capability_id" in mod.MANIFEST


class TestPetitPotam:

    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_missing_listener(self, mock_cred, capsys):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.coercion.petitpotam import run
        args = _make_args(listener=None)
        rc = run(args)
        assert rc == 1
        assert "listener" in capsys.readouterr().err.lower()

    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_impacket_not_installed(self, mock_cred):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.coercion.petitpotam import run
        with patch.dict("sys.modules", {"impacket": None, "impacket.dcerpc": None,
                                         "impacket.dcerpc.v5": None,
                                         "impacket.dcerpc.v5.transport": None}):
            args = _make_args()
            rc = run(args)
            assert isinstance(rc, int)


class TestEfspotato:
    """efspotato is info-only, should always return 0."""

    def test_run_returns_zero(self, capsys):
        from adxpl.modules.coercion.efspotato import run
        rc = run(_make_args())
        assert rc == 0


class TestRemotepotato:
    """remotepotato is info-only."""

    def test_run_returns_zero(self, capsys):
        from adxpl.modules.coercion.remotepotato import run
        rc = run(_make_args())
        assert rc == 0
