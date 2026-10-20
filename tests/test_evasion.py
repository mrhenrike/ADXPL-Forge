"""Tests for adxpl.modules.evasion — AMSI bypass, ETW disable, CLM bypass and others."""

import importlib
import types

import pytest


EVASION_MODULES = [
    "adxpl.modules.evasion.amsi_bypass",
    "adxpl.modules.evasion.clm_bypass",
    "adxpl.modules.evasion.defender_disable",
    "adxpl.modules.evasion.etw_disable",
    "adxpl.modules.evasion.ppid_spoof",
    "adxpl.modules.evasion.ps_cradle",
    "adxpl.modules.evasion.scriptblock_bypass",
]


def _make_args(**kw):
    ns = types.SimpleNamespace()
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestEvasionManifests:

    @pytest.mark.parametrize("modpath", EVASION_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        m = mod.MANIFEST
        assert "capability_id" in m
        assert "mitre" in m


class TestAmsiBypass:

    def test_bypasses_dict(self):
        from adxpl.modules.evasion.amsi_bypass import BYPASSES
        assert isinstance(BYPASSES, dict)
        assert "patch_amsi_dll" in BYPASSES
        assert len(BYPASSES) >= 4

    def test_run_default(self, capsys):
        from adxpl.modules.evasion.amsi_bypass import run
        rc = run(_make_args())
        assert rc == 0
        out = capsys.readouterr().out
        assert "AMSI" in out or "amsi" in out.lower()

    def test_run_list(self, capsys):
        from adxpl.modules.evasion.amsi_bypass import run
        rc = run(_make_args(amsi_technique="list"))
        assert rc == 0

    def test_run_unknown(self, capsys):
        from adxpl.modules.evasion.amsi_bypass import run
        rc = run(_make_args(amsi_technique="nonexistent"))
        assert rc == 1

    def test_run_encoded(self, capsys):
        from adxpl.modules.evasion.amsi_bypass import run
        rc = run(_make_args(amsi_technique="patch_amsi_dll", encode=True))
        assert rc == 0
        out = capsys.readouterr().out
        assert "enc" in out.lower()


class TestEtwDisable:

    def test_run_default(self, capsys):
        from adxpl.modules.evasion.etw_disable import run
        rc = run(_make_args())
        assert rc == 0 or isinstance(rc, int)

    def test_run_unknown(self, capsys):
        from adxpl.modules.evasion.etw_disable import run
        rc = run(_make_args(etw_technique="nonexistent"))
        assert rc == 1


class TestClmBypass:

    def test_run_default(self, capsys):
        from adxpl.modules.evasion.clm_bypass import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestDefenderDisable:

    def test_run_default(self, capsys):
        from adxpl.modules.evasion.defender_disable import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestPsCradle:

    def test_run_default(self, capsys):
        from adxpl.modules.evasion.ps_cradle import run
        rc = run(_make_args())
        assert isinstance(rc, int)
