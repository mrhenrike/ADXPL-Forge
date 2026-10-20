"""Tests for adxpl.modules.persistence — golden/silver ticket, skeleton key, GPO abuse."""

import importlib
import types
from unittest.mock import patch, MagicMock

import pytest


PERSISTENCE_MODULES = [
    "adxpl.modules.persistence.admin_sd_holder",
    "adxpl.modules.persistence.dcshadow",
    "adxpl.modules.persistence.diamond_ticket_persist",
    "adxpl.modules.persistence.dsrm_backdoor",
    "adxpl.modules.persistence.dsrm_password",
    "adxpl.modules.persistence.golden_ticket",
    "adxpl.modules.persistence.gpo_abuse",
    "adxpl.modules.persistence.machine_account",
    "adxpl.modules.persistence.sid_history",
    "adxpl.modules.persistence.silver_ticket",
    "adxpl.modules.persistence.skeleton_key",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="dc01.test.local", dc_ip="10.0.0.1",
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestPersistenceManifests:

    @pytest.mark.parametrize("modpath", PERSISTENCE_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        m = mod.MANIFEST
        assert "capability_id" in m


class TestGoldenTicket:

    def test_missing_krbtgt_hash(self, capsys):
        from adxpl.modules.persistence.golden_ticket import run
        rc = run(_make_args())
        assert rc == 1
        err = capsys.readouterr().err
        assert "krbtgt" in err.lower()

    def test_missing_domain_sid(self, capsys):
        from adxpl.modules.persistence.golden_ticket import run
        rc = run(_make_args(krbtgt_hash="aad3b435b51404eeaad3b435b51404ee"))
        assert rc == 1
        err = capsys.readouterr().err
        assert "sid" in err.lower()

    @patch("shutil.which", return_value=None)
    def test_run_with_params_no_tools(self, mock_which, capsys):
        from adxpl.modules.persistence.golden_ticket import run
        rc = run(_make_args(
            krbtgt_hash="aad3b435b51404eeaad3b435b51404ee",
            domain_sid="S-1-5-21-123456789-123456789-123456789",
        ))
        assert isinstance(rc, int)


class TestSilverTicket:

    def test_missing_service_hash(self, capsys):
        from adxpl.modules.persistence.silver_ticket import run
        rc = run(_make_args())
        assert rc == 1

    @patch("shutil.which", return_value=None)
    def test_run_with_params(self, mock_which, capsys):
        from adxpl.modules.persistence.silver_ticket import run
        rc = run(_make_args(
            service_hash="aad3b435b51404eeaad3b435b51404ee",
            domain_sid="S-1-5-21-123456789-123456789-123456789",
        ))
        assert isinstance(rc, int)


class TestSkeletonKey:

    @patch("shutil.which", return_value=None)
    def test_run_no_tools(self, mock_which, capsys):
        from adxpl.modules.persistence.skeleton_key import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestGpoAbuse:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.persistence.gpo_abuse import run
        rc = run(_make_args(command="net user evil P@ss /add", target_dn="OU=test"))
        assert isinstance(rc, int)
