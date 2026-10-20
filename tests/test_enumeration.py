"""Tests for adxpl.modules.enumeration — LDAP enum, SPN scan, BloodHound, DNS, delegation."""

import importlib
import os
import types
from unittest.mock import patch, MagicMock

import pytest


ENUMERATION_MODULES = [
    "adxpl.modules.enumeration.acl_scanner",
    "adxpl.modules.enumeration.adacl_scanner",
    "adxpl.modules.enumeration.adalanche",
    "adxpl.modules.enumeration.adcs_enum",
    "adxpl.modules.enumeration.adrecon",
    "adxpl.modules.enumeration.ad_miner",
    "adxpl.modules.enumeration.bloodhound_collect",
    "adxpl.modules.enumeration.bloodhound_ingestor",
    "adxpl.modules.enumeration.delegation_enum",
    "adxpl.modules.enumeration.dns_enum",
    "adxpl.modules.enumeration.gmsa_dump",
    "adxpl.modules.enumeration.gpo_enum",
    "adxpl.modules.enumeration.laps_dump",
    "adxpl.modules.enumeration.ldapdomaindump",
    "adxpl.modules.enumeration.ldap_enum",
    "adxpl.modules.enumeration.maq_enum",
    "adxpl.modules.enumeration.plumhound",
    "adxpl.modules.enumeration.pywerview",
    "adxpl.modules.enumeration.spn_scan",
    "adxpl.modules.enumeration.trust_map",
]


def _make_args(**kw):
    ns = types.SimpleNamespace(
        domain="test.local", username="admin", password="P@ss",
        target="dc01.test.local", dc_ip="10.0.0.1",
        output="/tmp/adxpl_test_out",
        lm_hash="", nt_hash="",
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class TestEnumerationManifests:

    @pytest.mark.parametrize("modpath", ENUMERATION_MODULES)
    def test_manifest_and_run(self, modpath):
        mod = importlib.import_module(modpath)
        assert hasattr(mod, "MANIFEST")
        assert hasattr(mod, "run")
        m = mod.MANIFEST
        assert "capability_id" in m
        assert "mitre" in m


class TestLdapEnum:

    @patch("adxpl.modules.enumeration.ldap_enum.connect")
    @patch("adxpl.modules.enumeration.ldap_enum.get_base_dn")
    @patch("adxpl.modules.enumeration.ldap_enum.ADCredential.from_args")
    def test_run_with_mocked_ldap(self, mock_cred, mock_base, mock_conn, capsys):
        mock_cred.return_value = MagicMock(
            username="admin", password="P@ss", domain="test.local",
            lm_hash="", nt_hash=""
        )
        mock_base.return_value = "DC=test,DC=local"
        conn = MagicMock()
        conn.entries = []
        conn.search = MagicMock(return_value=True)
        mock_conn.return_value = conn

        from adxpl.modules.enumeration.ldap_enum import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestBloodhoundCollect:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_bloodhound(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.enumeration.bloodhound_collect import run
        rc = run(_make_args())
        assert isinstance(rc, int)


class TestDnsEnum:

    @patch("shutil.which", return_value=None)
    @patch("adxpl.core.credential.ADCredential.from_args")
    def test_run_no_tools(self, mock_cred, mock_which, capsys):
        mock_cred.return_value = MagicMock(
            username="u", password="p", domain="d",
            lm_hash="", nt_hash=""
        )
        from adxpl.modules.enumeration.dns_enum import run
        rc = run(_make_args())
        assert isinstance(rc, int)
