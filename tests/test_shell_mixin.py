"""Tests for adxpl.core.shell_mixin AD-specific shell staging."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adxpl.core.shell_mixin import (
    AD_SHELL_TYPES,
    _ad_payload,
    get_session_manager,
    spawn_ad_shell,
)


def test_ad_shell_types_tuple():
    assert isinstance(AD_SHELL_TYPES, tuple)
    assert len(AD_SHELL_TYPES) >= 8


def test_ad_shell_types_contents():
    assert "powershell" in AD_SHELL_TYPES
    assert "powershell_b64" in AD_SHELL_TYPES
    assert "cmd_nc" in AD_SHELL_TYPES
    assert "ps_amsi_bypass" in AD_SHELL_TYPES
    assert "ps_clm_bypass" in AD_SHELL_TYPES
    assert "ps_download_cradle" in AD_SHELL_TYPES
    assert "wmi_process_shell" in AD_SHELL_TYPES


def test_ad_payload_amsi_bypass():
    payload = _ad_payload("ps_amsi_bypass", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "AmsiUtils" in payload


def test_ad_payload_clm_bypass():
    payload = _ad_payload("ps_clm_bypass", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "Invoke-Expression" in payload


def test_ad_payload_download_cradle():
    payload = _ad_payload("ps_download_cradle", "10.0.0.1", 8080)
    assert "http://10.0.0.1:8080/shell.ps1" in payload


def test_ad_payload_wmi_process():
    payload = _ad_payload("wmi_process_shell", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "cmd.exe" in payload


def test_ad_payload_fallback_to_core():
    payload = _ad_payload("bash", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "4444" in payload


def test_session_manager_singleton():
    mgr1 = get_session_manager()
    mgr2 = get_session_manager()
    assert mgr1 is mgr2


def test_spawn_ad_shell_callable():
    assert callable(spawn_ad_shell)
