# Changelog

All notable changes to ADXPL-Forge will be documented in this file.

## [2.1.0] - 2026-10-19

### Added
- PEP 561 `py.typed` marker for downstream type checking
- `ruff` linter configuration with per-file-ignores for legacy exploit modules
- `mypy` type checker configuration (relaxed for exploit framework)
- `pytest` configuration in pyproject.toml
- GitHub Actions CI workflow: ruff lint gate + pytest matrix (py3.9-3.14)
- 36 new tests: shells shim, shell_mixin payloads, credential handling, dispatcher routing
- xpl-core shells integration via `adxpl.core.shells` shim
- AD-specific shell_mixin: ps_amsi_bypass, ps_clm_bypass, ps_download_cradle, wmi_process_shell

### Changed
- Auto-fixed 84 files via ruff (import sorting, format strings)
- Updated test_core.py to handle varied safety_class values across modules

### Fixed
- test_version assertion updated to match current package version

## [2.0.0] - 2026-09-23

### Added
- 219 modules across 25 categories
- Full AD attack chain: enumeration, Kerberos, ADCS, lateral movement, credential theft
- Coercion, relay, ACL abuse, trust attacks, privilege escalation
- Kernel exploits, CVE exploits, LOLBins, evasion, BYOVD
- Emulation framework (APT29, Atomic Red Team, Caldera, ransomware sim)
- Exchange, SCCM, Azure AD modules
- Impacket integration modules
