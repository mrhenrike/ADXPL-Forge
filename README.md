<p align="center">
  <strong>ADXPL-Forge (AXF)</strong><br>
  Active Directory Attack and Audit Framework
</p>

<p align="center">
  <a href="https://github.com/mrhenrike/ADXPL-Forge/actions"><img src="https://github.com/mrhenrike/ADXPL-Forge/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-%3E%3D3.12-blue" alt="Python >= 3.12">
  <img src="https://img.shields.io/badge/modules-219-green" alt="219 Modules">
  <img src="https://img.shields.io/badge/categories-25-purple" alt="25 Categories">
  <img src="https://img.shields.io/badge/version-2.1.0-orange" alt="v2.1.0">
</p>

## Overview

ADXPL-Forge is the Active Directory offensive security component of the [XPL-Suite](https://github.com/mrhenrike). It provides 219 modules across 25 categories for AD enumeration, exploitation, lateral movement, privilege escalation and post-exploitation.

## Categories

Kerberoasting, AS-REP Roasting, delegation abuse, DCSync, NTLM relay, password spray, enumeration, BloodHound integration, ADCS abuse, GPO abuse, trust attacks, SID history, golden/silver/diamond ticket, skeleton key, shadow credentials, LAPS abuse, RBCD, constrained/unconstrained delegation, S4U, DPAPI, SCCM, CVE exploits, LOLBins, evasion, BYOVD, emulation.

## Requirements

- Python >= 3.12
- [xpl-core](https://github.com/mrhenrike/xpl-core) >= 0.3.0
- [xpl-intel](https://github.com/mrhenrike/xpl-intel) >= 2.0.0

## Installation

```bash
pip install adxpl
```

Or from source:

```bash
git clone https://github.com/mrhenrike/ADXPL-Forge.git
cd ADXPL-Forge
pip install -e ".[dev]"
```

## Quick Start

```bash
adxpl --help
adxpl enumerate -t 10.0.0.1
adxpl kerberoast -t 10.0.0.1 -u user -p pass
```

## Testing

```bash
pytest tests/ -q
```

## Project Structure

```
adxpl/
├── core/           # Base classes, interpreter, options
├── modules/        # 219 exploit/audit modules (25 categories)
├── resources/      # Wordlists, templates, data files
└── tests/          # Unit and integration tests
```

## License

See [LICENSE](LICENSE) for details.

## Author

**Andre Henrique de Oliveira** ([@mrhenrike](https://github.com/mrhenrike)) | [Uniao Geek](https://uniaogeek.com.br)

Part of the [XPL-Suite](https://github.com/mrhenrike) ecosystem.
