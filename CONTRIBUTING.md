# Contributing to ADXPL-Forge

Thank you for your interest in contributing. This project is an offensive and defensive security research tool for Active Directory and Kerberos environments.

## Legal Notice

By contributing you confirm that:
- You have authorization to submit the code
- The exploit or module targets systems you own or have explicit written permission to test
- You understand and accept the [project disclaimer](README.md#disclaimer)
- You will not submit modules designed to cause unauthorized harm

## Development Setup

```bash
git clone https://github.com/mrhenrike/ADXPL-Forge.git
cd ADXPL-Forge
pip install -e ".[dev]"
python -m adxpl
```

## Module Structure

Each module lives under `adxpl/modules/<category>/` and must:

1. Inherit from the base exploit class
2. Define `__info__` with all required metadata fields
3. Include `simulate = True` as default mode
4. Implement `check()` for target validation
5. Implement `run()` with safety gates before live payloads

## Contribution Checklist

- [ ] `simulate=True` default
- [ ] `check()` returns `bool`
- [ ] `__info__` complete with CVSS, MITRE, CVE
- [ ] No secrets or credentials in code
- [ ] Impact level accurate
- [ ] Tested locally in isolated AD lab

## Submitting a Pull Request

1. Fork the repository
2. `git checkout -b add-cve-YYYY-NNNNN`
3. Add your module(s)
4. Run tests: `pytest`
5. Submit PR with clear description

## Module Categories

| Path | Description |
|------|-------------|
| `modules/exploits/` | Direct AD exploitation (Kerberos, LDAP, SMB) |
| `modules/scanners/` | AD enumeration and discovery |
| `modules/creds/` | Credential attacks (AS-REP, Kerberoast, etc.) |
| `modules/persistence/` | Persistence techniques |
| `modules/privesc/` | Privilege escalation paths |

## Contact

Andre Henrique (@mrhenrike) - henrique.santos@uniaogeek.com.br
