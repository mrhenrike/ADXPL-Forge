# Security Policy - ADXPL-Forge

## Scope

ADXPL-Forge (AXF) is an offensive and defensive security research framework for Active Directory environments. This policy covers:

- Vulnerabilities in the AXF codebase itself
- Misuse of AXF modules against unauthorized targets

## Authorized Use Only

AXF modules must **only** be used on:

- Systems you own
- Isolated lab environments with no production connectivity
- Engagements with **explicit written authorization**

Unauthorized use may violate computer crime laws in your jurisdiction.

## Reporting a Vulnerability in AXF

If you find a security issue in the AXF framework (RCE in the CLI, credential leak, sandbox escape, etc.):

1. **Do not** open a public GitHub issue for exploitable findings
2. Email: **henrique.santos@uniaogeek.com.br**
3. Include: affected version, reproduction steps, impact assessment
4. Allow **90 days** for remediation before public disclosure

We follow coordinated disclosure.

## Reporting Active Directory Vulnerabilities

If AXF helps you discover a vulnerability in Active Directory or related Microsoft products:

1. Document in an isolated lab
2. Notify Microsoft through their MSRC disclosure channel
3. Allow minimum **90 days** for critical issues
4. After disclosure, consider contributing a module via pull request

## Safe Defaults

- Simulate mode enabled by default where applicable
- Destructive operations require explicit opt-in
- Operations are logged for audit purposes

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | Yes       |
| 2.0.x   | Best effort |
| < 2.0   | No        |

Maintainer: Andre Henrique ([@mrhenrike](https://github.com/mrhenrike))
