"""ADCS ESC1-ESC8: classic certificate abuse techniques.

Reference: SpecterOps "Certified Pre-Owned" (2021), updated with
ESC7/ESC8 additions from 2022-2023 research.

Each ESC is a standalone check function returning a list of findings.
The ``run()`` entry point dispatches by --esc flag or runs all.
"""


from dataclasses import dataclass
from typing import Any


MANIFEST = {
    "capability_id": "adxpl.adcs.esc_classic.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["certificate_abuse", "privilege_escalation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1649"],
}


@dataclass
class ESCFinding:
    esc_id: int
    template_name: str
    ca_name: str
    description: str
    severity: str = "HIGH"
    remediation: str = ""


def check_esc1(templates: list[dict[str, Any]], ca_name: str) -> list[ESCFinding]:
    """ESC1: misconfigured certificate template allows SAN specification.

    Condition: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set + low-priv enrollment
    + Client Authentication or Smart Card Logon EKU.
    """
    findings: list[ESCFinding] = []
    for tpl in templates:
        name = tpl.get("name", "")
        flags = tpl.get("msPKI-Certificate-Name-Flag", 0)
        enrollee_supplies_subject = bool(flags & 1)
        ekus = tpl.get("pKIExtendedKeyUsage", [])
        has_client_auth = (
            "1.3.6.1.5.5.7.3.2" in ekus  # Client Authentication
            or "1.3.6.1.4.1.311.20.2.2" in ekus  # Smart Card Logon
            or not ekus  # No EKU = any purpose
        )
        enrollment_rights = tpl.get("enrollment_rights", [])

        if enrollee_supplies_subject and has_client_auth and enrollment_rights:
            findings.append(ESCFinding(
                esc_id=1,
                template_name=name,
                ca_name=ca_name,
                description=(
                    f"Template '{name}' allows enrollee to specify SAN "
                    f"with Client Auth EKU. Enrollment: {enrollment_rights}"
                ),
                remediation="Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or restrict enrollment",
            ))
    return findings


def check_esc2(templates: list[dict[str, Any]], ca_name: str) -> list[ESCFinding]:
    """ESC2: template with Any Purpose or SubCA EKU + low-priv enrollment."""
    findings: list[ESCFinding] = []
    for tpl in templates:
        name = tpl.get("name", "")
        ekus = tpl.get("pKIExtendedKeyUsage", [])
        any_purpose = "2.5.29.37.0" in ekus
        sub_ca = "1.3.6.1.4.1.311.20.2.3" not in ekus and not ekus
        enrollment = tpl.get("enrollment_rights", [])

        if (any_purpose or sub_ca) and enrollment:
            findings.append(ESCFinding(
                esc_id=2,
                template_name=name,
                ca_name=ca_name,
                description=f"Template '{name}' grants Any Purpose/SubCA EKU",
                remediation="Restrict EKU to specific purposes, limit enrollment",
            ))
    return findings


def check_esc3(templates: list[dict[str, Any]], ca_name: str) -> list[ESCFinding]:
    """ESC3: enrollment agent template + second template for SAN issuance."""
    agent_templates = []
    san_templates = []

    for tpl in templates:
        ekus = tpl.get("pKIExtendedKeyUsage", [])
        # Certificate Request Agent OID
        if "1.3.6.1.4.1.311.20.2.1" in ekus:
            agent_templates.append(tpl)
        schema_v = tpl.get("msPKI-Template-Schema-Version", 1)
        auth_policy = tpl.get("msPKI-RA-Application-Policies", [])
        if schema_v >= 2 and auth_policy:
            san_templates.append(tpl)

    findings: list[ESCFinding] = []
    for agent in agent_templates:
        for san in san_templates:
            findings.append(ESCFinding(
                esc_id=3,
                template_name=f"{agent.get('name', '')} + {san.get('name', '')}",
                ca_name=ca_name,
                description=(
                    "Enrollment agent template can request certs on behalf of "
                    "another user via a secondary template"
                ),
                remediation="Restrict enrollment agent issuance, add RA restrictions",
            ))
    return findings


def check_esc4(templates: list[dict[str, Any]], ca_name: str) -> list[ESCFinding]:
    """ESC4: template with vulnerable ACL (WriteDacl/WriteOwner/WriteProperty)."""
    findings: list[ESCFinding] = []
    dangerous_rights = {"WriteDacl", "WriteOwner", "WriteProperty", "GenericAll", "GenericWrite"}

    for tpl in templates:
        name = tpl.get("name", "")
        acl = tpl.get("acl_entries", [])
        for ace in acl:
            rights = set(ace.get("rights", []))
            principal = ace.get("principal", "")
            if rights & dangerous_rights:
                findings.append(ESCFinding(
                    esc_id=4,
                    template_name=name,
                    ca_name=ca_name,
                    description=(
                        f"'{principal}' has {rights & dangerous_rights} on template '{name}'"
                    ),
                    remediation="Remove dangerous ACEs from certificate template",
                ))
    return findings


def check_esc5(ca_info: dict[str, Any]) -> list[ESCFinding]:
    """ESC5: vulnerable PKI object ACL (CA server, RPC/DCOM config)."""
    findings: list[ESCFinding] = []
    ca_name = ca_info.get("name", "")
    dangerous_rights = {"WriteDacl", "WriteOwner", "GenericAll"}

    for ace in ca_info.get("acl_entries", []):
        rights = set(ace.get("rights", []))
        principal = ace.get("principal", "")
        if rights & dangerous_rights:
            findings.append(ESCFinding(
                esc_id=5,
                template_name="(CA object)",
                ca_name=ca_name,
                description=f"'{principal}' has {rights & dangerous_rights} on CA object",
                remediation="Harden PKI object permissions",
            ))
    return findings


def check_esc6(ca_info: dict[str, Any]) -> list[ESCFinding]:
    """ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA.

    If set, any certificate request can specify a SAN regardless of template.
    """
    findings: list[ESCFinding] = []
    ca_name = ca_info.get("name", "")
    flags = ca_info.get("flags", 0)

    # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
    if flags & 0x00040000:
        findings.append(ESCFinding(
            esc_id=6,
            template_name="(CA-level)",
            ca_name=ca_name,
            description="EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled on the CA",
            severity="CRITICAL",
            remediation="certutil -config 'CA' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
        ))
    return findings


def check_esc7(ca_info: dict[str, Any]) -> list[ESCFinding]:
    """ESC7: ManageCA + ManageCertificates permissions on the CA.

    Combined access allows approving pending requests and enabling ESC6.
    """
    findings: list[ESCFinding] = []
    ca_name = ca_info.get("name", "")

    manage_ca_principals = []
    manage_certs_principals = []

    for ace in ca_info.get("acl_entries", []):
        rights = set(ace.get("rights", []))
        principal = ace.get("principal", "")
        if "ManageCA" in rights:
            manage_ca_principals.append(principal)
        if "ManageCertificates" in rights:
            manage_certs_principals.append(principal)

    overlap = set(manage_ca_principals) & set(manage_certs_principals)
    for principal in overlap:
        findings.append(ESCFinding(
            esc_id=7,
            template_name="(CA-level)",
            ca_name=ca_name,
            description=(
                f"'{principal}' has both ManageCA + ManageCertificates; "
                f"can enable ESC6 flag and approve pending requests"
            ),
            severity="CRITICAL",
            remediation="Separate ManageCA and ManageCertificates roles",
        ))
    return findings


def check_esc8(ca_info: dict[str, Any]) -> list[ESCFinding]:
    """ESC8: NTLM relay to AD CS HTTP enrollment (Web Enrollment/CES/CEP).

    If HTTP enrollment endpoints exist without EPA/channel binding,
    NTLM relay to the CA issues certs as the relayed principal.
    """
    findings: list[ESCFinding] = []
    ca_name = ca_info.get("name", "")

    http_endpoints = ca_info.get("http_enrollment_endpoints", [])
    for ep in http_endpoints:
        url = ep.get("url", "")
        has_epa = ep.get("epa_enabled", False)
        has_ssl = ep.get("ssl_required", False)

        if not has_epa:
            findings.append(ESCFinding(
                esc_id=8,
                template_name="(HTTP enrollment)",
                ca_name=ca_name,
                description=(
                    f"HTTP enrollment at {url}: "
                    f"EPA={'yes' if has_epa else 'NO'}, SSL={'yes' if has_ssl else 'NO'}; "
                    f"NTLM relay possible"
                ),
                severity="CRITICAL",
                remediation="Enable EPA on all HTTP enrollment endpoints, require HTTPS",
            ))
    return findings


def run(args: Any) -> int:
    """Entry point: dispatch by --esc or run all classic checks."""
    from adxpl.core.credential import ADCredential

    cred = ADCredential.from_args(args)
    dc_ip = getattr(args, "dc_ip", None)
    esc = getattr(args, "esc", None)

    print("[*] ADCS Classic ESC Audit (ESC1-ESC8)")
    print(f"[*] Domain: {cred.domain}")
    print(f"[*] DC: {dc_ip or 'auto'}")

    # In a real execution, templates and CA info would come from LDAP queries.
    # Here we show the dispatch pattern.
    templates: list[dict[str, Any]] = []
    ca_info: dict[str, Any] = {"name": "Unknown-CA", "acl_entries": [], "flags": 0}

    esc_checks = {
        "1": lambda: check_esc1(templates, ca_info["name"]),
        "2": lambda: check_esc2(templates, ca_info["name"]),
        "3": lambda: check_esc3(templates, ca_info["name"]),
        "4": lambda: check_esc4(templates, ca_info["name"]),
        "5": lambda: check_esc5(ca_info),
        "6": lambda: check_esc6(ca_info),
        "7": lambda: check_esc7(ca_info),
        "8": lambda: check_esc8(ca_info),
    }

    if esc and esc in esc_checks:
        findings = esc_checks[esc]()
    else:
        findings = []
        for check_fn in esc_checks.values():
            findings.extend(check_fn())

    print(f"\n[*] Total findings: {len(findings)}")
    for f in findings:
        print(f"  [ESC{f.esc_id}] {f.severity}: {f.description}")

    return 0
