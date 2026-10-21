"""Tests for adxpl.modules.adcs.esc_classic (ESC1-ESC8)."""


from adxpl.modules.adcs.esc_classic import (
    check_esc1,
    check_esc2,
    check_esc3,
    check_esc4,
    check_esc5,
    check_esc6,
    check_esc7,
    check_esc8,
)


def _make_template(**overrides: object) -> dict:
    base = {
        "name": "TestTemplate",
        "msPKI-Certificate-Name-Flag": 0,
        "pKIExtendedKeyUsage": [],
        "enrollment_rights": [],
        "acl_entries": [],
        "msPKI-Template-Schema-Version": 1,
        "msPKI-RA-Application-Policies": [],
    }
    base.update(overrides)
    return base


class TestESC1:
    def test_vulnerable(self) -> None:
        tpl = _make_template(
            name="VulnTemplate",
            **{
                "msPKI-Certificate-Name-Flag": 1,
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
                "enrollment_rights": ["Domain Users"],
            },
        )
        findings = check_esc1([tpl], "CA01")
        assert len(findings) == 1
        assert findings[0].esc_id == 1
        assert "VulnTemplate" in findings[0].description

    def test_safe_no_san(self) -> None:
        tpl = _make_template(
            **{
                "msPKI-Certificate-Name-Flag": 0,
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
                "enrollment_rights": ["Domain Users"],
            },
        )
        assert check_esc1([tpl], "CA01") == []

    def test_safe_no_enrollment(self) -> None:
        tpl = _make_template(
            **{
                "msPKI-Certificate-Name-Flag": 1,
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
                "enrollment_rights": [],
            },
        )
        assert check_esc1([tpl], "CA01") == []

    def test_no_eku_means_any(self) -> None:
        tpl = _make_template(
            name="NoEKU",
            **{
                "msPKI-Certificate-Name-Flag": 1,
                "pKIExtendedKeyUsage": [],
                "enrollment_rights": ["Everyone"],
            },
        )
        findings = check_esc1([tpl], "CA01")
        assert len(findings) == 1


class TestESC2:
    def test_any_purpose(self) -> None:
        tpl = _make_template(
            name="AnyPurpose",
            pKIExtendedKeyUsage=["2.5.29.37.0"],
            enrollment_rights=["Domain Users"],
        )
        assert len(check_esc2([tpl], "CA01")) == 1


class TestESC3:
    def test_agent_and_san(self) -> None:
        agent = _make_template(
            name="Agent",
            pKIExtendedKeyUsage=["1.3.6.1.4.1.311.20.2.1"],
            enrollment_rights=["Users"],
        )
        san = _make_template(
            name="SANTarget",
            **{
                "msPKI-Template-Schema-Version": 2,
                "msPKI-RA-Application-Policies": ["1.3.6.1.4.1.311.20.2.1"],
            },
        )
        findings = check_esc3([agent, san], "CA01")
        assert len(findings) == 1
        assert findings[0].esc_id == 3


class TestESC4:
    def test_dangerous_acl(self) -> None:
        tpl = _make_template(
            name="WeakACL",
            acl_entries=[{"principal": "Domain Users", "rights": ["WriteDacl"]}],
        )
        findings = check_esc4([tpl], "CA01")
        assert len(findings) == 1
        assert "WriteDacl" in findings[0].description

    def test_safe_acl(self) -> None:
        tpl = _make_template(
            acl_entries=[{"principal": "Enterprise Admins", "rights": ["Read"]}],
        )
        assert check_esc4([tpl], "CA01") == []


class TestESC5:
    def test_ca_object_vulnerable(self) -> None:
        ca = {"name": "CA01", "acl_entries": [{"principal": "Users", "rights": ["GenericAll"]}]}
        findings = check_esc5(ca)
        assert len(findings) == 1


class TestESC6:
    def test_flag_set(self) -> None:
        ca = {"name": "CA01", "flags": 0x00040000, "acl_entries": []}
        findings = check_esc6(ca)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_flag_not_set(self) -> None:
        ca = {"name": "CA01", "flags": 0, "acl_entries": []}
        assert check_esc6(ca) == []


class TestESC7:
    def test_combined_permissions(self) -> None:
        ca = {
            "name": "CA01",
            "acl_entries": [
                {"principal": "helpdesk", "rights": ["ManageCA", "ManageCertificates"]},
            ],
        }
        findings = check_esc7(ca)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_separated(self) -> None:
        ca = {
            "name": "CA01",
            "acl_entries": [
                {"principal": "admin1", "rights": ["ManageCA"]},
                {"principal": "admin2", "rights": ["ManageCertificates"]},
            ],
        }
        assert check_esc7(ca) == []


class TestESC8:
    def test_no_epa(self) -> None:
        ca = {
            "name": "CA01",
            "http_enrollment_endpoints": [
                {"url": "https://ca01/certsrv", "epa_enabled": False, "ssl_required": True},
            ],
            "acl_entries": [],
        }
        findings = check_esc8(ca)
        assert len(findings) == 1

    def test_epa_enabled(self) -> None:
        ca = {
            "name": "CA01",
            "http_enrollment_endpoints": [
                {"url": "https://ca01/certsrv", "epa_enabled": True, "ssl_required": True},
            ],
            "acl_entries": [],
        }
        assert check_esc8(ca) == []
