"""Tests for adxpl.core.ldap_engine."""


from types import SimpleNamespace

from adxpl.core.ldap_engine import LDAPEngine


class FakeEntry:
    def __init__(self, dn: str, attrs: dict) -> None:
        self._dn = dn
        self._attrs = attrs

    @property
    def entry_dn(self) -> str:
        return self._dn

    @property
    def entry_attributes(self) -> list[str]:
        return list(self._attrs.keys())

    def __getitem__(self, key: str) -> SimpleNamespace:
        return SimpleNamespace(value=self._attrs[key])


class FakeConnection:
    def __init__(self, entries: list[FakeEntry] | None = None) -> None:
        self.entries: list[FakeEntry] = entries or []
        self._searches: list[dict] = []

    def search(self, base: str, ldap_filter: str, search_scope: str = "SUBTREE",
               attributes: object = None) -> None:
        self._searches.append({
            "base": base, "filter": ldap_filter, "scope": search_scope,
        })


class TestLDAPEngine:
    def _engine(self, entries: list[FakeEntry] | None = None) -> LDAPEngine:
        conn = FakeConnection(entries or [])
        return LDAPEngine(conn, base_dn="DC=corp,DC=local")

    def test_base_dn(self) -> None:
        eng = self._engine()
        assert eng.base_dn == "DC=corp,DC=local"

    def test_enum_users(self) -> None:
        entry = FakeEntry("CN=jdoe,DC=corp,DC=local", {
            "sAMAccountName": "jdoe",
            "adminCount": 0,
        })
        conn = FakeConnection([entry])
        eng = LDAPEngine(conn, base_dn="DC=corp,DC=local")
        conn.entries = [entry]
        results = eng.enum_users()
        assert len(conn._searches) == 1
        assert "objectCategory=person" in conn._searches[0]["filter"]

    def test_enum_spns(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=test,DC=com")
        eng.enum_spns()
        assert "servicePrincipalName" in conn._searches[0]["filter"]

    def test_enum_asrep_roastable(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=x,DC=y")
        eng.enum_asrep_roastable()
        assert "4194304" in conn._searches[0]["filter"]

    def test_enum_unconstrained_delegation(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=x,DC=y")
        eng.enum_unconstrained_delegation()
        assert "524288" in conn._searches[0]["filter"]

    def test_enum_constrained_delegation(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=x,DC=y")
        eng.enum_constrained_delegation()
        assert "msDS-AllowedToDelegateTo" in conn._searches[0]["filter"]

    def test_enum_rbcd(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=x,DC=y")
        eng.enum_rbcd()
        assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in conn._searches[0]["filter"]

    def test_enum_adcs_cas(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=corp,DC=local")
        eng.enum_adcs_cas()
        assert "pKIEnrollmentService" in conn._searches[0]["filter"]

    def test_enum_adcs_templates(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=corp,DC=local")
        eng.enum_adcs_templates()
        assert "pKICertificateTemplate" in conn._searches[0]["filter"]

    def test_custom_query(self) -> None:
        conn = FakeConnection()
        eng = LDAPEngine(conn, base_dn="DC=x,DC=y")
        eng.custom_query("(cn=admin)")
        assert conn._searches[0]["filter"] == "(cn=admin)"
