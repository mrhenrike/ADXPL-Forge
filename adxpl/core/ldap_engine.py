"""High-level LDAP query engine built on top of ldap_session.

Provides domain enumeration helpers: users, groups, computers, GPOs,
OUs, trusts, ADCS objects, delegation flags and SPN queries.
"""


from dataclasses import dataclass, field
from typing import Any


@dataclass
class LDAPResult:
    dn: str
    attributes: dict[str, Any] = field(default_factory=dict)


class LDAPEngine:
    """Stateful LDAP query engine wrapping an ldap3 Connection."""

    def __init__(self, connection: Any, base_dn: str = "") -> None:
        self._conn = connection
        self._base_dn = base_dn or self._detect_base_dn()

    @property
    def base_dn(self) -> str:
        return self._base_dn

    def _detect_base_dn(self) -> str:
        """Derive base DN from RootDSE defaultNamingContext."""
        try:
            self._conn.search(
                "",
                "(objectClass=*)",
                search_scope="BASE",
                attributes=["defaultNamingContext"],
            )
            if self._conn.entries:
                ctx = str(self._conn.entries[0].defaultNamingContext)
                return ctx
        except Exception:
            pass
        return ""

    def _search(
        self,
        ldap_filter: str,
        attributes: list[str] | str = "*",
        base: str | None = None,
        scope: str = "SUBTREE",
    ) -> list[LDAPResult]:
        base = base or self._base_dn
        self._conn.search(base, ldap_filter, search_scope=scope, attributes=attributes)
        results: list[LDAPResult] = []
        for entry in self._conn.entries:
            attrs = {}
            for attr in entry.entry_attributes:
                val = entry[attr].value
                attrs[attr] = val
            results.append(LDAPResult(dn=str(entry.entry_dn), attributes=attrs))
        return results

    # --- Domain enumeration helpers ---

    def enum_users(self, enabled_only: bool = True) -> list[LDAPResult]:
        filt = (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            if enabled_only
            else "(&(objectCategory=person)(objectClass=user))"
        )
        return self._search(
            filt,
            ["sAMAccountName", "distinguishedName", "memberOf",
             "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
             "servicePrincipalName", "adminCount"],
        )

    def enum_computers(self) -> list[LDAPResult]:
        return self._search(
            "(objectClass=computer)",
            ["sAMAccountName", "dNSHostName", "operatingSystem",
             "operatingSystemVersion", "lastLogonTimestamp",
             "userAccountControl", "msDS-AllowedToDelegateTo"],
        )

    def enum_groups(self) -> list[LDAPResult]:
        return self._search(
            "(objectClass=group)",
            ["sAMAccountName", "member", "adminCount", "groupType"],
        )

    def enum_gpos(self) -> list[LDAPResult]:
        return self._search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "gPCFileSysPath", "gPCMachineExtensionNames"],
        )

    def enum_ous(self) -> list[LDAPResult]:
        return self._search(
            "(objectClass=organizationalUnit)",
            ["name", "gpLink", "description"],
        )

    def enum_trusts(self) -> list[LDAPResult]:
        return self._search(
            "(objectClass=trustedDomain)",
            ["trustPartner", "trustDirection", "trustType",
             "trustAttributes", "securityIdentifier"],
        )

    def enum_spns(self) -> list[LDAPResult]:
        """Find accounts with SPNs set (kerberoastable)."""
        return self._search(
            "(&(objectClass=user)(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "memberOf", "adminCount"],
        )

    def enum_asrep_roastable(self) -> list[LDAPResult]:
        """Find accounts that do not require pre-authentication."""
        # UF_DONT_REQUIRE_PREAUTH = 0x400000
        return self._search(
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "memberOf", "adminCount"],
        )

    def enum_unconstrained_delegation(self) -> list[LDAPResult]:
        """Find objects trusted for unconstrained delegation."""
        # TRUSTED_FOR_DELEGATION = 0x80000
        return self._search(
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            ["sAMAccountName", "dNSHostName", "userAccountControl"],
        )

    def enum_constrained_delegation(self) -> list[LDAPResult]:
        """Find objects with constrained delegation (msDS-AllowedToDelegateTo)."""
        return self._search(
            "(msDS-AllowedToDelegateTo=*)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo",
             "userAccountControl"],
        )

    def enum_rbcd(self) -> list[LDAPResult]:
        """Find objects with resource-based constrained delegation configured."""
        return self._search(
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )

    def enum_adcs_cas(self) -> list[LDAPResult]:
        """Enumerate Certificate Authorities registered in AD."""
        config_dn = f"CN=Configuration,{self._base_dn}"
        return self._search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "cACertificate",
             "certificateTemplates", "nTSecurityDescriptor"],
            base=f"CN=Public Key Services,CN=Services,{config_dn}",
        )

    def enum_adcs_templates(self) -> list[LDAPResult]:
        """Enumerate certificate templates from AD."""
        config_dn = f"CN=Configuration,{self._base_dn}"
        return self._search(
            "(objectClass=pKICertificateTemplate)",
            ["cn", "displayName", "msPKI-Certificate-Name-Flag",
             "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
             "msPKI-Template-Schema-Version", "msPKI-RA-Application-Policies",
             "nTSecurityDescriptor"],
            base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
        )

    def enum_laps(self) -> list[LDAPResult]:
        """Find computers with LAPS (ms-Mcs-AdmPwd attribute)."""
        return self._search(
            "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))",
            ["sAMAccountName", "dNSHostName", "ms-Mcs-AdmPwd",
             "ms-Mcs-AdmPwdExpirationTime"],
        )

    def custom_query(self, ldap_filter: str, attributes: list[str] | None = None) -> list[LDAPResult]:
        return self._search(ldap_filter, attributes or "*")
