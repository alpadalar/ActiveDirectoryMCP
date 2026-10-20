"""Deterministic mocked-LDAP harness built on ldap3 MOCK_SYNC.

``MockDirectory`` replaces the two ldap3 names that ``core.ldap_manager`` looks up
(``Server`` and ``Connection``) with an OFFLINE_AD_2012_R2 schema server and a
MOCK_SYNC connection. The real ``LDAPManager`` and the real tool classes then run
end to end with no network and no live directory.

Design decisions:

* Seed replay, not shared state. Seeds are kept as an ordered list of
  ``(dn, attributes)`` tuples. Every new ``Connection`` created while ``patch()``
  is active replays the whole list into its own MOCK_SYNC store. ``LDAPManager``
  caches a single bound connection, so one manager sees its own writes
  consistently; a second connection only sees the seeds (pinned by
  ``test_fidelity_state_is_per_connection``).
* Determinism. Seed data is declared in code. No randomness, no clock, no
  sockets. ``whenCreated``, ``pwdLastSet``, ``objectSid`` and ``objectGUID`` are
  present only if a test seeds them.
* The default bind password is a placeholder constant, never a real credential,
  and the harness never prints or logs it.
* No pytest import, so non-test callers (the E2E fixture) can use this module.

What the mock cannot emulate is documented in TESTING_GUIDE.md ("Fidelity
limits") and pinned by ``tests/unit/test_mock_directory.py``.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple
from unittest.mock import patch

import ldap3

from active_directory_mcp.config.models import (
    ActiveDirectoryConfig,
    OrganizationalUnitsConfig,
    PerformanceConfig,
    SecurityConfig,
)
from active_directory_mcp.core.ldap_manager import LDAPManager

_SEAM = "active_directory_mcp.core.ldap_manager"

# Keyword arguments the harness forwards to the MOCK_SYNC Connection. Everything
# else LDAPManager passes (receive_timeout, auto_bind, authentication, ...) is
# dropped or fixed so the mock stays offline and deterministic.
_CONNECTION_KWARGS = ("user", "password", "check_names", "raise_exceptions")


class MockDirectory:
    """In-memory directory behind the real LDAPManager (see module docstring)."""

    def __init__(
        self,
        base_dn: str = "DC=test,DC=local",
        bind_dn: str = "CN=svc,DC=test,DC=local",
        bind_password: str = "mock-bind-secret",
        server_url: str = "ldaps://dc.test.local",
    ) -> None:
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.server_url = server_url
        self.domain = ".".join(
            part.split("=", 1)[1] for part in base_dn.split(",") if part.upper().startswith("DC=")
        )
        self.seeds: List[Tuple[str, Dict[str, Any]]] = []
        self.connections: List[ldap3.Connection] = []
        self._schema_less = False

        self.users_container = f"CN=Users,{base_dn}"
        self.groups_container = f"CN=Groups,{base_dn}"
        self.computers_container = f"CN=Computers,{base_dn}"
        self.service_container = f"CN=Service,{base_dn}"

        self.add_entry(base_dn, {"objectClass": ["top", "domain", "domainDNS"]})
        for container in (
            self.users_container,
            self.groups_container,
            self.computers_container,
            self.service_container,
        ):
            self.add_entry(container, {"objectClass": ["top", "container"]})
        # The bind account is a person, not a "user", so it never shows up in user listings.
        self.add_entry(
            bind_dn,
            {
                "objectClass": ["top", "person", "organizationalPerson"],
                "userPassword": bind_password,
            },
        )

    # ------------------------------------------------------------------ seeding

    def add_entry(self, dn: str, attributes: Dict[str, Any]) -> str:
        self.seeds.append((dn, dict(attributes)))
        return dn

    def add_ou(self, name: str, parent: Optional[str] = None) -> str:
        dn = f"OU={name},{parent or self.base_dn}"
        return self.add_entry(dn, {"objectClass": ["top", "organizationalUnit"], "ou": name})

    def add_user(
        self, sam: str, ou: Optional[str] = None, enabled: bool = True, **attrs: Any
    ) -> str:
        dn = f"CN={sam},{ou or self.users_container}"
        attributes: Dict[str, Any] = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": sam,
            "sAMAccountName": sam,
            "userPrincipalName": f"{sam}@{self.domain}",
            "userAccountControl": 512 if enabled else 514,
        }
        attributes.update(attrs)
        return self.add_entry(dn, attributes)

    def add_group(self, name: str, members: Sequence[str] = (), **attrs: Any) -> str:
        dn = f"CN={name},{self.groups_container}"
        attributes: Dict[str, Any] = {
            "objectClass": ["top", "group"],
            "cn": name,
            "sAMAccountName": name,
        }
        if members:
            attributes["member"] = list(members)
        attributes.update(attrs)
        return self.add_entry(dn, attributes)

    def add_computer(self, name: str, **attrs: Any) -> str:
        dn = f"CN={name},{self.computers_container}"
        attributes: Dict[str, Any] = {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": name,
            "sAMAccountName": f"{name}$",
            "userAccountControl": 4096,
        }
        attributes.update(attrs)
        return self.add_entry(dn, attributes)

    # ------------------------------------------------------------------ seam

    def _build_server(self, host: str, *args: Any, **kwargs: Any) -> ldap3.Server:
        # tls / connect_timeout are irrelevant to the offline server and are dropped.
        get_info = ldap3.NONE if self._schema_less else ldap3.OFFLINE_AD_2012_R2
        return ldap3.Server(host, get_info=get_info)

    def _build_connection(self, server: Any, **kwargs: Any) -> ldap3.Connection:
        forwarded = {k: kwargs[k] for k in _CONNECTION_KWARGS if k in kwargs}
        connection = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC, **forwarded)
        for dn, attributes in self.seeds:
            connection.strategy.add_entry(dn, attributes)
        self.connections.append(connection)
        return connection

    @contextmanager
    def patch(self, schema_less: bool = False) -> Iterator["MockDirectory"]:
        """Patch ``Server`` and ``Connection`` where LDAPManager looks them up.

        ``schema_less=True`` mirrors production ``AD_MCP_SKIP_SCHEMA`` mode: the
        module flag is switched on and the server carries no schema, so attribute
        names are not checked (and integer attributes come back stringified).
        """
        self._schema_less = schema_less
        with patch(f"{_SEAM}.Server", side_effect=self._build_server), patch(
            f"{_SEAM}.Connection", side_effect=self._build_connection
        ), patch(f"{_SEAM}.SKIP_SCHEMA", schema_less):
            yield self

    # ------------------------------------------------------------------ configs

    def ad_config(self, **overrides: Any) -> ActiveDirectoryConfig:
        values: Dict[str, Any] = dict(
            server=self.server_url,
            domain=self.domain,
            base_dn=self.base_dn,
            bind_dn=self.bind_dn,
            password=self.bind_password,
        )
        values.update(overrides)
        return ActiveDirectoryConfig(**values)

    def ou_config(self) -> OrganizationalUnitsConfig:
        return OrganizationalUnitsConfig(
            users_ou=self.users_container,
            groups_ou=self.groups_container,
            computers_ou=self.computers_container,
            service_accounts_ou=self.service_container,
        )

    def security_config(self, **overrides: Any) -> SecurityConfig:
        return SecurityConfig(**overrides)

    def performance_config(self, page_size: int = 1000, **overrides: Any) -> PerformanceConfig:
        values: Dict[str, Any] = dict(max_retries=1, retry_delay=0.01, page_size=page_size)
        values.update(overrides)
        return PerformanceConfig(**values)

    def config_file(self, tmp_path: Path, page_size: int = 1000) -> Path:
        """Write a JSON config (without the password) for the server classes."""
        data = {
            "active_directory": {
                "server": self.server_url,
                "domain": self.domain,
                "base_dn": self.base_dn,
                "bind_dn": self.bind_dn,
            },
            "organizational_units": self.ou_config().model_dump(),
            "performance": {"max_retries": 1, "retry_delay": 0.01, "page_size": page_size},
        }
        path = Path(tmp_path) / "mock_directory_config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def env(self, tmp_path: Path) -> Dict[str, str]:
        """Environment for ``patch.dict(os.environ, ...)``; the password comes from AD_PASSWORD."""
        return {
            "AD_MCP_CONFIG": str(self.config_file(tmp_path)),
            "AD_PASSWORD": self.bind_password,
        }

    # ------------------------------------------------------------------ manager / reads

    def make_manager(self, page_size: int = 1000) -> LDAPManager:
        """Build a real LDAPManager whose Server is the offline one (call under patch())."""
        return LDAPManager(
            self.ad_config(),
            self.security_config(),
            self.performance_config(page_size=page_size),
            self.ou_config(),
        )

    def search(
        self,
        search_filter: str,
        attributes: Any = ldap3.ALL_ATTRIBUTES,
        search_base: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Read the state of the most recently created connection."""
        connection = self.connections[-1]
        connection.search(search_base or self.base_dn, search_filter, attributes=attributes)
        return [
            {"dn": entry.entry_dn, "attributes": entry.entry_attributes_as_dict}
            for entry in connection.entries
        ]
