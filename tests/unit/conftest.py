"""Shared fixtures for unit tests (no LDAP server, no environment needed)."""

from unittest.mock import MagicMock, Mock, patch

import pytest

from active_directory_mcp.config.models import (
    ActiveDirectoryConfig,
    OrganizationalUnitsConfig,
)
from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
from active_directory_mcp.tools.security import SecurityTools
from active_directory_mcp.tools.user import UserTools


@pytest.fixture
def ad_settings() -> ActiveDirectoryConfig:
    return ActiveDirectoryConfig(
        server="ldaps://dc.test.local",
        domain="test.local",
        base_dn="DC=test,DC=local",
        bind_dn="CN=svc,DC=test,DC=local",
        password="dummy-password",
    )


@pytest.fixture
def mock_ldap_manager(ad_settings) -> Mock:
    manager = Mock(spec=LDAPManager)
    manager.ad_config = ad_settings
    manager.organizational_units = OrganizationalUnitsConfig(
        users_ou="CN=Users,DC=test,DC=local",
        groups_ou="CN=Groups,DC=test,DC=local",
        computers_ou="CN=Computers,DC=test,DC=local",
        service_accounts_ou="CN=Service,DC=test,DC=local",
    )
    manager.search.return_value = []
    for name in ("add", "modify", "delete", "move"):
        getattr(manager, name).return_value = True
    return manager


@pytest.fixture
def user_tools(mock_ldap_manager):
    return UserTools(mock_ldap_manager)


@pytest.fixture
def group_tools(mock_ldap_manager):
    return GroupTools(mock_ldap_manager)


@pytest.fixture
def computer_tools(mock_ldap_manager):
    return ComputerTools(mock_ldap_manager)


@pytest.fixture
def ou_tools(mock_ldap_manager):
    return OrganizationalUnitTools(mock_ldap_manager)


@pytest.fixture
def security_tools(mock_ldap_manager):
    return SecurityTools(mock_ldap_manager)


@pytest.fixture
def ldap3_seam():
    """Patch ldap3 Server/Connection as imported by core.ldap_manager; yield (Server, Connection)."""
    with patch("active_directory_mcp.core.ldap_manager.Server", MagicMock()) as server, patch(
        "active_directory_mcp.core.ldap_manager.Connection", MagicMock()
    ) as connection:
        yield server, connection
