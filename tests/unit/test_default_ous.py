"""Regression: create_computer / create_group default-OU path with the REAL config types.

Before the fix the tools read ``ldap.ad_config.organizational_units`` which the real
``ActiveDirectoryConfig`` does not have, so omitting ``ou`` raised AttributeError.
"""

from unittest.mock import MagicMock, patch

import pytest

from active_directory_mcp.config.models import (
    ActiveDirectoryConfig,
    Config,
    OrganizationalUnitsConfig,
    PerformanceConfig,
    SecurityConfig,
)
from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.user import UserTools
from tests.support.helpers import parse_response

AD = {
    "server": "ldaps://dc.test.local",
    "domain": "test.local",
    "base_dn": "DC=test,DC=local",
    "bind_dn": "CN=svc,DC=test,DC=local",
    "password": "dummy-password",
}


def _real_manager(ous=None):
    with patch("active_directory_mcp.core.ldap_manager.Server", MagicMock()), patch(
        "active_directory_mcp.core.ldap_manager.Connection", MagicMock()
    ):
        manager = LDAPManager(
            ActiveDirectoryConfig(**AD), SecurityConfig(enable_tls=False), PerformanceConfig(),
            organizational_units=ous,
        )
    manager.search = MagicMock(return_value=[])
    manager.add = MagicMock(return_value=True)
    manager.modify = MagicMock(return_value=True)
    manager.is_secure_channel = MagicMock(return_value=True)  # password writes need TLS
    return manager


def test_create_computer_default_ou_with_real_config():
    manager = _real_manager()
    data = parse_response(ComputerTools(manager).create_computer("NEWPC"))
    assert data["success"] is True
    assert data["dn"] == "CN=NEWPC,CN=Computers,DC=test,DC=local"


def test_create_group_default_ou_with_real_config():
    manager = _real_manager()
    data = parse_response(GroupTools(manager).create_group("Sales"))
    assert data["success"] is True
    assert manager.add.call_args.args[0] == "CN=Sales,CN=Users,DC=test,DC=local"


def test_configured_ous_win_over_derived_defaults():
    ous = OrganizationalUnitsConfig(
        users_ou="OU=U,DC=test,DC=local",
        groups_ou="OU=G,DC=test,DC=local",
        computers_ou="OU=C,DC=test,DC=local",
        service_accounts_ou="OU=S,DC=test,DC=local",
    )
    manager = _real_manager(ous)
    assert parse_response(ComputerTools(manager).create_computer("PC1"))["dn"] == (
        "CN=PC1,OU=C,DC=test,DC=local"
    )
    GroupTools(manager).create_group("Ops")
    assert manager.add.call_args.args[0] == "CN=Ops,OU=G,DC=test,DC=local"


def test_create_user_uses_configured_users_ou():
    ous = OrganizationalUnitsConfig(
        users_ou="OU=Staff,DC=test,DC=local",
        groups_ou="OU=G,DC=test,DC=local",
        computers_ou="OU=C,DC=test,DC=local",
        service_accounts_ou="OU=S,DC=test,DC=local",
    )
    manager = _real_manager(ous)
    data = parse_response(UserTools(manager).create_user("jdoe", "Pw-1234!x", "John", "Doe"))
    assert data["success"] is True
    assert data["dn"] == "CN=John Doe,OU=Staff,DC=test,DC=local"


def test_create_user_default_ou_with_real_config():
    manager = _real_manager()
    data = parse_response(UserTools(manager).create_user("jdoe", "Pw-1234!x", "John", "Doe"))
    assert data["dn"] == "CN=John Doe,CN=Users,DC=test,DC=local"


def test_config_without_organizational_units_gets_base_dn_defaults():
    config = Config(active_directory=AD)
    ous = config.organizational_units
    assert ous.computers_ou == "CN=Computers,DC=test,DC=local"
    assert ous.users_ou == "CN=Users,DC=test,DC=local"
    assert ous.groups_ou == "CN=Users,DC=test,DC=local"
    assert ous.service_accounts_ou == "CN=Users,DC=test,DC=local"


def test_explicit_organizational_units_are_kept():
    config = Config(
        active_directory=AD,
        organizational_units={
            "users_ou": "OU=U,DC=test,DC=local",
            "groups_ou": "OU=G,DC=test,DC=local",
            "computers_ou": "OU=C,DC=test,DC=local",
            "service_accounts_ou": "OU=S,DC=test,DC=local",
        },
    )
    assert config.organizational_units.computers_ou == "OU=C,DC=test,DC=local"


@pytest.mark.parametrize("missing", ["users_ou", "groups_ou", "computers_ou", "service_accounts_ou"])
def test_partial_organizational_units_are_filled_from_defaults(missing):
    full = {
        "users_ou": "OU=U,DC=test,DC=local",
        "groups_ou": "OU=G,DC=test,DC=local",
        "computers_ou": "OU=C,DC=test,DC=local",
        "service_accounts_ou": "OU=S,DC=test,DC=local",
    }
    del full[missing]
    ous = Config(active_directory=AD, organizational_units=full).organizational_units
    assert getattr(ous, missing).endswith(",DC=test,DC=local")
    assert getattr(ous, missing).startswith("CN=")


def test_computer_filters_use_configured_computer_object_class():
    manager = _real_manager()
    manager.ad_config.computer_object_class = "device"
    ComputerTools(manager).list_computers()
    ComputerTools(manager).get_computer("PC1")
    filters = [c.kwargs["search_filter"] for c in manager.search.call_args_list]
    assert filters and all("(objectClass=device)" in f for f in filters)
    assert not any("objectClass=computer" in f for f in filters)
