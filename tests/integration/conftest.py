"""Pytest fixture'ları: gerçek LDAP ortamı ile entegrasyon."""

import os
import uuid
from typing import Dict

import pytest
from ldap3 import MODIFY_ADD, MODIFY_DELETE, Connection, Server

from active_directory_mcp.config.loader import load_config
from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.security import SecurityTools
from active_directory_mcp.tools.user import UserTools


@pytest.fixture(scope="session")
def ad_config():
    """AD yapılandırmasını ortam değişkeninden yükle."""
    config_path = os.environ.get("AD_MCP_CONFIG")
    if not config_path:
        pytest.skip("AD_MCP_CONFIG not set; start the lab with scripts/run_tests_with_ldap.sh")
    return load_config(config_path)


@pytest.fixture(scope="session")
def ldap_manager(ad_config):
    """Gerçek LDAP bağlantısı için yöneticiyi hazırla."""
    manager = LDAPManager(
        ad_config.active_directory,
        ad_config.security,
        ad_config.performance,
        ad_config.organizational_units,
    )
    yield manager
    manager.disconnect()


@pytest.fixture(scope="session")
def ldap_connection(ad_config):
    """Doğrudan LDAP bağlantısı (ham bağlantı işlemleri için)."""
    server = Server(ad_config.active_directory.server)
    conn = Connection(
        server,
        user=ad_config.active_directory.bind_dn,
        password=ad_config.active_directory.password.get_secret_value(),
        auto_bind=True,
    )
    yield conn
    conn.unbind()


@pytest.fixture
def test_ou_dn(ad_config, ldap_connection):
    """Testler için geçici OU oluşturur."""
    ou_name = f"PyTest-{uuid.uuid4().hex[:8]}"
    ou_dn = f"ou={ou_name},{ad_config.active_directory.base_dn}"
    ldap_connection.add(ou_dn, ["top", "organizationalUnit"], {"ou": ou_name})
    try:
        yield ou_dn
    finally:
        try:
            ldap_connection.delete(ou_dn)
        except Exception:
            pass


def _ensure_list(value):
    return value if isinstance(value, list) else [value]


@pytest.fixture
def seeded_user(ad_config, ldap_connection, test_ou_dn) -> Dict[str, str]:
    """Gerçek LDAP üzerinde test kullanıcısı oluştur."""
    user_cn = "PyTest User"
    user_dn = f"CN={user_cn},{test_ou_dn}"
    attributes = {
        "objectClass": [
            "top",
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "extensibleObject",
        ],
        "cn": user_cn,
        "sn": "User",
        "givenName": "PyTest",
        "displayName": user_cn,
        "mail": "pytest.user@test.local",
        "sAMAccountName": "pytestuser",
        "userPrincipalName": "pytestuser@test.local",
        "userPassword": "Password123!",
        "userAccountControl": "512",
    }

    ldap_connection.add(user_dn, attributes=attributes)

    try:
        yield {"dn": user_dn, "username": "pytestuser", "cn": user_cn}
    finally:
        try:
            ldap_connection.delete(user_dn)
        except Exception:
            pass


@pytest.fixture
def seeded_group(ad_config, ldap_connection, seeded_user, test_ou_dn) -> Dict[str, str]:
    """Test grubu oluştur ve kullanıcıyı üyeliklere ekle."""
    group_name = "PyTest Group"
    group_dn = f"CN={group_name},{test_ou_dn}"
    attributes = {
        "objectClass": ["top", "groupOfNames", "extensibleObject"],
        "cn": group_name,
        "description": "Pytest integration group",
        "sAMAccountName": "PYTESTGROUP",
        "groupType": "-2147483646",
        "member": _ensure_list(seeded_user["dn"]),
    }

    ldap_connection.add(group_dn, attributes=attributes)
    ldap_connection.modify(
        seeded_user["dn"],
        {"memberOf": [(MODIFY_ADD, [group_dn])]},
    )

    try:
        yield {"dn": group_dn, "name": "PYTESTGROUP"}
    finally:
        ldap_connection.modify(
            seeded_user["dn"],
            {"memberOf": [(MODIFY_DELETE, [group_dn])]},
        )
        try:
            ldap_connection.delete(group_dn)
        except Exception:
            pass


@pytest.fixture
def user_tools(ldap_manager):
    return UserTools(ldap_manager)


@pytest.fixture
def group_tools(ldap_manager):
    return GroupTools(ldap_manager)


@pytest.fixture
def security_tools(ldap_manager):
    return SecurityTools(ldap_manager)
