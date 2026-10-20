"""UserTools entegrasyon testleri (gerçek LDAP)."""

import json


def _parse_single_content(result):
    assert len(result) == 1
    return json.loads(result[0].text)


def test_list_users_with_real_directory(user_tools, seeded_user, test_ou_dn):
    """List_users gerçek LDAP'tan oluşturulan kullanıcıyı döndürmeli."""
    response = user_tools.list_users(ou=test_ou_dn)
    data = _parse_single_content(response)

    assert data["count"] >= 1
    usernames = [entry["sAMAccountName"] for entry in data["users"]]
    assert seeded_user["username"] in usernames


def test_get_user_returns_details(user_tools, seeded_user):
    """get_user yeni eklediğimiz kullanıcının ayrıntılarını dönmeli."""
    response = user_tools.get_user(seeded_user["username"])
    data = _parse_single_content(response)

    assert data["dn"].lower() == seeded_user["dn"].lower()
    assert data["computed"]["enabled"] is True


def test_get_user_groups_returns_membership(user_tools, seeded_group, seeded_user):
    """Kullanıcı grup üyeliklerini döndürebilmeli."""
    response = user_tools.get_user_groups(seeded_user["username"])
    data = _parse_single_content(response)

    assert data["success"] is True
    group_names = [group.get("sAMAccountName") for group in data["groups"]]
    assert seeded_group["name"] in group_names


def test_password_generation_rules(user_tools):
    password = user_tools._generate_password()
    assert len(password) >= 12
    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in "!@#$%^&*" for c in password)
