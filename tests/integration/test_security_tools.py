"""SecurityTools entegrasyon testleri."""

import json


def _parse(result):
    assert len(result) == 1
    return json.loads(result[0].text)


def test_get_user_permissions(security_tools, seeded_user, seeded_group):
    """Kullanıcının yetkileri gerçek LDAP verisi üzerinden çözümlenmeli."""
    response = security_tools.get_user_permissions(seeded_user["username"])
    data = _parse(response)

    assert data["username"] == seeded_user["username"]
    assert data["total_groups"] >= 1
    assert data["privileged_groups_count"] >= 0


def test_get_privileged_groups(security_tools, seeded_group):
    """Privileged grup listesi çağrısı hata vermemeli."""
    response = security_tools.get_privileged_groups()
    data = _parse(response)

    assert "privileged_groups" in data
    assert data.get("success", True) is True


def test_get_inactive_users_runs(security_tools):
    """Inactive kullanıcı sorgusu gerçek dizinde çalışmalı."""
    response = security_tools.get_inactive_users(days=0, include_disabled=True)
    data = _parse(response)

    assert "inactive_users" in data
    assert data["criteria_days"] == 0
