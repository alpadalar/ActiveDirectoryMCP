"""GroupTools entegrasyon testleri."""

import json


def _parse(result):
    assert len(result) == 1
    return json.loads(result[0].text)


def test_list_groups_returns_seeded_group(group_tools, seeded_group, test_ou_dn):
    response = group_tools.list_groups(ou=test_ou_dn)
    data = _parse(response)

    names = [group["sAMAccountName"] for group in data["groups"]]
    assert seeded_group["name"] in names


def test_get_group_returns_details(group_tools, seeded_group):
    response = group_tools.get_group(seeded_group["name"])
    data = _parse(response)

    assert data["dn"].lower() == seeded_group["dn"].lower()
    assert data["computed"]["member_count"] >= 1


def test_get_members_lists_user(group_tools, seeded_group):
    response = group_tools.get_members(seeded_group["name"], recursive=False)
    data = _parse(response)

    assert data["member_count"] >= 1
    assert any(member["type"] == "user" for member in data["members"])
