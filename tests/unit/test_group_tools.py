"""Unit tests for GroupTools (mocked LDAPManager, no directory server)."""

import pytest
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from tests.support.helpers import ldap_entry, parse_response

GROUP_DN = "CN=Sales,CN=Groups,DC=test,DC=local"
MEMBER = "CN=John Doe,CN=Users,DC=test,DC=local"
SECURITY_GLOBAL = -2147483646  # 0x80000002 as signed 32-bit, as AD returns it


def _group(mock_ldap_manager, **attrs):
    mock_ldap_manager.search.return_value = [ldap_entry(GROUP_DN, sAMAccountName="Sales", **attrs)]


class TestListGroups:
    def test_success(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = [
            ldap_entry(GROUP_DN, sAMAccountName="Sales", groupType=0x80000002, member=[MEMBER]),
            ldap_entry("CN=D,DC=test,DC=local", sAMAccountName="D", groupType=0x00000004),
        ]
        data = parse_response(group_tools.list_groups())
        assert data["count"] == 2
        first, second = data["groups"]
        assert (first["scope"], first["type"], first["memberCount"]) == ("Global", "Security", 1)
        assert (second["scope"], second["type"]) == ("DomainLocal", "Distribution")

    def test_filter_criteria(self, group_tools, mock_ldap_manager):
        group_tools.list_groups(ou="OU=G,DC=test,DC=local", filter_criteria="(description=*)")
        kwargs = mock_ldap_manager.search.call_args.kwargs
        assert kwargs["search_base"] == "OU=G,DC=test,DC=local"
        assert "(description=*)" in kwargs["search_filter"]

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        data = parse_response(group_tools.list_groups())
        assert data["success"] is False
        assert data["type"] == "LDAPException"


class TestGetGroup:
    def test_success(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, groupType=0x80000002, member=[MEMBER, "CN=x"], memberOf=["CN=p"])
        data = parse_response(group_tools.get_group("Sales"))
        assert data["dn"] == GROUP_DN
        assert data["computed"]["scope"] == "Global"
        assert data["computed"]["type"] == "Security"
        assert data["computed"]["member_count"] == 2
        assert data["computed"]["parent_groups_count"] == 1

    def test_not_found(self, group_tools, mock_ldap_manager):
        data = parse_response(group_tools.get_group("ghost"))
        assert data["success"] is False
        assert "not found" in data["error"]

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        assert parse_response(group_tools.get_group("Sales"))["success"] is False


class TestCreateGroup:
    def test_success(self, group_tools, mock_ldap_manager):
        data = parse_response(group_tools.create_group("Sales", description="d"))
        assert data["success"] is True
        dn, attrs = mock_ldap_manager.add.call_args.args
        assert dn == "CN=Sales,CN=Groups,DC=test,DC=local"
        assert attrs["groupType"] == 0x80000002
        assert attrs["description"] == "d"

    def test_explicit_ou_and_scope(self, group_tools, mock_ldap_manager):
        group_tools.create_group(
            "Mail", ou="OU=X,DC=test,DC=local", group_scope="Universal", group_type="Distribution"
        )
        dn, attrs = mock_ldap_manager.add.call_args.args
        assert dn == "CN=Mail,OU=X,DC=test,DC=local"
        assert attrs["groupType"] == 0x8

    def test_already_exists(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager)
        data = parse_response(group_tools.create_group("Sales"))
        assert data["success"] is False
        assert "already exists" in data["error"]
        mock_ldap_manager.add.assert_not_called()

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.add.side_effect = LDAPException("denied")
        data = parse_response(group_tools.create_group("Sales"))
        assert data["success"] is False
        assert "denied" in data["error"]


class TestModifyGroup:
    def test_success(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager)
        data = parse_response(group_tools.modify_group("Sales", {"description": "new"}))
        assert data["success"] is True
        mock_ldap_manager.modify.assert_called_once_with(
            GROUP_DN, {"description": [(MODIFY_REPLACE, ["new"])]}
        )

    def test_not_found(self, group_tools, mock_ldap_manager):
        assert parse_response(group_tools.modify_group("ghost", {"a": "b"}))["success"] is False

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException("nope")
        assert parse_response(group_tools.modify_group("Sales", {"a": "b"}))["success"] is False


class TestDeleteGroup:
    def test_success(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager)
        assert parse_response(group_tools.delete_group("Sales"))["success"] is True
        mock_ldap_manager.delete.assert_called_once_with(GROUP_DN)

    def test_not_found(self, group_tools, mock_ldap_manager):
        assert parse_response(group_tools.delete_group("ghost"))["success"] is False

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager)
        mock_ldap_manager.delete.side_effect = LDAPException("busy")
        assert parse_response(group_tools.delete_group("Sales"))["success"] is False


class TestMembership:
    def test_add_member(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[])
        data = parse_response(group_tools.add_member("Sales", MEMBER))
        assert data["success"] is True
        mock_ldap_manager.modify.assert_called_once_with(
            GROUP_DN, {"member": [(MODIFY_ADD, [MEMBER])]}
        )

    def test_add_member_already_present(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[MEMBER])
        data = parse_response(group_tools.add_member("Sales", MEMBER))
        assert data["success"] is False
        assert "already" in data["error"]
        mock_ldap_manager.modify.assert_not_called()

    def test_add_member_group_missing(self, group_tools, mock_ldap_manager):
        assert parse_response(group_tools.add_member("ghost", MEMBER))["success"] is False

    def test_add_member_ldap_error(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[])
        mock_ldap_manager.modify.side_effect = LDAPException("denied")
        assert parse_response(group_tools.add_member("Sales", MEMBER))["success"] is False

    def test_remove_member(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[MEMBER])
        data = parse_response(group_tools.remove_member("Sales", MEMBER))
        assert data["success"] is True
        mock_ldap_manager.modify.assert_called_once_with(
            GROUP_DN, {"member": [(MODIFY_DELETE, [MEMBER])]}
        )

    def test_remove_member_not_present(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[])
        data = parse_response(group_tools.remove_member("Sales", MEMBER))
        assert data["success"] is False
        assert "not in group" in data["error"]

    def test_remove_member_group_missing(self, group_tools, mock_ldap_manager):
        assert parse_response(group_tools.remove_member("ghost", MEMBER))["success"] is False

    def test_remove_member_ldap_error(self, group_tools, mock_ldap_manager):
        _group(mock_ldap_manager, member=[MEMBER])
        mock_ldap_manager.modify.side_effect = LDAPException("denied")
        assert parse_response(group_tools.remove_member("Sales", MEMBER))["success"] is False


class TestGetMembers:
    def test_flat(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN, member=[MEMBER])],
            [ldap_entry(MEMBER, objectClass=["top", "user"], sAMAccountName="jdoe")],
        ]
        data = parse_response(group_tools.get_members("Sales"))
        assert data["member_count"] == 1
        assert data["members"][0]["type"] == "user"
        assert data["members"][0]["level"] == 0

    def test_recursive_nested_group(self, group_tools, mock_ldap_manager):
        nested = "CN=Nested,CN=Groups,DC=test,DC=local"
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN, member=[nested])],
            [ldap_entry(nested, objectClass=["top", "group"], sAMAccountName="Nested", member=[MEMBER])],
            [ldap_entry(MEMBER, objectClass=["top", "user"], sAMAccountName="jdoe")],
        ]
        data = parse_response(group_tools.get_members("Sales", recursive=True))
        assert [(m["type"], m["level"]) for m in data["members"]] == [("group", 0), ("user", 1)]

    def test_recursive_cycle_terminates(self, group_tools, mock_ldap_manager):
        # A contains B, B contains A: B is expanded once; A is re-listed but expanded at most once
        a = "CN=A,DC=test,DC=local"
        b = "CN=B,DC=test,DC=local"

        def fake_search(search_base, **kwargs):
            if "sAMAccountName=" in kwargs["search_filter"]:
                return [ldap_entry(a, member=[b])]
            members = {a: [b], b: [a]}[search_base]
            return [ldap_entry(search_base, objectClass=["group"], sAMAccountName="x", member=members)]

        mock_ldap_manager.search.side_effect = fake_search
        data = parse_response(group_tools.get_members("A", recursive=True))
        assert data["member_count"] <= 3

    def test_member_lookup_failure_reported(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN, member=[MEMBER])],
            LDAPException("referral"),
        ]
        data = parse_response(group_tools.get_members("Sales"))
        assert "Could not retrieve member details" in data["members"][0]["error"]

    def test_group_missing(self, group_tools, mock_ldap_manager):
        assert parse_response(group_tools.get_members("ghost"))["success"] is False

    def test_ldap_error(self, group_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        assert parse_response(group_tools.get_members("Sales"))["success"] is False


class TestHelpers:
    @pytest.mark.parametrize(
        "value,scope,gtype",
        [
            (SECURITY_GLOBAL, "Global", "Security"),
            (SECURITY_GLOBAL & 0xFFFFFFFF, "Global", "Security"),
            (0x00000004, "DomainLocal", "Distribution"),
            (0x80000008, "Universal", "Security"),
            (0, "Unknown", "Distribution"),
        ],
    )
    def test_scope_and_type(self, group_tools, value, scope, gtype):
        assert group_tools._get_group_scope(value) == scope
        assert group_tools._get_group_type(value) == gtype

    @pytest.mark.parametrize(
        "scope,gtype,expected",
        [
            ("Global", "Security", 0x80000002),
            ("DomainLocal", "Security", 0x80000004),
            ("Universal", "Distribution", 0x8),
            ("bogus", "Distribution", 0x2),
        ],
    )
    def test_calculate_group_type(self, group_tools, scope, gtype, expected):
        assert group_tools._calculate_group_type(scope, gtype) == expected

    def test_schema_info(self, group_tools):
        schema = group_tools.get_schema_info()
        for op in ("list_groups", "add_member", "remove_member", "get_members"):
            assert op in schema["operations"]


class TestGroupInputHardening:
    def test_list_groups_rejects_out_of_base_ou(self, group_tools, mock_ldap_manager):
        data = parse_response(group_tools.list_groups(ou="OU=X,DC=evil,DC=com"))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()

    @pytest.mark.parametrize("bad", ["(a=1))(|(objectClass=*)", "dept=IT"])
    def test_list_groups_rejects_malformed_filter(self, group_tools, mock_ldap_manager, bad):
        data = parse_response(group_tools.list_groups(filter_criteria=bad))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()

    def test_list_groups_valid_filter_text_unchanged(self, group_tools, mock_ldap_manager):
        group_tools.list_groups(filter_criteria="(mail=*)")
        sent = mock_ldap_manager.search.call_args.kwargs["search_filter"]
        assert sent == f"(&(objectClass={group_tools.ldap.ad_config.group_object_class})(mail=*))"

    def test_create_group_escapes_rdn(self, group_tools, mock_ldap_manager):
        data = parse_response(group_tools.create_group("a,OU=Admins"))
        assert data["success"] is True
        assert mock_ldap_manager.add.call_args.args[0] == (
            "CN=a\\,OU\\=Admins,CN=Groups,DC=test,DC=local"
        )

    def test_create_group_rejects_out_of_base_ou(self, group_tools, mock_ldap_manager):
        data = parse_response(group_tools.create_group("g", ou="OU=X,DC=evil,DC=com"))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.add.assert_not_called()

    @pytest.mark.parametrize("method", ["add_member", "remove_member"])
    def test_member_dn_outside_base_rejected(self, group_tools, mock_ldap_manager, method):
        data = parse_response(getattr(group_tools, method)("Sales", "CN=Evil,DC=evil,DC=com"))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()
        mock_ldap_manager.modify.assert_not_called()

    def test_get_members_skips_out_of_base_member(self, group_tools, mock_ldap_manager):
        outside = "CN=Evil,DC=evil,DC=com"
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN, sAMAccountName="Sales", member=[outside, MEMBER])],
            [ldap_entry(MEMBER, sAMAccountName="jdoe", objectClass=["user"])],
        ]
        data = parse_response(group_tools.get_members("Sales"))
        assert [m["dn"] for m in data["members"]] == [MEMBER]
        bases = [c.kwargs["search_base"] for c in mock_ldap_manager.search.call_args_list]
        assert outside not in bases
