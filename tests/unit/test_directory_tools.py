"""Unit tests for DirectoryTools (mocked LDAPManager; MockDirectory cannot evaluate
extensible-match filters, so the chain query is asserted by its exact filter string)."""

import datetime as dt

import ldap3
import pytest
from ldap3.core.exceptions import LDAPException

from active_directory_mcp import validation
from active_directory_mcp.tools.directory import (
    HARD_MAX_RESULTS,
    ROOTDSE_ATTRIBUTES,
    SEARCH_TIME_LIMIT_SECONDS,
    DirectoryTools,
)
from tests.support.helpers import ldap_entry, parse_response

BASE = "DC=test,DC=local"
GROUP_DN = "CN=Admins,CN=Users,DC=test,DC=local"
CHAIN = "1.2.840.113556.1.4.1941"


@pytest.fixture
def directory_tools(mock_ldap_manager):
    return DirectoryTools(mock_ldap_manager)


def _member(cn, classes, sam=None):
    return ldap_entry(
        f"CN={cn},CN=Users,{BASE}",
        sAMAccountName=sam or cn,
        displayName=cn.upper(),
        objectClass=classes,
    )


class TestNestedGroupMembers:
    def test_chain_filter_and_call_order(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN, sAMAccountName="Admins")],
            [
                _member("alice", ["top", "person", "user"]),
                _member("inner", ["top", "group"]),
                _member("pc1", ["top", "user", "computer"]),
            ],
        ]
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        first, second = mock_ldap_manager.search.call_args_list
        assert "(sAMAccountName=Admins)" in first.kwargs["search_filter"]
        assert second.kwargs["search_filter"] == f"(memberOf:{CHAIN}:={GROUP_DN})"
        assert second.kwargs["search_base"] == BASE
        assert data["success"] is True and data["count"] == 3
        assert data["group_dn"] == GROUP_DN
        assert [m["type"] for m in data["members"]] == ["user", "group", "computer"]
        assert data["members"][0]["sAMAccountName"] == "alice"
        assert data["truncated"] is False

    def test_dn_metacharacters_escaped(self, directory_tools, mock_ldap_manager):
        evil_dn = "CN=a(b)c*d\\e,CN=Users,DC=test,DC=local"
        mock_ldap_manager.search.side_effect = [[ldap_entry(evil_dn)], []]
        directory_tools.get_nested_group_members("a")
        chain = mock_ldap_manager.search.call_args_list[1].kwargs["search_filter"]
        assert chain == f"(memberOf:{CHAIN}:=CN=a\\28b\\29c\\2ad\\5ce,CN=Users,DC=test,DC=local)"

    @pytest.mark.parametrize("bad", ["a\x00b", "a\nb", "", "  ", None, 5, "x" * 300])
    def test_bad_group_name_rejected_before_ldap(self, directory_tools, mock_ldap_manager, bad):
        data = parse_response(directory_tools.get_nested_group_members(bad))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()

    @pytest.mark.parametrize("name", ["Sales (EMEA)", "a)(objectClass=*", "x*", "a\\b"])
    def test_legitimate_and_hostile_names_are_escaped_not_rejected(
        self, directory_tools, mock_ldap_manager, name
    ):
        mock_ldap_manager.search.return_value = []
        directory_tools.get_nested_group_members(name)
        flt = mock_ldap_manager.search.call_args.kwargs["search_filter"]
        assert flt.endswith(validation.eq_filter("sAMAccountName", name) + ")")
        assert "(objectClass=*" not in flt

    def test_ambiguous_group_is_an_error(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = [
            ldap_entry(GROUP_DN), ldap_entry("CN=Admins,OU=x,DC=test,DC=local")
        ]
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        assert data["success"] is False and "ambiguous" in data["error"].lower()
        assert mock_ldap_manager.search.call_count == 1

    def test_not_found_no_second_search(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        data = parse_response(directory_tools.get_nested_group_members("ghost"))
        assert data["success"] is False and "not found" in data["error"]
        assert mock_ldap_manager.search.call_count == 1

    def test_outside_base_dn_dropped(self, directory_tools, mock_ldap_manager):
        outside = ldap_entry("CN=evil,DC=other,DC=com", sAMAccountName="evil", objectClass=["user"])
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN)],
            [outside, _member("alice", ["user"])],
        ]
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        assert [m["sAMAccountName"] for m in data["members"]] == ["alice"]

    def test_truncated(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.security_config.max_list_results = 2
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN)],
            [_member(n, ["user"]) for n in ("a", "b", "c")],
        ]
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        assert data["count"] == 2
        assert data["truncated"] is True and data["result_limit"] == 2
        assert mock_ldap_manager.search.call_args_list[1].kwargs["size_limit"] == 3

    @pytest.mark.parametrize("configured", [0, 10**9])
    def test_hard_ceiling_and_time_limit_even_when_unlimited(
        self, directory_tools, mock_ldap_manager, configured
    ):
        mock_ldap_manager.security_config.max_list_results = configured
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(GROUP_DN)],
            [_member(f"u{i}", ["user"]) for i in range(HARD_MAX_RESULTS + 1)],
        ]
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        second = mock_ldap_manager.search.call_args_list[1].kwargs
        assert second["size_limit"] == HARD_MAX_RESULTS + 1
        assert second["time_limit"] == SEARCH_TIME_LIMIT_SECONDS > 0
        assert data["count"] == HARD_MAX_RESULTS
        assert data["truncated"] is True and data["result_limit"] == HARD_MAX_RESULTS

    def test_ldap_error(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        data = parse_response(directory_tools.get_nested_group_members("Admins"))
        assert data["success"] is False and data["type"] == "LDAPException"


class TestRootDse:
    def test_query_shape_and_serialization(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = [
            {
                "dn": "",
                "attributes": {
                    "defaultNamingContext": BASE,
                    "dnsHostName": ["dc.test.local"],
                    "supportedLDAPVersion": ["2", "3"],
                    "currentTime": dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
                    "serverName": b"CN=DC,CN=Servers",
                    "isSynchronized": "TRUE",
                    "schemaNamingContext": [],
                    "unlisted": "secret",
                },
            }
        ]
        data = parse_response(directory_tools.get_rootdse_info())
        kwargs = mock_ldap_manager.search.call_args.kwargs
        assert kwargs["search_base"] == ""
        assert kwargs["search_filter"] == "(objectClass=*)"
        assert kwargs["search_scope"] == ldap3.BASE
        assert kwargs["attributes"] == list(ROOTDSE_ATTRIBUTES)
        info = data["rootdse"]
        assert info["dnsHostName"] == "dc.test.local"
        assert info["supportedLDAPVersion"] == ["2", "3"]
        assert info["currentTime"].startswith("2026-01-02T03:04:05")
        assert info["serverName"] == "CN=DC,CN=Servers"
        assert "schemaNamingContext" not in info and "unlisted" not in info

    def test_empty_result_is_structured_failure(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        assert parse_response(directory_tools.get_rootdse_info())["success"] is False

    def test_ldap_error(self, directory_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        assert parse_response(directory_tools.get_rootdse_info())["success"] is False
