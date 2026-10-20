"""Smoke tests for the MockDirectory harness plus one pinned test per fidelity limit.

The smoke tests drive the real LDAPManager and tool classes against ldap3
MOCK_SYNC. The ``test_fidelity_*`` tests pin observed mock behaviour (ldap3 2.9.1)
so TESTING_GUIDE.md ("Fidelity limits") cannot rot: if the mock changes, a test
fails and the guide must be updated.
"""

import logging
import socket
import ssl

import ldap3
import pytest
from ldap3 import MODIFY_REPLACE
from ldap3.core.exceptions import (
    LDAPAttributeError,
    LDAPEntryAlreadyExistsResult,
)

from active_directory_mcp.core import ldap_manager as ldap_manager_module
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
from active_directory_mcp.tools.user import UserTools
from tests.support.helpers import parse_response
from tests.support.mock_directory import MockDirectory

PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"
BIT_AND_FILTER = "(userAccountControl:1.2.840.113556.1.4.803:=2)"
IN_CHAIN_FILTER = "(memberOf:1.2.840.113556.1.4.1941:=CN=staff,CN=Groups,DC=test,DC=local)"


@pytest.fixture(autouse=True)
def _quiet_ldap_logs(caplog):
    caplog.set_level(logging.CRITICAL)


@pytest.fixture
def directory() -> MockDirectory:
    return MockDirectory()


@pytest.fixture
def seeded(directory):
    for name in ("alice", "bob", "carol", "dave", "erin"):
        directory.add_user(name, displayName=name.title(), mail=f"{name}@test.local")
    directory.add_user("frank", enabled=False)
    directory.add_group("staff")
    directory.add_computer("WS01")
    directory.add_ou("Eng")
    return directory


def _uac(directory: MockDirectory, sam: str):
    rows = directory.search(f"(sAMAccountName={sam})", ["userAccountControl"])
    return rows[0]["attributes"]["userAccountControl"]


# ---------------------------------------------------------------- harness plumbing


def test_patch_restores_real_ldap3_classes(directory):
    with directory.patch():
        assert ldap_manager_module.Server is not ldap3.Server
        assert ldap_manager_module.Connection is not ldap3.Connection
    assert ldap_manager_module.Server is ldap3.Server
    assert ldap_manager_module.Connection is ldap3.Connection


def test_patch_restores_after_exception(directory):
    with pytest.raises(RuntimeError):
        with directory.patch():
            raise RuntimeError("boom")
    assert ldap_manager_module.Server is ldap3.Server
    assert ldap_manager_module.Connection is ldap3.Connection
    assert ldap_manager_module.SKIP_SCHEMA is False or isinstance(
        ldap_manager_module.SKIP_SCHEMA, bool
    )


def test_harness_opens_no_sockets(seeded, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("socket connect attempted while the harness is active")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    with seeded.patch():
        manager = seeded.make_manager()
        assert manager.test_connection()["connected"] is True
        assert parse_response(UserTools(manager).get_user("alice"))["dn"].startswith("CN=alice")


def test_configs_and_env(directory, tmp_path):
    env = directory.env(tmp_path)
    assert set(env) == {"AD_MCP_CONFIG", "AD_PASSWORD"}
    import os
    from unittest.mock import patch

    from active_directory_mcp.config.loader import load_config

    with patch.dict(os.environ, env):
        config = load_config()
    assert config.active_directory.base_dn == directory.base_dn
    assert config.active_directory.password.get_secret_value() == directory.bind_password
    assert config.performance.page_size == 1000
    assert directory.ou_config().groups_ou == directory.groups_container


def test_seeds_are_ordered_and_deterministic():
    first, second = MockDirectory(), MockDirectory()
    assert first.seeds == second.seeds
    dn = first.add_user("x")
    assert first.seeds[-1][0] == dn


# ---------------------------------------------------------------- typed (schema) mode


def test_get_user_integer_uac_is_typed(seeded):
    with seeded.patch():
        tools = UserTools(seeded.make_manager())
        data = parse_response(tools.get_user("alice"))
    assert data["dn"] == "CN=alice,CN=Users,DC=test,DC=local"
    assert data["attributes"]["userAccountControl"] == [512]
    assert data["attributes"]["displayName"] == ["Alice"]


def test_list_users_small_page_returns_all_entries(seeded):
    # objectClass=user also matches the computer account, as in real AD: 6 users + 1 computer.
    with seeded.patch():
        tools = UserTools(seeded.make_manager(page_size=2))
        data = parse_response(tools.list_users())
    assert data["count"] == 7
    by_sam = {u["sAMAccountName"]: u for u in data["users"]}
    assert by_sam["alice"]["enabled"] is True
    assert by_sam["frank"]["enabled"] is False


def test_disable_then_enable_flips_uac_bit(seeded):
    with seeded.patch():
        tools = UserTools(seeded.make_manager())
        assert parse_response(tools.disable_user("alice"))["success"] is True
        assert _uac(seeded, "alice") == [514]
        assert parse_response(tools.enable_user("alice"))["success"] is True
        assert _uac(seeded, "alice") == [512]


def test_modify_and_delete_user(seeded):
    with seeded.patch():
        tools = UserTools(seeded.make_manager())
        assert parse_response(tools.modify_user("alice", {"title": "Engineer"}))["success"]
        assert seeded.search("(sAMAccountName=alice)", ["title"])[0]["attributes"]["title"] == [
            "Engineer"
        ]
        assert parse_response(tools.delete_user("alice"))["success"] is True
        assert seeded.search("(sAMAccountName=alice)") == []


def test_manager_add_search_round_trip(seeded):
    with seeded.patch():
        manager = seeded.make_manager()
        dn = "CN=Zed Z,CN=Users,DC=test,DC=local"
        manager.add(
            dn,
            {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "sAMAccountName": "zed",
                "userAccountControl": 512,
            },
        )
        found = manager.search(seeded.base_dn, "(sAMAccountName=zed)", ["userAccountControl"])
        assert found == [{"dn": dn, "attributes": {"userAccountControl": [512]}}]
        manager.delete(dn)
        assert seeded.search("(sAMAccountName=zed)") == []


def test_computer_tools_through_harness(seeded):
    with seeded.patch():
        tools = ComputerTools(seeded.make_manager())
        got = parse_response(tools.get_computer("WS01$"))
        assert got["attributes"]["userAccountControl"] == [4096]
        listed = parse_response(tools.list_computers())
        assert listed["count"] == 1 and listed["computers"][0]["enabled"] is True
        assert parse_response(tools.disable_computer("WS01$"))["success"] is True
        assert seeded.search("(sAMAccountName=WS01$)", ["userAccountControl"])[0]["attributes"][
            "userAccountControl"
        ] == [4098]
        assert parse_response(tools.delete_computer("WS01$"))["success"] is True
        assert seeded.search("(sAMAccountName=WS01$)") == []


def test_ou_tools_through_harness(seeded):
    ou_dn = "OU=Eng,DC=test,DC=local"
    with seeded.patch():
        tools = OrganizationalUnitTools(seeded.make_manager())
        assert parse_response(tools.get_ou(ou_dn))["dn"] == ou_dn
        listed = parse_response(tools.list_ous())
        assert [o["dn"] for o in listed["organizational_units"]] == [ou_dn]
        # delete_ou cannot be exercised here: see test_fidelity_onelevel_scope_includes_base.


def test_test_connection_reports_connected_and_search(directory):
    with directory.patch():
        info = directory.make_manager().test_connection()
    assert info["connected"] is True
    assert info["search_test"] is True
    assert info["bound"] is True
    assert info["user"] == directory.bind_dn


def test_bad_password_fails_to_connect(directory):
    with directory.patch():
        manager = directory.make_manager()
        manager.ad_config.password = type(manager.ad_config.password)("wrong-password")
        assert manager.test_connection()["connected"] is False


def test_manager_without_patch_uses_real_classes(directory):
    # Nothing leaked from earlier patch() contexts: a fresh manager gets a real ldap3.Server.
    manager = directory.make_manager()
    assert isinstance(manager._server_pool[0], ldap3.Server)
    assert not directory.connections


# ---------------------------------------------------------------- schema-less mode


def test_schema_less_mode_group_membership_and_creates(seeded):
    alice = "CN=alice,CN=Users,DC=test,DC=local"
    with seeded.patch(schema_less=True):
        manager = seeded.make_manager()
        groups, users, computers = GroupTools(manager), UserTools(manager), ComputerTools(manager)
        assert parse_response(groups.add_member("staff", alice))["success"] is True
        members = seeded.search("(sAMAccountName=staff)", ["member"])[0]["attributes"]["member"]
        assert any(alice in str(m) for m in members)

        created = parse_response(users.create_user("newbie", "Str0ng-Placeholder!", "New", "Bie"))
        assert created["success"] is True
        assert seeded.search("(sAMAccountName=newbie)")[0]["dn"] == created["dn"]
        assert parse_response(groups.create_group("ops"))["success"] is True
        assert seeded.search("(sAMAccountName=ops)")
        assert parse_response(computers.create_computer("WS09"))["success"] is True
        assert seeded.search("(sAMAccountName=WS09$)")

    # Schema-less mode flips the module flag back after the context exits.
    assert ldap_manager_module.SKIP_SCHEMA is False


def test_schema_less_mode_stringifies_integers(seeded):
    with seeded.patch(schema_less=True):
        data = parse_response(UserTools(seeded.make_manager()).get_user("alice"))
    assert data["attributes"]["userAccountControl"] == ["b'512'"]


# ------------------------------------------------------- regressions for former product bugs


def test_create_user_round_trip_schema_mode(directory):
    with directory.patch():
        tools = UserTools(directory.make_manager())
        assert parse_response(tools.create_user("bob2", "Str0ng-Placeholder!", "Bob", "Two"))[
            "success"
        ]


def test_create_ou_succeeds(directory):
    with directory.patch(schema_less=True):
        tools = OrganizationalUnitTools(directory.make_manager())
        assert parse_response(tools.create_ou("Sales"))["success"] is True


# ---------------------------------------------------------------- fidelity limits


def test_fidelity_extensible_match_filters_unsupported(seeded):
    # Real AD evaluates bit-AND (803) and IN_CHAIN (1941) matching rules; ldap3 MOCK_SYNC cannot.
    with seeded.patch():
        manager = seeded.make_manager()
        connection = manager.connect()
        for flt in (BIT_AND_FILTER, IN_CHAIN_FILTER):
            with pytest.raises(LDAPAttributeError):
                connection.search(seeded.base_dn, flt, attributes=["sAMAccountName"])
            with pytest.raises(LDAPAttributeError):
                manager.search(seeded.base_dn, flt, ["sAMAccountName"])


def test_fidelity_unicodepwd_write_has_no_tls_or_encoding_enforcement():
    # Real AD refuses unicodePwd writes on a non-TLS bind (unwillingToPerform) and
    # validates the UTF-16LE quoted encoding. The mock accepts both.
    directory = MockDirectory(server_url="ldap://dc.test.local")
    directory.add_user("alice")
    with directory.patch():
        manager = directory.make_manager()
        connection = manager.connect()
        assert connection.server.ssl is False and connection.tls_started is False
        dn = "CN=alice,CN=Users,DC=test,DC=local"
        assert manager.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [b"not-utf16-quoted"])]})
        assert manager.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, ['"x"'.encode("utf-16-le")])]})


def test_fidelity_tls_not_emulated(seeded):
    # Real clients validate the certificate chain. The harness drops the Tls object, so
    # a config requiring certificate validation still binds without any chain check; Server.ssl
    # follows the URL scheme only and no TLS session is ever started.
    with seeded.patch():
        manager = seeded.make_manager()
        connection = manager.connect()
        assert connection.server.ssl is True
        assert connection.tls_started is False
        # LDAPManager asked for validated certificates; the harness-built Server ignores that.
        assert connection.server.tls.validate == ssl.CERT_NONE
        assert connection.server.tls.ca_certs_file is None
    plain = MockDirectory(server_url="ldap://dc.test.local")
    with plain.patch():
        assert plain.make_manager().connect().server.ssl is False


def _spy_pages(manager, base, flt, size_limit=0):
    connection = manager.connect()
    original = connection.search
    pages = []

    def spy(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        finally:
            control = connection.result.get("controls", {}).get(PAGED_RESULTS_OID, {})
            pages.append(
                (kwargs.get("paged_size"), len(connection.entries), control["value"]["cookie"])
                if control
                else (kwargs.get("paged_size"), len(connection.entries), None)
            )

    connection.search = spy
    try:
        return manager.search(base, flt, ["sAMAccountName"], size_limit=size_limit), pages
    finally:
        connection.search = original


def test_fidelity_paged_search_cookie_behaviour(seeded):
    # 7 entries match objectClass=user (6 users + the computer account).
    with seeded.patch():
        # page_size smaller than the result set: every entry is returned over several pages
        # and the last page carries an empty cookie. Non-empty cookies are opaque random bytes.
        results, pages = _spy_pages(
            seeded.make_manager(page_size=2), seeded.base_dn, "(objectClass=user)"
        )
        assert len(results) == 7
        assert [(size, count) for size, count, _ in pages] == [(2, 2), (2, 2), (2, 2), (2, 1)]
        assert all(cookie for _, _, cookie in pages[:-1])
        assert pages[-1][2] == b""

        # size_limit smaller than page_size shrinks the page: one page, no further request.
        results, pages = _spy_pages(
            seeded.make_manager(page_size=5), seeded.base_dn, "(objectClass=user)", size_limit=3
        )
        assert len(results) == 3
        assert [(size, count) for size, count, _ in pages] == [(3, 3)]

        # page_size larger than the result set: single page, empty cookie.
        results, pages = _spy_pages(
            seeded.make_manager(page_size=50), seeded.base_dn, "(objectClass=user)"
        )
        assert len(results) == 7 and [(s, c) for s, c, _ in pages] == [(50, 7)]
        assert pages[0][2] == b""

        # Exhausted-cookie case: when the result count is an exact multiple of page_size the
        # mock hands back a non-empty cookie and then an empty final page. ldap3 reports an
        # empty page as False; LDAPManager.search treats result code 0 as success, so the
        # empty final page ends the loop and all entries are returned.
        # Real AD behaviour for this boundary is not verified here (live-AD checklist).
        exact = seeded.make_manager(page_size=7).search(
            seeded.base_dn, "(objectClass=user)", ["sAMAccountName"]
        )
        assert len(exact) == 7


def test_empty_result_returns_empty_list_in_both_modes(seeded):
    # ldap3 search() returns False for zero entries with result code 0: that is success.
    for kwargs in ({}, {"schema_less": True}):
        with seeded.patch(**kwargs):
            manager = seeded.make_manager()
            assert manager.search(seeded.base_dn, "(sAMAccountName=nobody)", ["cn"]) == []


def test_empty_last_page_does_not_raise(seeded):
    # 2 seeded users + exact page-size multiple -> final page is empty.
    with seeded.patch():
        found = seeded.make_manager(page_size=1).search(
            seeded.base_dn, "(&(objectClass=user)(sAMAccountName=alice))", ["sAMAccountName"]
        )
    assert len(found) == 1


def test_base_search_on_missing_entry_returns_empty(seeded):
    from ldap3 import BASE

    with seeded.patch():
        manager = seeded.make_manager()
        missing = "OU=Nope," + seeded.base_dn
        assert manager.search(missing, "(objectClass=*)", ["name"], search_scope=BASE) == []


def test_group_tools_work_in_schema_mode(seeded):
    from active_directory_mcp.tools.group import GroupTools

    with seeded.patch():
        tools = GroupTools(seeded.make_manager())
        assert isinstance(parse_response(tools.list_groups()), (dict, list))
        assert parse_response(tools.get_members("nonexistent-group"))["success"] is False
        assert parse_response(tools.get_group("nonexistent-group"))["success"] is False


def test_fidelity_non_leaf_delete_allowed(seeded):
    # Real AD refuses to delete a non-leaf entry (notAllowedOnNonLeaf). The mock deletes the
    # container and leaves its children in place.
    with seeded.patch():
        manager = seeded.make_manager()
        assert manager.delete(seeded.users_container) is True
        remaining = seeded.search("(sAMAccountName=alice)")
        assert [r["dn"] for r in remaining] == ["CN=alice,CN=Users,DC=test,DC=local"]


def test_fidelity_add_under_missing_parent_allowed(seeded):
    # Real AD returns noSuchObject when the parent is missing. The mock does not check.
    with seeded.patch():
        manager = seeded.make_manager()
        dn = "CN=orphan,OU=DoesNotExist,DC=test,DC=local"
        assert manager.add(dn, {"objectClass": ["top", "person"], "sAMAccountName": "orphan"})
        assert seeded.search("(sAMAccountName=orphan)")[0]["dn"] == dn


def test_fidelity_duplicate_add_exception_type(seeded):
    # Observed with raise_exceptions=True: the mock raises LDAPEntryAlreadyExistsResult, a
    # result exception, not an LDAPOperationResult carrying AD's exact diagnostic text.
    with seeded.patch():
        manager = seeded.make_manager()
        with pytest.raises(LDAPEntryAlreadyExistsResult):
            manager.add(
                "CN=alice,CN=Users,DC=test,DC=local",
                {"objectClass": ["top", "person", "organizationalPerson", "user"]},
            )


def test_fidelity_no_ad_computed_attributes(seeded):
    # Real AD back-links memberOf and stamps whenCreated/pwdLastSet/objectGUID/objectSid.
    alice = "CN=alice,CN=Users,DC=test,DC=local"
    with seeded.patch(schema_less=True):
        manager = seeded.make_manager()
        GroupTools(manager).add_member("staff", alice)
        UserTools(manager).create_user("newbie", "Str0ng-Placeholder!", "New", "Bie")
        attrs = ["memberOf", "whenCreated", "pwdLastSet", "objectGUID", "objectSid"]
        for sam in ("alice", "newbie"):
            row = seeded.search(f"(sAMAccountName={sam})", attrs)[0]["attributes"]
            assert all(row[name] == [] for name in attrs), row


def test_fidelity_state_is_per_connection(seeded):
    # Writes live in the Connection that made them; a fresh Connection replays only the seeds.
    with seeded.patch():
        first = seeded.make_manager()
        first.delete("CN=alice,CN=Users,DC=test,DC=local")
        assert seeded.search("(sAMAccountName=alice)") == []
        second = seeded.make_manager()
        assert [
            e["dn"] for e in second.search(seeded.base_dn, "(sAMAccountName=alice)", ["cn"])
        ] == ["CN=alice,CN=Users,DC=test,DC=local"]
        assert len(seeded.connections) == 2
        # The first manager still sees its own delete.
        assert first.search(seeded.base_dn, "(sAMAccountName=alice)", ["cn"]) == []


def test_fidelity_case_handling(seeded):
    # DN, attribute-value comparison for sAMAccountName and attribute names are
    # case-insensitive; returned attribute keys use the schema's canonical case (schema mode).
    with seeded.patch():
        connection = seeded.make_manager().connect()
        assert connection.search(
            seeded.base_dn.lower(), "(sAMAccountName=ALICE)", attributes=["samaccountname"]
        )
        assert connection.entries[0].entry_dn == "CN=alice,CN=Users,DC=test,DC=local"
        assert connection.entries[0].entry_attributes_as_dict == {"sAMAccountName": ["alice"]}


def test_fidelity_any_privilege_is_granted(seeded):
    # No ACLs: the bind account can rewrite the domain root, other accounts and itself.
    with seeded.patch():
        manager = seeded.make_manager()
        assert manager.modify(seeded.base_dn, {"description": [(MODIFY_REPLACE, ["changed"])]})
        assert manager.modify(
            "CN=alice,CN=Users,DC=test,DC=local",
            {"userAccountControl": [(MODIFY_REPLACE, [2])]},
        )
        assert manager.modify(seeded.bind_dn, {"description": [(MODIFY_REPLACE, ["self"])]})


def test_fidelity_onelevel_scope_includes_base(seeded):
    # Real AD one-level searches return only the children. MOCK_SYNC returns the base entry
    # as well, so LDAPManager callers that pass search_scope=1 (OU child counting and the
    # forced OU content delete) see the OU itself as its own child: delete_ou(force=True)
    # recurses until RecursionError and delete_ou() always reports child objects.
    ou_dn = "OU=Eng,DC=test,DC=local"
    with seeded.patch():
        connection = seeded.make_manager().connect()
        assert connection.search(ou_dn, "(objectClass=*)", search_scope=ldap3.LEVEL)
        assert [e.entry_dn for e in connection.entries] == [ou_dn]
        tools = OrganizationalUnitTools(seeded.make_manager())
        forced = parse_response(tools.delete_ou(ou_dn, force=True))
        assert forced["success"] is False and forced["type"] == "RecursionError"
        plain = parse_response(tools.delete_ou(ou_dn))
        assert plain["success"] is False and plain["child_count"] == 1
