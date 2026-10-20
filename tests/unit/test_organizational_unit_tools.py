"""Unit tests for OrganizationalUnitTools (mocked LDAP; no server needed)."""

import pytest

from tests.support.helpers import ldap_entry, parse_response

OU = "OU=Sales,DC=test,DC=local"
OU_CLASSES = ["top", "organizationalUnit"]


def _ou(dn=OU, **attrs):
    return ldap_entry(dn, objectClass=OU_CLASSES, name=dn.split(",")[0][3:], **attrs)


def _tree(mapping):
    """search side_effect: ONELEVEL listing of search_base comes from `mapping`; BASE
    existence checks (objectClass=organizationalUnit with scope BASE) succeed."""

    def search(search_base, search_filter, attributes=None, search_scope=2, **_):
        if search_scope == 1 and search_filter == "(objectClass=*)":
            return mapping.get(search_base, [])
        return [_ou(search_base)]

    return search


# ------------------------------------------------------------------- list_ous


def test_list_ous_success_sorted_with_levels_and_gplink(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        _ou(
            "OU=B,OU=A,DC=test,DC=local",
            description="child",
            gPLink="[LDAP://cn={ABC-123},cn=policies,cn=system,DC=test,DC=local;0]",
        ),
        _ou("OU=A,DC=test,DC=local", managedBy="CN=boss,DC=test,DC=local"),
    ]
    data = parse_response(ou_tools.list_ous())
    assert data["count"] == 2
    ous = data["organizational_units"]
    assert [o["name"] for o in ous] == ["A", "B"]
    assert [o["level"] for o in ous] == [1, 2]
    assert ous[0]["managedBy"] == "CN=boss,DC=test,DC=local"
    assert ous[1]["linkedGPOs"][0]["guid"] == "ABC-123"


def test_list_ous_parent_filter_and_nonrecursive(ou_tools, mock_ldap_manager):
    ou_tools.list_ous(parent_ou=OU, filter_criteria="(name=x*)", recursive=False)
    kwargs = mock_ldap_manager.search.call_args.kwargs
    assert kwargs["search_base"] == OU
    assert kwargs["search_filter"] == "(&(objectClass=organizationalUnit)(name=x*))"
    assert kwargs["search_scope"] == 1


def test_list_ous_failure(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("down")
    data = parse_response(ou_tools.list_ous())
    assert data["success"] is False


# --------------------------------------------------------------------- get_ou


def test_get_ou_success_with_counts(ou_tools, mock_ldap_manager):
    def search(search_base, search_filter, attributes=None, search_scope=2, **_):
        if search_filter == "(objectClass=*)":
            return [ldap_entry("CN=x," + OU), ldap_entry("OU=y," + OU)]
        return [_ou(search_base)]

    mock_ldap_manager.search.side_effect = search
    data = parse_response(ou_tools.get_ou(OU))
    assert data["dn"] == OU
    assert data["computed"]["child_objects_count"] == 2
    assert data["computed"]["level"] == 1


def test_get_ou_invalid_dn(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.get_ou("not a dn"))
    assert data["success"] is False
    assert "Invalid DN" in data["error"]
    mock_ldap_manager.search.assert_not_called()


def test_get_ou_not_found(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.get_ou(OU))
    assert data["success"] is False
    assert "not found" in data["error"]


def test_get_ou_failure(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("boom")
    assert parse_response(ou_tools.get_ou(OU))["success"] is False


# ------------------------------------------------------------------ create_ou


def test_create_ou_success(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.create_ou("Ops", description="d", managed_by="CN=m,DC=test,DC=local"))
    assert data["success"] is True
    assert data["dn"] == "OU=Ops,DC=test,DC=local"
    dn, attrs = mock_ldap_manager.add.call_args.args
    assert dn == "OU=Ops,DC=test,DC=local"
    assert attrs["objectClass"] == OU_CLASSES
    assert attrs["description"] == "d"
    assert attrs["managedBy"] == "CN=m,DC=test,DC=local"


def test_create_ou_under_parent(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.create_ou("Sub", parent_ou=OU))
    assert data["dn"] == f"OU=Sub,{OU}"


def test_create_ou_already_exists(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_ou("OU=Ops,DC=test,DC=local")]
    data = parse_response(ou_tools.create_ou("Ops"))
    assert data["success"] is False
    assert "already exists" in data["error"]
    mock_ldap_manager.add.assert_not_called()


def test_create_ou_add_returns_false_and_exception(ou_tools, mock_ldap_manager):
    mock_ldap_manager.add.return_value = False
    assert parse_response(ou_tools.create_ou("Ops"))["success"] is False
    mock_ldap_manager.add.side_effect = Exception("denied")
    data = parse_response(ou_tools.create_ou("Ops"))
    assert data["success"] is False
    assert "denied" in data["error"]


# ------------------------------------------------------------------ modify_ou


def test_modify_ou_success(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_ou()]
    data = parse_response(ou_tools.modify_ou(OU, {"description": "x", "l": ["a"]}))
    assert data["success"] is True
    dn, mods = mock_ldap_manager.modify.call_args.args
    assert dn == OU
    assert mods["description"][0][1] == ["x"]
    assert mods["l"][0][1] == ["a"]


def test_modify_ou_invalid_not_found_failure(ou_tools, mock_ldap_manager):
    assert parse_response(ou_tools.modify_ou("bad", {"a": 1}))["success"] is False
    assert parse_response(ou_tools.modify_ou(OU, {"a": 1}))["success"] is False
    mock_ldap_manager.modify.assert_not_called()
    mock_ldap_manager.search.return_value = [_ou()]
    mock_ldap_manager.modify.side_effect = Exception("x")
    assert parse_response(ou_tools.modify_ou(OU, {"a": 1}))["success"] is False


# ------------------------------------------------------------------- delete_ou


def test_delete_ou_empty_without_force(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({})
    data = parse_response(ou_tools.delete_ou(OU))
    assert data["success"] is True
    mock_ldap_manager.delete.assert_called_once_with(OU)


def test_delete_ou_nonempty_without_force_refuses(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({OU: [ldap_entry("CN=u," + OU)]})
    data = parse_response(ou_tools.delete_ou(OU, force=False))
    assert data["success"] is False
    assert data["child_count"] == 1
    mock_ldap_manager.delete.assert_not_called()


def test_delete_ou_missing_returns_error(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.delete_ou(OU))
    assert data["success"] is False
    assert "not found" in data["error"]
    mock_ldap_manager.delete.assert_not_called()


def test_delete_ou_invalid_dn(ou_tools, mock_ldap_manager):
    assert parse_response(ou_tools.delete_ou("garbage"))["success"] is False
    mock_ldap_manager.delete.assert_not_called()


def test_delete_ou_delete_returns_false(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({})
    mock_ldap_manager.delete.return_value = False
    assert parse_response(ou_tools.delete_ou(OU))["success"] is False


def test_delete_ou_force_deletes_deepest_first_and_ou_last(ou_tools, mock_ldap_manager):
    sub = "OU=Sub," + OU
    leaf = "CN=leaf," + sub
    user = "CN=user," + OU
    mock_ldap_manager.search.side_effect = _tree(
        {
            OU: [_ou(sub), ldap_entry(user, objectClass=["top", "user"])],
            sub: [ldap_entry(leaf, objectClass=["top", "user"])],
        }
    )
    data = parse_response(ou_tools.delete_ou(OU, force=True))
    assert data["success"] is True
    assert data["forced"] is True
    order = [c.args[0] for c in mock_ldap_manager.delete.call_args_list]
    # current behavior: listing is walked in reverse; sub-OU contents go before the sub-OU
    assert order == [user, leaf, sub, OU]
    assert order.index(leaf) < order.index(sub) < order.index(OU)


def test_delete_ou_force_child_delete_failure_is_reported(ou_tools, mock_ldap_manager):
    bad = "CN=stuck," + OU
    mock_ldap_manager.search.side_effect = _tree(
        {OU: [ldap_entry(bad, objectClass=["top", "user"])]}
    )

    def delete(dn):
        if dn == bad:
            raise Exception("insufficient access")
        return True

    mock_ldap_manager.delete.side_effect = delete
    data = parse_response(ou_tools.delete_ou(OU, force=True))
    assert data["success"] is False
    assert bad in data["error"]
    # the OU itself must not be reported deleted nor attempted
    assert OU not in [c.args[0] for c in mock_ldap_manager.delete.call_args_list]


def test_delete_ou_force_child_listing_failure_is_reported(ou_tools, mock_ldap_manager):
    def search(search_base, search_filter, attributes=None, search_scope=2, **_):
        if search_filter == "(objectClass=*)":
            raise Exception("listing failed")
        return [_ou(search_base)]

    mock_ldap_manager.search.side_effect = search
    data = parse_response(ou_tools.delete_ou(OU, force=True))
    assert data["success"] is False
    mock_ldap_manager.delete.assert_not_called()


def test_delete_organizational_unit_alias(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({})
    assert parse_response(ou_tools.delete_organizational_unit(OU))["success"] is True


# --------------------------------------------------------------------- move_ou


def test_move_ou_success(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_ou()]
    target = "OU=Archive,DC=test,DC=local"
    data = parse_response(ou_tools.move_ou(OU, target))
    assert data["success"] is True
    assert data["new_dn"] == f"OU=Sales,{target}"
    mock_ldap_manager.move.assert_called_once_with(OU, target)


def test_move_ou_invalid_missing_parent_failure(ou_tools, mock_ldap_manager):
    target = "OU=Archive,DC=test,DC=local"
    assert parse_response(ou_tools.move_ou("bad", target))["success"] is False
    assert parse_response(ou_tools.move_ou(OU, target))["error"].startswith("OU not found")

    calls = iter([[_ou()], []])
    mock_ldap_manager.search.side_effect = lambda **_: next(calls)
    assert parse_response(ou_tools.move_ou(OU, target))["error"].startswith("Parent OU not found")

    mock_ldap_manager.search.side_effect = None
    mock_ldap_manager.search.return_value = [_ou()]
    mock_ldap_manager.move.side_effect = Exception("x")
    assert parse_response(ou_tools.move_ou(OU, target))["success"] is False


def test_move_organizational_unit_alias_param_names(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_ou()]
    target = "OU=Archive,DC=test,DC=local"
    assert parse_response(
        ou_tools.move_organizational_unit(source_dn=OU, destination_parent_dn=target)
    )["success"] is True


# ----------------------------------------------------------- get_ou_contents


def test_get_ou_contents_types_and_counts(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry("CN=u," + OU, objectClass=["top", "user"], sAMAccountName="u"),
        ldap_entry("CN=c," + OU, objectClass=["top", "user", "computer"], sAMAccountName="c$"),
        ldap_entry("CN=g," + OU, objectClass=["top", "group"], name="g"),
        _ou("OU=s," + OU),
        ldap_entry("CN=z," + OU, objectClass=["top"], name="z"),
    ]
    data = parse_response(ou_tools.get_ou_contents(OU))
    assert data["total_count"] == 5
    assert data["type_counts"] == {
        "computer": 1, "group": 1, "organizationalUnit": 1, "unknown": 1, "user": 1,
    }


def test_get_ou_contents_filter_by_type(ou_tools, mock_ldap_manager):
    ou_tools.get_ou_contents(OU, object_types=["computer"])
    assert mock_ldap_manager.search.call_args.kwargs["search_filter"] == "(|(objectClass=computer))"


def test_get_ou_contents_invalid_inputs_and_failure(ou_tools, mock_ldap_manager):
    assert parse_response(ou_tools.get_ou_contents("bad"))["success"] is False
    assert parse_response(ou_tools.get_ou_contents(OU, object_types=["nope"]))["success"] is False
    mock_ldap_manager.search.side_effect = Exception("x")
    assert parse_response(ou_tools.get_ou_contents(OU))["success"] is False


# ------------------------------------------------------------------- helpers


def test_parse_gp_link_well_formed(ou_tools):
    link = (
        "[LDAP://cn={AAA},cn=policies,cn=system,DC=test,DC=local;0]"
        "[LDAP://cn={BBB},cn=policies,cn=system,DC=test,DC=local;2]"
    )
    gpos = ou_tools._parse_gp_link(link)
    assert [g["guid"] for g in gpos] == ["AAA", "BBB"]
    assert [g["enabled"] for g in gpos] == [True, False]
    assert gpos[1]["options"] == 2


@pytest.mark.parametrize("link", ["", "garbage", "[no-semicolon]"])
def test_parse_gp_link_malformed_returns_empty(ou_tools, link):
    assert ou_tools._parse_gp_link(link) == []


def test_calculate_ou_level(ou_tools):
    base = "DC=test,DC=local"
    assert ou_tools._calculate_ou_level(base, base) == 0
    assert ou_tools._calculate_ou_level("OU=A," + base, base) == 1
    assert ou_tools._calculate_ou_level("OU=B,OU=A," + base, base) == 2
    assert ou_tools._calculate_ou_level("OU=A,DC=other,DC=com", base) == 0


@pytest.mark.parametrize("dn", ["", "OU=,DC=x", "noequals,DC=x", "=v,DC=x"])
def test_validate_dn_rejects_malformed(ou_tools, dn):
    assert ou_tools._validate_dn(dn) is False


def test_validate_dn_accepts_good(ou_tools):
    assert ou_tools._validate_dn(OU) is True


def test_extract_ou_name_and_validate_ou_dn(ou_tools):
    assert ou_tools._extract_ou_name(OU) == "Sales"
    assert ou_tools._extract_ou_name("CN=x,DC=y") == ""
    assert ou_tools._validate_ou_dn(OU) is True
    assert ou_tools._validate_ou_dn("CN=x,DC=y") is False


def test_schema_info(ou_tools):
    assert "delete_ou" in ou_tools.get_schema_info()["operations"]


# ------------------------------------------------ B-02: counting must not swallow errors


def test_count_child_objects_propagates_error(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("ldap down")
    with pytest.raises(Exception, match="ldap down"):
        ou_tools._count_child_objects(OU)


def test_count_sub_ous_propagates_error(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("ldap down")
    with pytest.raises(Exception, match="ldap down"):
        ou_tools._count_sub_ous(OU)


def test_delete_ou_refuses_when_child_count_fails(ou_tools, mock_ldap_manager):
    def search(search_base, search_filter, attributes=None, search_scope=2, **_):
        if search_filter == "(objectClass=*)":
            raise Exception("count failed")
        return [_ou(search_base)]

    mock_ldap_manager.search.side_effect = search
    data = parse_response(ou_tools.delete_ou(OU, force=False))
    assert data["success"] is False
    assert "count failed" in data["error"]
    mock_ldap_manager.delete.assert_not_called()


def test_get_ou_reports_error_when_counts_fail(ou_tools, mock_ldap_manager):
    def search(search_base, search_filter, attributes=None, search_scope=2, **_):
        if search_filter == "(objectClass=*)":
            raise Exception("count failed")
        return [_ou(search_base)]

    mock_ldap_manager.search.side_effect = search
    data = parse_response(ou_tools.get_ou(OU))
    assert data["success"] is False
    assert "computed" not in data


# ------------------------------------------------- config/validator hardening

OUTSIDE = "OU=X,DC=evil,DC=com"


@pytest.mark.parametrize(
    "call",
    [
        lambda t: t.list_ous(parent_ou=OUTSIDE),
        lambda t: t.list_ous(filter_criteria="(name=a*"),
        lambda t: t.list_ous(filter_criteria=")(objectClass=*"),
        lambda t: t.get_ou(OUTSIDE),
        lambda t: t.create_ou("Sales", parent_ou=OUTSIDE),
        lambda t: t.modify_ou(OUTSIDE, {"description": "x"}),
        lambda t: t.delete_ou(OUTSIDE),
        lambda t: t.delete_ou(OUTSIDE, force=True),
        lambda t: t.move_ou(OUTSIDE, "DC=test,DC=local"),
        lambda t: t.move_ou(OU, OUTSIDE),
        lambda t: t.get_ou_contents(OUTSIDE),
    ],
    ids=[
        "list-parent", "list-unbalanced", "list-breakout", "get", "create-parent", "modify",
        "delete", "delete-force", "move-src", "move-dest", "contents",
    ],
)
def test_ou_tools_reject_unconfined_or_hostile_input_without_ldap(
    ou_tools, mock_ldap_manager, call
):
    data = parse_response(call(ou_tools))
    assert data["success"] is False
    for name in ("search", "add", "modify", "delete", "move"):
        getattr(mock_ldap_manager, name).assert_not_called()


def test_outside_base_error_text_differs_from_invalid_dn(ou_tools):
    outside = parse_response(ou_tools.get_ou(OUTSIDE))
    malformed = parse_response(ou_tools.get_ou("not a dn"))
    assert "outside" in outside["error"]
    assert "Invalid DN" in malformed["error"]
    assert "outside" not in malformed["error"]


def test_create_ou_escapes_name_rdn(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.create_ou("Sales,OU=Admins"))
    assert data["success"] is True
    dn = mock_ldap_manager.add.call_args.args[0]
    assert dn.startswith("OU=Sales\\,OU\\=Admins,")
    assert dn.endswith("DC=test,DC=local")


def test_get_ou_contents_computer_branch_uses_configured_class(
    ou_tools, mock_ldap_manager, ad_settings
):
    ad_settings.computer_object_class = "device"
    ou_tools.get_ou_contents(OU, ["computer"])
    assert mock_ldap_manager.search.call_args.kwargs["search_filter"] == "(|(objectClass=device))"


def test_ou_level_and_gplink_fallbacks_are_preserved(ou_tools):
    assert ou_tools._calculate_ou_level(None, "DC=test,DC=local") == 0
    assert ou_tools._parse_gp_link(None) == []


# ------------------------------------------- base_dn protection (review CR-02)

BASE = "DC=test,DC=local"


def test_delete_ou_rejects_base_dn_itself(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({})
    data = parse_response(ou_tools.delete_ou(BASE, force=True))
    assert data["success"] is False
    mock_ldap_manager.delete.assert_not_called()
    mock_ldap_manager.search.assert_not_called()


def test_modify_ou_rejects_base_dn_itself(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.modify_ou(BASE, {"description": "x"}))
    assert data["success"] is False
    mock_ldap_manager.modify.assert_not_called()


def test_move_ou_rejects_base_dn_as_source(ou_tools, mock_ldap_manager):
    data = parse_response(ou_tools.move_ou(BASE, "OU=Archive,DC=test,DC=local"))
    assert data["success"] is False
    mock_ldap_manager.move.assert_not_called()


def test_move_ou_rejects_parent_beneath_itself(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_ou()]
    for target in (OU, "OU=Child," + OU):
        data = parse_response(ou_tools.move_ou(OU, target))
        assert data["success"] is False
    mock_ldap_manager.move.assert_not_called()


def test_move_ou_new_dn_escapes_special_characters(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(OU, objectClass=OU_CLASSES, name="A,B")]
    data = parse_response(ou_tools.move_ou(OU, "OU=Archive,DC=test,DC=local"))
    assert data["new_dn"] == "OU=A\\,B,OU=Archive,DC=test,DC=local"


def test_get_ou_statistics_formats_stats_not_flag(ou_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _tree({})
    data = parse_response(ou_tools.get_ou_statistics(OU))
    assert data["ou_dn"] == OU
    assert "total_objects" in data
