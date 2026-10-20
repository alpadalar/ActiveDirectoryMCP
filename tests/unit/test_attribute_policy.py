"""Tests for the modify attribute allow-lists (SEC-03)."""

import pytest

from active_directory_mcp import attribute_policy as ap
from active_directory_mcp.attribute_policy import (
    HARD_DENY,
    MODIFY_ALLOWLIST,
    AttributeNotAllowedError,
    validate_modify_attributes,
)

TYPES = sorted(MODIFY_ALLOWLIST)


def test_four_types_defined():
    assert TYPES == ["computer", "group", "ou", "user"]


def test_allowlists_and_hard_deny_disjoint():
    deny = {n.lower() for n in HARD_DENY}
    for names in MODIFY_ALLOWLIST.values():
        assert not ({n.lower() for n in names} & deny)


def test_containers_are_immutable():
    assert isinstance(HARD_DENY, frozenset)
    assert all(isinstance(v, frozenset) for v in MODIFY_ALLOWLIST.values())


@pytest.mark.parametrize("otype", TYPES)
def test_full_allowed_set_accepted(otype):
    validate_modify_attributes(otype, {n: "x" for n in MODIFY_ALLOWLIST[otype]})


def test_case_insensitive_accept():
    validate_modify_attributes("user", {"DISPLAYNAME": "x", "GivenName": "y"})


def test_case_insensitive_reject():
    with pytest.raises(AttributeNotAllowedError) as exc:
        validate_modify_attributes("user", {"USERACCOUNTCONTROL": 512})
    assert exc.value.rejected == ("USERACCOUNTCONTROL",)


@pytest.mark.parametrize("otype", TYPES)
@pytest.mark.parametrize("name", sorted(HARD_DENY))
def test_hard_deny_rejected(otype, name):
    with pytest.raises(AttributeNotAllowedError):
        validate_modify_attributes(otype, {name: "v"})
    with pytest.raises(AttributeNotAllowedError):
        validate_modify_attributes(otype, {name.upper(): "v"})


@pytest.mark.parametrize("otype", TYPES)
def test_hard_deny_wins_even_if_allowlisted(otype, monkeypatch):
    widened = dict(MODIFY_ALLOWLIST)
    widened[otype] = MODIFY_ALLOWLIST[otype] | HARD_DENY
    monkeypatch.setattr(ap, "MODIFY_ALLOWLIST", widened)
    for name in HARD_DENY:
        with pytest.raises(AttributeNotAllowedError):
            validate_modify_attributes(otype, {name: "v"})


def test_mixed_rejects_atomically_and_lists_all_bad():
    with pytest.raises(AttributeNotAllowedError) as exc:
        validate_modify_attributes(
            "user", {"mail": "a@b", "memberOf": "x", "bogus": "y", "unicodePwd": "z"}
        )
    assert exc.value.rejected == ("bogus", "memberOf", "unicodePwd")
    assert "mail" in exc.value.allowed
    assert str(exc.value) == "Attribute(s) not permitted for user: bogus, memberOf, unicodePwd"


def test_error_text_has_no_values():
    secret = "S3cr3t-Value!"
    with pytest.raises(AttributeNotAllowedError) as exc:
        validate_modify_attributes("group", {"unicodePwd": secret, "description": secret})
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value.rejected + exc.value.allowed)


def test_non_string_key_rejected():
    with pytest.raises(AttributeNotAllowedError):
        validate_modify_attributes("user", {1: "x"})  # type: ignore[dict-item]


def test_empty_mapping_ok():
    validate_modify_attributes("user", {})


def test_unknown_type():
    with pytest.raises(ValueError):
        validate_modify_attributes("contact", {"mail": "x"})


def test_disjoint_invariant_raises_not_asserts():
    bad = {"user": ["description", "memberOf"]}
    with pytest.raises(RuntimeError, match="user.*memberof"):
        ap._check_allowlists_disjoint(bad, ap._HARD_DENY_LOWER)
    ap._check_allowlists_disjoint({"user": ["description"]}, ap._HARD_DENY_LOWER)


def test_module_contains_no_assert_statements():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ap))
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
