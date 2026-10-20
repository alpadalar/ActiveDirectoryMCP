"""Unit tests for UserTools (mocked LDAPManager, no directory server)."""

from datetime import datetime, timedelta, timezone

import pytest
from ldap3 import MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from tests.support.helpers import ldap_entry, parse_response

USER_DN = "CN=John Doe,CN=Users,DC=test,DC=local"


def _found(mock_ldap_manager, dn=USER_DN, **attrs):
    mock_ldap_manager.search.return_value = [ldap_entry(dn, sAMAccountName="jdoe", **attrs)]


class TestListUsers:
    def test_success(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = [
            ldap_entry("CN=A,DC=test,DC=local", sAMAccountName="a", userAccountControl=512),
            ldap_entry("CN=B,DC=test,DC=local", sAMAccountName="b", userAccountControl=514),
        ]
        data = parse_response(user_tools.list_users())
        assert data["count"] == 2
        assert [u["enabled"] for u in data["users"]] == [True, False]
        mock_ldap_manager.search.assert_called_once()

    def test_filter_criteria_and_ou(self, user_tools, mock_ldap_manager):
        user_tools.list_users(ou="OU=X,DC=test,DC=local", filter_criteria="(mail=*)")
        kwargs = mock_ldap_manager.search.call_args.kwargs
        assert kwargs["search_base"] == "OU=X,DC=test,DC=local"
        assert kwargs["search_filter"].startswith("(&(objectClass=")
        assert "(mail=*)" in kwargs["search_filter"]

    def test_unreadable_uac_is_unknown_not_enabled(self, user_tools, mock_ldap_manager):
        """Fail closed (commit 60207c8): missing UAC must not be reported as enabled."""
        mock_ldap_manager.search.return_value = [
            ldap_entry("CN=A,DC=test,DC=local", sAMAccountName="a")
        ]
        data = parse_response(user_tools.list_users())
        assert data["users"][0]["enabled"] is None

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        data = parse_response(user_tools.list_users())
        assert data["success"] is False
        assert "Connection failed" in data["error"]
        assert data["type"] == "LDAPException"


class TestGetUser:
    def test_success_computed_fields(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager, userAccountControl=514, pwdLastSet=5, displayName="John Doe")
        data = parse_response(user_tools.get_user("jdoe"))
        assert data["dn"] == USER_DN
        assert data["attributes"]["sAMAccountName"] == ["jdoe"]
        assert data["computed"]["enabled"] is False
        assert data["computed"]["locked"] is False
        assert data["computed"]["password_expired"] is False
        assert data["computed"]["account_expired"] is False

    def test_account_expired_wired_through_get_user(self, user_tools, mock_ldap_manager):
        past = datetime.now(timezone.utc) - timedelta(days=3)
        _found(mock_ldap_manager, userAccountControl=512, accountExpires=past)
        data = parse_response(user_tools.get_user("jdoe"))
        assert data["computed"]["account_expired"] is True

    def test_not_found(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        data = parse_response(user_tools.get_user("ghost"))
        assert data["success"] is False
        assert "not found" in data["error"]

    def test_filter_is_escaped(self, user_tools, mock_ldap_manager):
        user_tools.get_user("a*)(uid=*")
        flt = mock_ldap_manager.search.call_args.kwargs["search_filter"]
        assert "a*)(uid=*" not in flt
        assert r"a\2a\29\28uid=\2a" in flt

    def test_filter_escape_does_not_double_escape(self, user_tools):
        assert user_tools._escape_ldap_filter("a\\b*") == "a\\5cb\\2a"

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("boom")
        data = parse_response(user_tools.get_user("jdoe"))
        assert data["success"] is False


class TestCreateUser:
    def test_success(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe", email="j@x"))
        assert data["success"] is True
        assert data["dn"] == USER_DN
        assert data["upn"] == "jdoe@test.local"
        dn, attrs = mock_ldap_manager.add.call_args.args
        assert dn == USER_DN
        assert attrs["userAccountControl"] == 514  # created disabled
        assert attrs["mail"] == "j@x"
        # password set, then account enabled
        assert mock_ldap_manager.modify.call_count == 2
        last = mock_ldap_manager.modify.call_args.args[1]
        assert last == {"userAccountControl": [(MODIFY_REPLACE, [512])]}

    def test_already_exists(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe"))
        assert data["success"] is False
        assert "already exists" in data["error"]
        mock_ldap_manager.add.assert_not_called()

    def test_add_failure(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        mock_ldap_manager.add.side_effect = LDAPException("denied")
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe"))
        assert data["success"] is False
        assert "denied" in data["error"]

    def test_password_failure_rolls_back(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = []
        mock_ldap_manager.modify.side_effect = LDAPException("password policy")
        data = parse_response(user_tools.create_user("jdoe", "weak", "John", "Doe"))
        assert data["success"] is False
        assert "password setting failed" in data["error"]
        mock_ldap_manager.delete.assert_called_once_with(USER_DN)


class TestModifyUser:
    def test_success(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.modify_user("jdoe", {"title": "Dev", "mail": ["a@x"]}))
        assert data["success"] is True
        changes = mock_ldap_manager.modify.call_args.args[1]
        assert changes == {
            "title": [(MODIFY_REPLACE, ["Dev"])],
            "mail": [(MODIFY_REPLACE, ["a@x"])],
        }

    def test_json_string_attributes(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.modify_user("jdoe", '{"title": "Dev"}'))
        assert data["success"] is True

    def test_password_handled_separately(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        parse_response(user_tools.modify_user("jdoe", {"password": "Pw-1234!x"}))
        changes = mock_ldap_manager.modify.call_args.args[1]
        assert list(changes) == ["unicodePwd"]

    def test_not_found(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.modify_user("ghost", {"title": "x"}))
        assert data["success"] is False
        mock_ldap_manager.modify.assert_not_called()

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException("nope")
        data = parse_response(user_tools.modify_user("jdoe", {"title": "x"}))
        assert data["success"] is False


class TestDeleteUser:
    def test_success(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.delete_user("jdoe"))
        assert data["success"] is True
        mock_ldap_manager.delete.assert_called_once_with(USER_DN)

    def test_not_found(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.delete_user("ghost"))
        assert data["success"] is False
        mock_ldap_manager.delete.assert_not_called()

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        mock_ldap_manager.delete.side_effect = LDAPException("busy")
        data = parse_response(user_tools.delete_user("jdoe"))
        assert data["success"] is False


class TestEnableDisable:
    @pytest.mark.parametrize("method,uac", [("enable_user", 512), ("disable_user", 514)])
    def test_success(self, user_tools, mock_ldap_manager, method, uac):
        _found(mock_ldap_manager)
        data = parse_response(getattr(user_tools, method)("jdoe"))
        assert data["success"] is True
        assert data["userAccountControl"] == uac
        mock_ldap_manager.modify.assert_called_once_with(
            USER_DN, {"userAccountControl": [(MODIFY_REPLACE, [uac])]}
        )

    @pytest.mark.parametrize("method", ["enable_user", "disable_user"])
    def test_not_found(self, user_tools, mock_ldap_manager, method):
        data = parse_response(getattr(user_tools, method)("ghost"))
        assert data["success"] is False

    @pytest.mark.parametrize("method", ["enable_user", "disable_user"])
    def test_ldap_error(self, user_tools, mock_ldap_manager, method):
        _found(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException("denied")
        data = parse_response(getattr(user_tools, method)("jdoe"))
        assert data["success"] is False


class TestResetPassword:
    def test_generated_password(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.reset_password("jdoe"))
        assert data["success"] is True
        assert isinstance(data["new_password"], str) and data["new_password"]
        assert data["force_change"] is True
        assert mock_ldap_manager.modify.call_count == 2  # unicodePwd + pwdLastSet=0

    def test_supplied_password_no_force(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.reset_password("jdoe", "Pw-1234!x", force_change=False))
        assert data["success"] is True
        assert mock_ldap_manager.modify.call_count == 1

    def test_not_found(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.reset_password("ghost"))
        assert data["success"] is False

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException("policy")
        data = parse_response(user_tools.reset_password("jdoe"))
        assert data["success"] is False
        assert "new_password" not in data


class TestGetUserGroups:
    def test_success(self, user_tools, mock_ldap_manager):
        groups = ["CN=Domain Users,CN=Users,DC=test,DC=local", "CN=Sales,OU=G,DC=test,DC=local"]
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(USER_DN, memberOf=groups)],
            [ldap_entry(groups[0], sAMAccountName="Domain Users")],
            [ldap_entry(groups[1], sAMAccountName="Sales", displayName="Sales Team")],
        ]
        data = parse_response(user_tools.get_user_groups("jdoe"))
        assert data["group_count"] == 2
        assert [g["sAMAccountName"] for g in data["groups"]] == ["Domain Users", "Sales"]

    def test_group_lookup_failure_is_reported_per_group(self, user_tools, mock_ldap_manager):
        group = "CN=Sales,OU=G,DC=test,DC=local"
        mock_ldap_manager.search.side_effect = [
            [ldap_entry(USER_DN, memberOf=[group])],
            LDAPException("referral"),
        ]
        data = parse_response(user_tools.get_user_groups("jdoe"))
        assert data["groups"] == [{"dn": group, "error": "Could not retrieve group details"}]

    def test_not_found(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.get_user_groups("ghost"))
        assert data["success"] is False

    def test_ldap_error(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.side_effect = LDAPException("down")
        data = parse_response(user_tools.get_user_groups("jdoe"))
        assert data["success"] is False


class TestHelpers:
    def test_password_generation(self, user_tools):
        pw = user_tools._generate_password()
        assert len(pw) >= 12
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(c in "!@#$%^&*" for c in pw)

    def test_uac_flags(self, user_tools):
        assert user_tools._is_user_enabled(512) is True
        assert user_tools._is_user_enabled(514) is False
        assert user_tools._is_user_locked(528) is True
        assert user_tools._is_user_locked(512) is False

    @pytest.mark.parametrize("bad", [None, "", "abc", [], object()])
    def test_unreadable_uac_fails_closed(self, user_tools, bad):
        assert user_tools._is_user_enabled(bad) is None
        assert user_tools._is_user_locked(bad) is None

    def test_uac_accepts_list_and_numeric_string(self, user_tools):
        assert user_tools._is_user_enabled([514]) is False
        assert user_tools._is_user_enabled("512") is True

    def test_schema_info(self, user_tools):
        schema = user_tools.get_schema_info()
        for op in ("list_users", "create_user", "modify_user", "delete_user", "get_user_groups"):
            assert op in schema["operations"]


NOW = datetime.now(timezone.utc)
PAST_DT = NOW - timedelta(days=30)
FUTURE_DT = NOW + timedelta(days=30)


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)) * 10


class TestAccountExpired:
    def _expired(self, user_tools, value, present=True):
        attrs = {"accountExpires": [value]} if present else {}
        return user_tools._is_account_expired(attrs)

    def test_is_account_expired_aware_datetime(self, user_tools):
        assert self._expired(user_tools, PAST_DT) is True
        assert self._expired(user_tools, FUTURE_DT) is False

    def test_is_account_expired_filetime_int(self, user_tools):
        assert self._expired(user_tools, _ft(PAST_DT)) is True
        assert self._expired(user_tools, _ft(FUTURE_DT)) is False

    def test_is_account_expired_filetime_numeric_string(self, user_tools):
        assert self._expired(user_tools, str(_ft(PAST_DT))) is True
        assert self._expired(user_tools, str(_ft(FUTURE_DT))) is False

    @pytest.mark.parametrize(
        "value",
        [
            0,
            None,
            9223372036854775807,
            datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            datetime(1601, 1, 1, tzinfo=timezone.utc),
        ],
        ids=["zero", "none", "never-int", "year-9999", "year-1601"],
    )
    def test_is_account_expired_sentinels_never_expire(self, user_tools, value):
        assert self._expired(user_tools, value) is False

    def test_is_account_expired_missing_attribute(self, user_tools):
        assert self._expired(user_tools, None, present=False) is False

    def test_is_account_expired_garbage_is_false(self, user_tools):
        assert self._expired(user_tools, "not-a-number") is False


class TestPasswordExpired:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, True),
            ("0", True),
            (datetime(1601, 1, 1, tzinfo=timezone.utc), True),
            (PAST_DT, False),
            (_ft(PAST_DT), False),
            (str(_ft(PAST_DT)), False),
        ],
    )
    def test_is_password_expired(self, user_tools, value, expected):
        assert user_tools._is_password_expired({"pwdLastSet": [value]}) is expected

    def test_missing_pwd_last_set_is_expired(self, user_tools):
        assert user_tools._is_password_expired({}) is True
