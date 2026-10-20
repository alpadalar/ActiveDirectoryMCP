"""Unit tests for UserTools (mocked LDAPManager, no directory server)."""

import logging
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
        data = parse_response(
            user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe", email="j@x")
        )
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


class TestUserInputHardening:
    def test_list_users_rejects_out_of_base_ou(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.list_users(ou="OU=X,DC=evil,DC=com"))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()

    @pytest.mark.parametrize("bad", ["(a=1))(|(objectClass=*)", "dept=IT", "(a=1"])
    def test_list_users_rejects_malformed_filter(self, user_tools, mock_ldap_manager, bad):
        data = parse_response(user_tools.list_users(filter_criteria=bad))
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.search.assert_not_called()

    def test_list_users_valid_filter_text_unchanged(self, user_tools, mock_ldap_manager):
        user_tools.list_users(filter_criteria="(department=IT)")
        sent = mock_ldap_manager.search.call_args.kwargs["search_filter"]
        assert (
            sent == f"(&(objectClass={user_tools.ldap.ad_config.user_object_class})(department=IT))"
        )

    def test_list_users_no_ou_uses_base_dn(self, user_tools, mock_ldap_manager):
        user_tools.list_users()
        assert mock_ldap_manager.search.call_args.kwargs["search_base"] == "DC=test,DC=local"

    def test_create_user_escapes_rdn(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "x,OU=Admins", "y"))
        assert data["success"] is True
        dn = mock_ldap_manager.add.call_args.args[0]
        assert dn == "CN=x\\,OU\\=Admins y,CN=Users,DC=test,DC=local"

    def test_create_user_default_uses_users_ou(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.organizational_units.users_ou = "OU=Staff,DC=test,DC=local"
        user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe")
        assert mock_ldap_manager.add.call_args.args[0] == "CN=John Doe,OU=Staff,DC=test,DC=local"

    def test_create_user_rejects_out_of_base_ou(self, user_tools, mock_ldap_manager):
        data = parse_response(
            user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe", ou="OU=X,DC=evil,DC=com")
        )
        assert data["success"] is False
        assert data["type"] == "ValidationError"
        mock_ldap_manager.add.assert_not_called()
        mock_ldap_manager.search.assert_not_called()

    def test_rollback_failure_is_logged_without_password(
        self, user_tools, mock_ldap_manager, caplog
    ):
        mock_ldap_manager.modify.side_effect = LDAPException("password policy")
        mock_ldap_manager.delete.side_effect = LDAPException("cannot delete")
        with caplog.at_level("WARNING"):
            data = parse_response(user_tools.create_user("jdoe", "Secret-Pw-9!", "John", "Doe"))
        assert data["success"] is False
        assert "password setting failed" in data["error"]
        assert "Secret-Pw-9!" not in caplog.text


class TestRuntimePasswordRedaction:
    """Passwords handled at runtime are registered, so errors cannot echo them (WR-05)."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        from active_directory_mcp import redaction

        redaction.clear_secrets()
        yield
        redaction.clear_secrets()

    def test_create_user_password_failure_does_not_echo_password(
        self, user_tools, mock_ldap_manager
    ):
        pw = "Zq9!rUntimeSecret"
        mock_ldap_manager.modify.side_effect = LDAPException(f"policy rejected {pw}")
        raw = user_tools.create_user("jdoe", pw, "John", "Doe")
        assert pw not in str(raw)
        assert parse_response(raw)["success"] is False

    def test_reset_password_supplied_failure_does_not_echo_password(
        self, user_tools, mock_ldap_manager
    ):
        pw = "Zq9!rUntimeSecret"
        _found(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException(f"bad {pw}")
        raw = user_tools.reset_password("jdoe", pw)
        assert pw not in str(raw)

    def test_reset_password_generated_is_registered_but_still_returned(
        self, user_tools, mock_ldap_manager
    ):
        from active_directory_mcp import redaction

        _found(mock_ldap_manager)
        data = parse_response(user_tools.reset_password("jdoe"))
        assert data["new_password"] != redaction.REDACTED
        assert redaction.redact(data["new_password"]) == redaction.REDACTED


# ---------------------------------------------------------------------------
# Phase 4 enforcement (SEC-03 / SEC-05 / SEC-06)
# ---------------------------------------------------------------------------


def _no_ldap_traffic(m):
    assert m.search.call_count == 0
    assert m.add.call_count == 0
    assert m.modify.call_count == 0


class TestModifyUserAllowList:
    @pytest.mark.parametrize(
        "attr", ["userAccountControl", "memberOf", "objectClass", "unicodePwd"]
    )
    def test_rejected_without_ldap_calls(self, user_tools, mock_ldap_manager, attr):
        data = parse_response(user_tools.modify_user("jdoe", {attr: "x"}))
        assert data["success"] is False
        assert data["error_code"] == "attribute_not_allowed"
        assert attr in data["rejected_attributes"]
        _no_ldap_traffic(mock_ldap_manager)

    def test_password_key_points_to_reset(self, user_tools, mock_ldap_manager):
        data = parse_response(user_tools.modify_user("jdoe", {"password": "Pw-1234!x"}))
        assert data["success"] is False
        assert data["error_code"] == "attribute_not_allowed"
        assert "reset_user_password" in data["error"]
        assert "Pw-1234!x" not in str(data)
        _no_ldap_traffic(mock_ldap_manager)

    def test_mixed_allowed_and_denied_rejects_all(self, user_tools, mock_ldap_manager):
        data = parse_response(
            user_tools.modify_user("jdoe", {"title": "Dev", "userAccountControl": 512})
        )
        assert data["success"] is False
        _no_ldap_traffic(mock_ldap_manager)

    def test_allowed_reaches_modify_replace(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager)
        data = parse_response(user_tools.modify_user("jdoe", {"department": "IT"}))
        assert data["success"] is True
        assert mock_ldap_manager.modify.call_args.args[1] == {
            "department": [(MODIFY_REPLACE, ["IT"])]
        }


class TestCreateUserEnforcement:
    def test_additional_attributes_rejected_before_add(self, user_tools, mock_ldap_manager):
        data = parse_response(
            user_tools.create_user(
                "jdoe",
                "Pw-1234!x",
                "John",
                "Doe",
                additional_attributes={"memberOf": ["CN=Admins"], "title": "x"},
            )
        )
        assert data["success"] is False
        assert data["error_code"] == "attribute_not_allowed"
        _no_ldap_traffic(mock_ldap_manager)

    def test_allowed_additional_attributes_pass(self, user_tools, mock_ldap_manager):
        data = parse_response(
            user_tools.create_user(
                "jdoe", "Pw-1234!x", "John", "Doe", additional_attributes={"title": "Dev"}
            )
        )
        assert data["success"] is True
        assert mock_ldap_manager.add.call_args.args[1]["title"] == "Dev"

    def test_non_tls_refused_first(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.return_value = False
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe"))
        assert data["error_code"] == "unicodePwd_requires_tls"
        _no_ldap_traffic(mock_ldap_manager)

    def test_channel_check_error_fails_closed(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.side_effect = LDAPException("boom")
        data = parse_response(user_tools.create_user("jdoe", "Pw-1234!x", "John", "Doe"))
        assert data["error_code"] == "unicodePwd_requires_tls"
        _no_ldap_traffic(mock_ldap_manager)


class TestResetPasswordEnforcement:
    def test_non_tls_refused_before_search(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.return_value = False
        gen = user_tools._generate_password
        user_tools._generate_password = lambda *a, **k: pytest.fail("generated password")
        try:
            data = parse_response(user_tools.reset_password("jdoe"))
        finally:
            user_tools._generate_password = gen
        assert data["error_code"] == "unicodePwd_requires_tls"
        _no_ldap_traffic(mock_ldap_manager)

    def test_channel_check_error_refuses(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.side_effect = RuntimeError("x")
        data = parse_response(user_tools.reset_password("jdoe", "Pw-1234!x"))
        assert data["error_code"] == "unicodePwd_requires_tls"
        _no_ldap_traffic(mock_ldap_manager)

    def test_set_user_password_defensive_raise(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.return_value = False
        with pytest.raises(RuntimeError) as exc:
            user_tools._set_user_password(USER_DN, "Pw-1234!x")
        assert "Pw-1234!x" not in str(exc.value)
        mock_ldap_manager.modify.assert_not_called()

    def test_password_returned_but_never_logged(self, user_tools, mock_ldap_manager, caplog):
        caplog.set_level(logging.DEBUG)
        _found(mock_ldap_manager)
        data = parse_response(user_tools.reset_password("jdoe"))
        generated = data["new_password"]  # returned by design
        data2 = parse_response(user_tools.reset_password("jdoe", "Supplied-Pw-9!zq"))
        assert data2["new_password"] == "Supplied-Pw-9!zq"
        for rec in caplog.records:
            msg = rec.getMessage()
            assert generated not in msg
            assert "Supplied-Pw-9!zq" not in msg

    def test_password_absent_from_error_and_logs_on_failure(
        self, user_tools, mock_ldap_manager, caplog
    ):
        caplog.set_level(logging.DEBUG)
        _found(mock_ldap_manager)
        mock_ldap_manager.modify.side_effect = LDAPException("policy Supplied-Pw-9!zq")
        data = parse_response(user_tools.reset_password("jdoe", "Supplied-Pw-9!zq"))
        assert data["success"] is False
        assert "Supplied-Pw-9!zq" not in str(data)
        assert all("Supplied-Pw-9!zq" not in r.getMessage() for r in caplog.records)


class TestListUsersCap:
    def _entries(self, n):
        return [ldap_entry(f"CN=U{i},DC=test,DC=local", sAMAccountName=f"u{i}") for i in range(n)]

    def test_cap_truncates(self, user_tools, mock_ldap_manager):
        limit = mock_ldap_manager.security_config.max_list_results
        mock_ldap_manager.search.return_value = self._entries(limit + 1)
        data = parse_response(user_tools.list_users())
        assert data["count"] == limit
        assert data["truncated"] is True
        assert data["result_limit"] == limit
        assert mock_ldap_manager.search.call_args.kwargs["size_limit"] == limit + 1

    def test_below_cap_not_truncated(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = self._entries(3)
        data = parse_response(user_tools.list_users())
        assert data["truncated"] is False and data["count"] == 3

    def test_zero_means_unlimited(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.security_config.max_list_results = 0
        mock_ldap_manager.search.return_value = self._entries(1500)
        data = parse_response(user_tools.list_users())
        assert data["count"] == 1500
        assert data["truncated"] is False
        assert "size_limit" not in mock_ldap_manager.search.call_args.kwargs

    def test_accuracy_note_only_with_lastlogon(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.search.return_value = self._entries(1)
        with_ll = parse_response(user_tools.list_users())  # default attrs include lastLogon
        assert "lastLogonTimestamp" in with_ll["accuracy_note"]
        without = parse_response(user_tools.list_users(attributes=["mail"]))
        assert "accuracy_note" not in without


class TestPrivilegedTargetProtection:
    """WR-02: password resets on privileged accounts need an explicit opt-out."""

    @pytest.fixture(autouse=True)
    def _secure(self, mock_ldap_manager):
        mock_ldap_manager.is_secure_channel.return_value = True

    @pytest.mark.parametrize("name", ["krbtgt", "Administrator", "ADMINISTRATOR"])
    def test_well_known_account_refused(self, user_tools, mock_ldap_manager, name):
        mock_ldap_manager.search.return_value = [ldap_entry(USER_DN, sAMAccountName=name)]
        data = parse_response(user_tools.reset_password(name, "Zq9!rUntimeSecret"))
        assert data["success"] is False and data["error_code"] == "protected_target"
        assert data["setting"] == "security.protect_privileged_targets"
        assert "Zq9!rUntimeSecret" not in str(data)
        mock_ldap_manager.modify.assert_not_called()

    def test_admincount_account_refused(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager, adminCount=1)
        data = parse_response(user_tools.reset_password("jdoe", "Zq9!rUntimeSecret"))
        assert data["error_code"] == "protected_target"
        mock_ldap_manager.modify.assert_not_called()

    def test_ordinary_user_allowed(self, user_tools, mock_ldap_manager):
        _found(mock_ldap_manager, adminCount=0)
        assert parse_response(user_tools.reset_password("jdoe", "Zq9!rUntimeSecret"))["success"]

    def test_opt_out_allows_administrator(self, user_tools, mock_ldap_manager):
        mock_ldap_manager.security_config.protect_privileged_targets = False
        mock_ldap_manager.search.return_value = [ldap_entry(USER_DN, sAMAccountName="krbtgt")]
        assert parse_response(user_tools.reset_password("krbtgt", "Zq9!rUntimeSecret"))["success"]
