"""Unit tests for SecurityTools (mocked LDAP, no server needed).

Caveat kept for every inactive-account test below: `lastLogon` is per-DC and not
replicated, so inactive-account results are single-DC evidence (Phase 4 SEC-06
documents this for operators).

Bug regressions covered here: B-01b, B-01c (security parts), B-03, B-04 and the
restore-discovered B-15a (check_password_policy / generate_security_report).
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.support.helpers import ldap_entry, parse_response

NEVER = 9223372036854775807
NEG_NEVER = -9223372036854775808
DAY_TICKS = 864000000000
BASE = "DC=test,DC=local"
NOW = datetime.now(timezone.utc)


def _ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def _router(groups=None, users=None, domain=None):
    """Build a `search` side effect routing by base DN / filter.

    groups: {sAMAccountName: entry}; users: {member_dn: entry}; domain: entry list.
    """
    groups = groups or {}
    users = users or {}

    def search(search_base=None, search_filter="", attributes=None, search_scope=None, **_kw):
        if search_filter == "(objectClass=domain)":
            return domain or []
        if search_base in users:
            return [users[search_base]]
        for name, entry in groups.items():
            if f"(sAMAccountName={name})" in search_filter:
                return [entry]
        return []

    return search


def _domain_entry(**overrides):
    attrs = {
        "name": "test",
        "dc": "test",
        "objectSid": b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00",
        "whenCreated": _ago(365),
        "whenChanged": _ago(1),
        "lockoutThreshold": 5,
        "lockoutDuration": timedelta(minutes=30),
        "maxPwdAge": timedelta(days=42),
        "minPwdAge": timedelta(days=1),
        "minPwdLength": 12,
        "pwdHistoryLength": 24,
    }
    attrs.update(overrides)
    return ldap_entry(BASE, **attrs)


def _user(dn, sam, uac=512, last_logon=None, **extra):
    attrs = {"sAMAccountName": sam, "userAccountControl": uac, "logonCount": 3, "badPwdCount": 0}
    if last_logon is not None:
        attrs["lastLogon"] = last_logon
    attrs.update(extra)
    return ldap_entry(dn, **attrs)


# ---------------------------------------------------------------------------
# get_domain_info
# ---------------------------------------------------------------------------


def test_get_domain_info_success(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_domain_entry()]
    data = parse_response(security_tools.get_domain_info())
    assert data["name"] == "test"
    policy = data["password_policy"]
    assert policy["min_password_length"] == 12
    assert policy["password_history_length"] == 24
    assert policy["lockout_threshold"] == 5
    assert policy["lockout_duration"]["description"] == "30 minutes"
    assert policy["max_password_age"]["description"] == "42 days"
    assert data["object_sid"]  # bytes were base64 encoded, response is JSON


def test_get_domain_info_int_intervals(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        _domain_entry(lockoutDuration=-18000000000, maxPwdAge=-42 * DAY_TICKS, minPwdAge=-DAY_TICKS)
    ]
    policy = parse_response(security_tools.get_domain_info())["password_policy"]
    assert policy["lockout_duration"]["description"] == "30 minutes"
    assert policy["max_password_age"]["description"] == "42 days"
    assert policy["min_password_age"]["description"] == "1 days"


def test_get_domain_info_never_expiring_policy(security_tools, mock_ldap_manager):
    """B-03: ldap3 maps the AD 'never' maxPwdAge to timedelta.max."""
    mock_ldap_manager.search.return_value = [_domain_entry(maxPwdAge=timedelta.max)]
    policy = parse_response(security_tools.get_domain_info())["password_policy"]
    assert policy["max_password_age"]["description"] == "Never"


def test_get_domain_info_ldap_failure(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    data = parse_response(security_tools.get_domain_info())
    assert data["success"] is False


def test_get_domain_info_not_found(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = []
    assert parse_response(security_tools.get_domain_info())["success"] is False


# ---------------------------------------------------------------------------
# _convert_time_interval (B-03)
# ---------------------------------------------------------------------------


def test_convert_time_interval_timedelta_and_int_agree(security_tools):
    from_td = security_tools._convert_time_interval(timedelta(days=1))
    from_int = security_tools._convert_time_interval(-DAY_TICKS)
    assert from_td == from_int
    assert from_td["raw"] == DAY_TICKS
    assert from_td["seconds"] == 86400
    assert from_td["description"] == "1 days"


def test_convert_time_interval_thirty_minutes_consistent(security_tools):
    a = security_tools._convert_time_interval(timedelta(minutes=30))
    b = security_tools._convert_time_interval(-18000000000)
    assert a == b
    assert a["description"] == "30 minutes"
    assert a["raw"] == 18000000000


def test_convert_time_interval_description_units(security_tools):
    f = security_tools._convert_time_interval
    assert f(timedelta(seconds=45))["description"] == "45 seconds"
    assert f(timedelta(seconds=90))["description"] == "2 minutes"
    assert f(timedelta(hours=5))["description"] == "5 hours"
    assert f(timedelta(days=42))["description"] == "42 days"


@pytest.mark.parametrize(
    "value,raw",
    [
        (0, 0),
        (timedelta(0), 0),
        (None, 0),
        ("0", 0),
        (NEG_NEVER, NEVER),
        (NEVER, NEVER),
        (timedelta.max, NEVER),
        (timedelta(days=10**7 + 1), NEVER),
    ],
)
def test_convert_time_interval_never_sentinels(security_tools, value, raw):
    result = security_tools._convert_time_interval(value)
    assert result == {"raw": raw, "description": "Never"}
    assert "seconds" not in result


def test_convert_time_interval_numeric_string(security_tools):
    assert security_tools._convert_time_interval("-864000000000") == (
        security_tools._convert_time_interval(-DAY_TICKS)
    )


def test_convert_time_interval_non_numeric_string(security_tools):
    assert security_tools._convert_time_interval("abc") == {"raw": "abc", "description": "Unknown"}


# ---------------------------------------------------------------------------
# get_privileged_groups
# ---------------------------------------------------------------------------


def test_get_privileged_groups_success(security_tools, mock_ldap_manager):
    members = [f"CN=u{i},CN=Users,{BASE}" for i in range(12)]
    groups = {
        "Domain Admins": ldap_entry(
            f"CN=Domain Admins,CN=Users,{BASE}",
            sAMAccountName="Domain Admins",
            displayName="Domain Admins",
            member=members,
            objectSid=b"\x01\x02",
        ),
        "Backup Operators": ldap_entry(
            f"CN=Backup Operators,CN=Builtin,{BASE}",
            sAMAccountName="Backup Operators",
            member=[f"CN=svc,{BASE}"],
        ),
    }
    mock_ldap_manager.search.side_effect = _router(groups=groups)
    data = parse_response(security_tools.get_privileged_groups())
    assert data["total_groups"] == 2
    by_name = {g["sam_account_name"]: g for g in data["privileged_groups"]}
    assert by_name["Domain Admins"]["member_count"] == 12
    assert len(by_name["Domain Admins"]["members"]) == 10
    assert by_name["Domain Admins"]["members_truncated"] is True
    assert by_name["Domain Admins"]["total_members"] == 12
    assert by_name["Backup Operators"]["member_count"] == 1


def test_get_privileged_groups_per_group_failure_is_skipped(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("down")
    data = parse_response(security_tools.get_privileged_groups())
    assert data["total_groups"] == 0


# ---------------------------------------------------------------------------
# get_user_permissions + helpers
# ---------------------------------------------------------------------------


def test_get_user_permissions_success(security_tools, mock_ldap_manager):
    user_dn = f"CN=Alice,CN=Users,{BASE}"
    da_dn = f"CN=Domain Admins,CN=Users,{BASE}"
    user = ldap_entry(
        user_dn,
        sAMAccountName="alice",
        displayName="Alice",
        memberOf=[da_dn],
        userAccountControl=512 | 0x10000,
    )
    group = ldap_entry(da_dn, sAMAccountName="Domain Admins", displayName="Domain Admins")

    def search(search_base=None, search_filter="", **_kw):
        return [group] if search_base == da_dn else [user]

    mock_ldap_manager.search.side_effect = search
    data = parse_response(security_tools.get_user_permissions("alice"))
    assert data["privileged_groups_count"] == 1
    assert data["account_status"]["password_never_expires"] is True
    assert data["security_assessment"]["risk_level"] == "high"


def test_get_user_permissions_not_found(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = []
    data = parse_response(security_tools.get_user_permissions("ghost"))
    assert data["success"] is False


def test_get_user_permissions_ldap_failure(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    assert parse_response(security_tools.get_user_permissions("alice"))["success"] is False


def test_is_privileged_group(security_tools):
    assert security_tools._is_privileged_group("Domain Admins")
    assert security_tools._is_privileged_group("DNS ADMINS")
    assert not security_tools._is_privileged_group("Helpdesk")


def test_has_privileged_groups(security_tools):
    assert security_tools._has_privileged_groups([f"CN=Domain Admins,CN=Users,{BASE}"])
    assert not security_tools._has_privileged_groups([f"CN=Helpdesk,OU=Groups,{BASE}"])
    assert not security_tools._has_privileged_groups([])


def test_assess_user_security_levels(security_tools):
    ok = {"enabled": True, "password_not_required": False, "password_never_expires": False}
    assert security_tools._assess_user_security(ok, [])["risk_level"] == "low"
    assert security_tools._assess_user_security(ok, [{"x": 1}])["risk_level"] == "medium"
    bad = dict(ok, password_not_required=True)
    assessed = security_tools._assess_user_security(bad, [])
    assert assessed["risk_level"] == "high"
    assert "Password not required" in assessed["risk_factors"]


# ---------------------------------------------------------------------------
# _get_days_since_last_logon (B-01b)
# ---------------------------------------------------------------------------


def test_days_since_last_logon_datetime(security_tools):
    assert security_tools._get_days_since_last_logon({"lastLogon": _ago(10)}) in (10, 9)


def test_days_since_last_logon_list_wrapped_datetime(security_tools):
    assert security_tools._get_days_since_last_logon({"lastLogon": [_ago(30)]}) in (30, 29)


def test_days_since_last_logon_int_filetime(security_tools):
    ft = security_tools._convert_datetime_to_filetime(_ago(20))
    assert security_tools._get_days_since_last_logon({"lastLogon": ft}) in (20, 19)


def test_days_since_last_logon_numeric_string(security_tools):
    ft = security_tools._convert_datetime_to_filetime(_ago(5))
    assert security_tools._get_days_since_last_logon({"lastLogon": str(ft)}) in (5, 4)


@pytest.mark.parametrize(
    "attrs",
    [
        {"lastLogon": 0},
        {"lastLogon": None},
        {},
        {"lastLogon": NEVER},
        {"lastLogon": datetime(1601, 1, 1, tzinfo=timezone.utc)},
    ],
)
def test_days_since_last_logon_unset_is_none(security_tools, attrs):
    assert security_tools._get_days_since_last_logon(attrs) is None


# ---------------------------------------------------------------------------
# audit_admin_accounts (B-01c, B-04)
# ---------------------------------------------------------------------------


def _audit_setup(mock_ldap_manager, members):
    """members: list of (sam, uac, last_logon)."""
    dns = {sam: f"CN={sam},CN=Users,{BASE}" for sam, _, _ in members}
    groups = {
        "Domain Admins": ldap_entry(
            f"CN=Domain Admins,CN=Users,{BASE}",
            sAMAccountName="Domain Admins",
            member=list(dns.values()),
        )
    }
    users = {dns[sam]: _user(dns[sam], sam, uac, ll) for sam, uac, ll in members}
    mock_ldap_manager.search.side_effect = _router(groups=groups, users=users)


def test_audit_admin_accounts_datetime_lastlogon(security_tools, mock_ldap_manager):
    """B-01c: a datetime lastLogon used to raise inside the loop and skip the whole group."""
    _audit_setup(mock_ldap_manager, [("oldadmin", 512, _ago(120))])
    data = parse_response(security_tools.audit_admin_accounts())
    assert data["total_admin_accounts"] == 1
    account = data["admin_accounts"][0]
    assert account["sam_account_name"] == "oldadmin"
    assert isinstance(account["days_since_logon"], int)
    assert account["days_since_logon"] in (120, 119)
    assert any(i.startswith("No logon for") for i in account["security_issues"])


def test_audit_admin_accounts_never_logged_on(security_tools, mock_ldap_manager):
    _audit_setup(mock_ldap_manager, [("fresh", 512, 0)])
    account = parse_response(security_tools.audit_admin_accounts())["admin_accounts"][0]
    assert account["last_logon"] == "Never"
    assert account["days_since_logon"] is None


def test_audit_admin_accounts_risk_counts(security_tools, mock_ldap_manager):
    _audit_setup(
        mock_ldap_manager,
        [("high1", 512 | 0x20, _ago(1)), ("med1", 512, _ago(120)), ("low1", 512, _ago(1))],
    )
    data = parse_response(security_tools.audit_admin_accounts())
    assert (data["high_risk_count"], data["medium_risk_count"], data["low_risk_count"]) == (1, 1, 1)


def test_audit_admin_accounts_sorted_by_severity(security_tools, mock_ldap_manager):
    _audit_setup(
        mock_ldap_manager,
        [("amy", 512, _ago(1)), ("mid", 512, _ago(120)), ("zed", 512 | 0x20, _ago(1))],
    )
    data = parse_response(security_tools.audit_admin_accounts())
    assert [a["sam_account_name"] for a in data["admin_accounts"]] == ["zed", "mid", "amy"]


def test_audit_admin_accounts_ties_sorted_by_name(security_tools, mock_ldap_manager):
    _audit_setup(mock_ldap_manager, [("bob", 512, _ago(1)), ("alice", 512, _ago(1))])
    data = parse_response(security_tools.audit_admin_accounts())
    assert [a["sam_account_name"] for a in data["admin_accounts"]] == ["alice", "bob"]


def test_audit_admin_accounts_ldap_failure_is_structured(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    data = parse_response(security_tools.audit_admin_accounts())
    assert data["total_admin_accounts"] == 0  # per-group failures are logged and skipped


# ---------------------------------------------------------------------------
# recommendations (B-04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["high", "HIGH", "High"])
def test_recommendation_matches_risk_level_high(security_tools, level):
    assert security_tools._get_security_recommendation(level, []).startswith("Immediate action")


@pytest.mark.parametrize("level", ["medium", "MEDIUM"])
def test_recommendation_matches_risk_level_medium(security_tools, level):
    assert security_tools._get_security_recommendation(level, []).startswith("Review account")


@pytest.mark.parametrize("level", ["low", "LOW", "bogus", ""])
def test_recommendation_fallback(security_tools, level):
    assert security_tools._get_security_recommendation(level, []).startswith("Monitor account")


def test_recommendation_matches_risk_level(security_tools):
    status = {"enabled": True, "password_not_required": True, "password_never_expires": False}
    assessed = security_tools._assess_user_security(status, [])
    assert assessed["risk_level"] == "high"
    assert assessed["recommendation"].startswith("Immediate action")


# ---------------------------------------------------------------------------
# get_inactive_users (B-01c, single-DC lastLogon evidence)
# ---------------------------------------------------------------------------


def test_get_inactive_users_handles_datetime_int_and_never(security_tools, mock_ldap_manager):
    recent_ft = security_tools._convert_datetime_to_filetime(_ago(2))
    mock_ldap_manager.search.return_value = [
        _user(f"CN=old,{BASE}", "old", last_logon=_ago(200)),
        _user(f"CN=recent,{BASE}", "recent", last_logon=_ago(2)),
        _user(f"CN=recentint,{BASE}", "recentint", last_logon=recent_ft),
        _user(f"CN=never,{BASE}", "never", last_logon=0),
        _user(f"CN=nolast,{BASE}", "nolast"),
    ]
    data = parse_response(security_tools.get_inactive_users(days=90))
    names = {u["sam_account_name"] for u in data["inactive_users"]}
    assert names == {"old", "never", "nolast"}
    never = next(u for u in data["inactive_users"] if u["sam_account_name"] == "never")
    assert never["last_logon"] == "Never" and never["days_inactive"] is None
    old = next(u for u in data["inactive_users"] if u["sam_account_name"] == "old")
    assert old["days_inactive"] in (200, 199)
    # sorted descending by inactivity: the unknown ones come first (99999 sentinel)
    assert data["inactive_users"][-1]["sam_account_name"] == "old"


def test_get_inactive_users_ldap_failure(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    assert parse_response(security_tools.get_inactive_users())["success"] is False


# ---------------------------------------------------------------------------
# get_password_policy_violations
# ---------------------------------------------------------------------------


def test_password_policy_violations_datetime_values(security_tools, mock_ldap_manager):
    domain = [ldap_entry(BASE, maxPwdAge=timedelta(days=42), minPwdAge=timedelta(days=1))]
    users = [
        _user(
            f"CN=stale,{BASE}", "stale", uac=512,
            pwdLastSet=_ago(200), accountExpires=_ago(5),
        ),
        _user(
            f"CN=fine,{BASE}", "fine", uac=512,
            pwdLastSet=_ago(3), accountExpires=datetime(9999, 12, 31, tzinfo=timezone.utc),
        ),
        _user(f"CN=nopwd,{BASE}", "nopwd", uac=512 | 0x20, pwdLastSet=0, accountExpires=0),
    ]

    def search(search_filter="", **_kw):
        return domain if search_filter == "(objectClass=domain)" else users

    mock_ldap_manager.search.side_effect = search
    data = parse_response(security_tools.get_password_policy_violations())
    by_name = {v["sam_account_name"]: v for v in data["password_violations"]}
    assert set(by_name) == {"stale", "nopwd"}
    assert "Password expired" in by_name["stale"]["violations"]
    assert "Account expired" in by_name["stale"]["violations"]
    assert "Password never set" in by_name["nopwd"]["violations"]
    assert by_name["nopwd"]["pwd_last_set"] == "Never"


@pytest.mark.parametrize(
    "raw, policy_set",
    [
        (str(-42 * 864000000000), True),
        (-42 * 864000000000, True),
        ("0", False),
        (-(2 ** 63), False),
        ("-9223372036854775808", False),
        (None, False),
    ],
)
def test_password_policy_violations_normalises_max_pwd_age(
    security_tools, mock_ldap_manager, raw, policy_set
):
    domain = [ldap_entry(BASE, maxPwdAge=raw, minPwdAge=0)]
    users = [
        _user(
            f"CN=noexp,{BASE}", "noexp", uac=512 | 0x10000,
            pwdLastSet=_ago(200), accountExpires=0,
        )
    ]

    def search(search_filter="", **_kw):
        return domain if search_filter == "(objectClass=domain)" else users

    mock_ldap_manager.search.side_effect = search
    data = parse_response(security_tools.get_password_policy_violations())
    assert "password_violations" in data
    flagged = {v["sam_account_name"]: v["violations"] for v in data["password_violations"]}
    if policy_set:
        assert "Password set to never expire" in flagged["noexp"]
        assert "Password expired" in flagged["noexp"]
    else:
        assert "noexp" not in flagged


def test_password_policy_violations_ldap_failure(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    assert parse_response(security_tools.get_password_policy_violations())["success"] is False


# ---------------------------------------------------------------------------
# check_password_policy / generate_security_report (B-15a)
# ---------------------------------------------------------------------------


def test_check_password_policy_compliant(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_domain_entry(minPwdLength=12, pwdHistoryLength=24)]
    data = parse_response(security_tools.check_password_policy())
    assert data["policy_compliant"] is True
    assert data["recommendations"] == []


def test_check_password_policy_weak(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [_domain_entry(minPwdLength=4, pwdHistoryLength=1)]
    data = parse_response(security_tools.check_password_policy())
    assert data["policy_compliant"] is False
    assert len(data["recommendations"]) == 2


def test_check_password_policy_failure(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = RuntimeError("boom")
    assert parse_response(security_tools.check_password_policy())["success"] is False


def test_generate_security_report_success(security_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = _router(domain=[_domain_entry()])
    data = parse_response(security_tools.generate_security_report())
    assert data["executive_summary"]["password_policy_compliant"] is True
    assert "detailed_findings" in data
    assert data["recommendations"]


def test_generate_security_report_failure_is_structured(security_tools, monkeypatch):
    def boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(security_tools, "get_domain_info", boom)
    assert parse_response(security_tools.generate_security_report())["success"] is False


def test_generate_security_recommendations(security_tools):
    recs = security_tools._generate_security_recommendations(
        {"high_risk_admin_accounts": 2, "password_policy_compliant": False,
         "overall_security_score": 10}
    )
    assert len(recs) == 3
    assert security_tools._generate_security_recommendations({})[0].startswith("Security posture")


# ---------------------------------------------------------------------------
# schema + hygiene
# ---------------------------------------------------------------------------


def test_get_schema_info(security_tools):
    info = security_tools.get_schema_info()
    assert "audit_admin_accounts" in info["operations"]
    assert "lastLogon" in info["security_attributes"]


def test_security_module_has_no_private_filetime_converter():
    import inspect

    from active_directory_mcp.tools import security

    src = inspect.getsource(security)
    assert "def _convert_filetime_to_datetime" not in src
    assert "def _convert_datetime_to_filetime" not in src
    assert "datetime(1601" not in src
    assert "except:" not in src.replace("except Exception", "")


def test_get_user_permissions_logs_skipped_group(security_tools, mock_ldap_manager, caplog):
    user_dn = f"CN=Alice,CN=Users,{BASE}"
    bad_dn = f"CN=Broken,CN=Users,{BASE}"
    user = ldap_entry(
        user_dn, sAMAccountName="alice", memberOf=[bad_dn], userAccountControl=512
    )

    def search(search_base=None, **_kw):
        if search_base == bad_dn:
            raise RuntimeError("group lookup failed")
        return [user]

    mock_ldap_manager.search.side_effect = search
    with caplog.at_level("WARNING"):
        data = parse_response(security_tools.get_user_permissions("alice"))
    assert data["privileged_groups_count"] == 0
    assert any(bad_dn in r.getMessage() for r in caplog.records)


# ------------------------------------------- caps and accuracy notes (SEC-06)


def _user_entries(n):
    return [
        ldap_entry(f"CN=u{i},CN=Users,{BASE}", sAMAccountName=f"u{i}", userAccountControl=512,
                   lastLogon=0, pwdLastSet=0)
        for i in range(n)
    ]


def test_get_inactive_users_capped_with_accuracy_note(security_tools, mock_ldap_manager):
    mock_ldap_manager.security_config.max_list_results = 2
    mock_ldap_manager.search.return_value = _user_entries(3)
    data = parse_response(security_tools.get_inactive_users())
    assert data["truncated"] is True and data["result_limit"] == 2 and data["count"] == 2
    assert "lastLogonTimestamp" in data["accuracy_note"]
    # audit scans are never capped before filtering; only the returned findings are
    assert "size_limit" not in mock_ldap_manager.search.call_args.kwargs


def test_get_inactive_users_audits_beyond_cap_before_filtering(security_tools, mock_ldap_manager):
    from datetime import datetime, timezone

    mock_ldap_manager.security_config.max_list_results = 2
    recent = datetime.now(timezone.utc)
    active = [
        ldap_entry(f"CN=a{i},CN=Users,{BASE}", sAMAccountName=f"a{i}", userAccountControl=512,
                   lastLogon=recent, pwdLastSet=recent)
        for i in range(5)
    ]
    offender = ldap_entry(f"CN=old,CN=Users,{BASE}", sAMAccountName="old",
                          userAccountControl=512, lastLogon=0, pwdLastSet=0)
    mock_ldap_manager.search.return_value = active + [offender]
    data = parse_response(security_tools.get_inactive_users())
    assert data["count"] == 1 and data["truncated"] is False
    assert data["inactive_users"][0]["sam_account_name"] == "old"


def test_password_policy_violations_audits_beyond_cap_before_filtering(
    security_tools, mock_ldap_manager
):
    from datetime import datetime, timezone

    mock_ldap_manager.security_config.max_list_results = 2
    now = datetime.now(timezone.utc)
    healthy = [
        ldap_entry(f"CN=h{i},CN=Users,{BASE}", sAMAccountName=f"h{i}", userAccountControl=512,
                   pwdLastSet=now, accountExpires=0)
        for i in range(4)
    ]
    bad = ldap_entry(f"CN=bad,CN=Users,{BASE}", sAMAccountName="bad",
                     userAccountControl=512, pwdLastSet=0, accountExpires=0)
    domain = ldap_entry(BASE, maxPwdAge=0, minPwdAge=0)
    mock_ldap_manager.search.side_effect = [[domain], healthy + [bad]]
    data = parse_response(security_tools.get_password_policy_violations())
    assert data["count"] == 1 and data["truncated"] is False
    assert data["password_violations"][0]["sam_account_name"] == "bad"


def test_get_inactive_users_cap_opt_out(security_tools, mock_ldap_manager):
    mock_ldap_manager.security_config.max_list_results = 0
    mock_ldap_manager.search.return_value = _user_entries(3)
    data = parse_response(security_tools.get_inactive_users())
    assert data["count"] == 3 and data["truncated"] is False
    assert "size_limit" not in mock_ldap_manager.search.call_args.kwargs


def test_password_policy_violations_capped(security_tools, mock_ldap_manager):
    mock_ldap_manager.security_config.max_list_results = 2
    domain = ldap_entry(BASE, maxPwdAge=0, minPwdAge=0)
    mock_ldap_manager.search.side_effect = [[domain], _user_entries(3)]
    data = parse_response(security_tools.get_password_policy_violations())
    assert data["truncated"] is True and data["result_limit"] == 2 and data["count"] == 2


def test_audit_admin_accounts_has_lastlogon_note(security_tools, mock_ldap_manager):
    data = parse_response(security_tools.audit_admin_accounts())
    assert "lastLogon" in data["accuracy_note"]
