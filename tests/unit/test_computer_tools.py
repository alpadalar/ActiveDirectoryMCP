"""Unit tests for ComputerTools (mocked LDAP; no server needed)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.support.helpers import ldap_entry, parse_response

WS_DN = "CN=WS01,CN=Computers,DC=test,DC=local"
NEVER = 9223372036854775807


def _filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch) // timedelta(microseconds=1)) * 10


def _ago(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


# ---------------------------------------------------------------- time helpers


@pytest.mark.parametrize(
    "make",
    [
        lambda: _ago(10),
        lambda: _filetime(_ago(10)),
        lambda: str(_filetime(_ago(10))),
    ],
    ids=["aware-datetime", "int-filetime", "numeric-string"],
)
def test_days_since_last_logon_accepts_real_value_types(computer_tools, make):
    assert computer_tools._get_days_since_last_logon({"lastLogon": [make()]}) in (9, 10)


@pytest.mark.parametrize(
    "value",
    [0, None, NEVER, datetime(1601, 1, 1, tzinfo=timezone.utc)],
    ids=["zero", "none", "never-sentinel", "year-1601"],
)
def test_days_since_last_logon_unset_is_none(computer_tools, value):
    assert computer_tools._get_days_since_last_logon({"lastLogon": [value]}) is None


def test_days_since_last_logon_missing_attribute_is_none(computer_tools):
    assert computer_tools._get_days_since_last_logon({}) is None


@pytest.mark.parametrize(
    "make",
    [lambda: _ago(40), lambda: _filetime(_ago(40)), lambda: str(_filetime(_ago(40)))],
    ids=["aware-datetime", "int-filetime", "numeric-string"],
)
def test_password_age_days_accepts_real_value_types(computer_tools, make):
    assert computer_tools._get_password_age_days({"pwdLastSet": [make()]}) in (39, 40)


@pytest.mark.parametrize(
    "value",
    [0, None, NEVER, datetime(1601, 1, 1, tzinfo=timezone.utc)],
    ids=["zero", "none", "never-sentinel", "year-1601"],
)
def test_password_age_days_unset_is_none(computer_tools, value):
    assert computer_tools._get_password_age_days({"pwdLastSet": [value]}) is None


def test_computer_has_no_private_filetime_converters():
    from active_directory_mcp.tools.base import BaseTool
    from active_directory_mcp.tools.computer import ComputerTools

    assert "_convert_filetime_to_datetime" not in ComputerTools.__dict__
    assert "_convert_datetime_to_filetime" not in ComputerTools.__dict__
    assert ComputerTools._convert_filetime_to_datetime is BaseTool._convert_filetime_to_datetime


# --------------------------------------------------------------- list_computers


def test_list_computers_success(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry(
            WS_DN,
            sAMAccountName="WS01$",
            dNSHostName="ws01.test.local",
            operatingSystem="Windows 10",
            userAccountControl=4096,
            lastLogon=_ago(1),
        ),
        ldap_entry(
            "CN=OFF,DC=test,DC=local",
            sAMAccountName="OFF$",
            userAccountControl=4098,
            lastLogon=0,
        ),
    ]
    data = parse_response(computer_tools.list_computers())
    assert data["count"] == 2
    assert data["computers"][0]["sAMAccountName"] == "WS01$"
    assert data["computers"][0]["enabled"] is True
    assert data["computers"][1]["enabled"] is False
    kwargs = mock_ldap_manager.search.call_args.kwargs
    assert kwargs["search_filter"] == "(objectClass=computer)"
    assert kwargs["search_base"] == "DC=test,DC=local"


def test_list_computers_with_ou_and_filter(computer_tools, mock_ldap_manager):
    computer_tools.list_computers(ou="OU=X,DC=test,DC=local", filter_criteria="(name=a*)")
    kwargs = mock_ldap_manager.search.call_args.kwargs
    assert kwargs["search_base"] == "OU=X,DC=test,DC=local"
    assert kwargs["search_filter"] == "(&(objectClass=computer)(name=a*))"


def test_list_computers_failure(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("ldap down")
    data = parse_response(computer_tools.list_computers())
    assert data["success"] is False
    assert "ldap down" in data["error"]


# ---------------------------------------------------------------- get_computer


def test_get_computer_populates_computed_from_datetimes(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry(
            WS_DN,
            sAMAccountName="WS01$",
            userAccountControl=4096,
            lastLogon=_ago(5),
            pwdLastSet=_ago(20),
        )
    ]
    data = parse_response(computer_tools.get_computer("WS01"))
    assert data["dn"] == WS_DN
    computed = data["computed"]
    assert computed["enabled"] is True
    assert computed["computer_type"] == "workstation"
    assert computed["days_since_last_logon"] in (4, 5)
    assert computed["password_age_days"] in (19, 20)
    assert "sAMAccountName=WS01$" in mock_ldap_manager.search.call_args.kwargs["search_filter"]


def test_get_computer_never_logged_on_is_not_active_now(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry(WS_DN, userAccountControl=4096, lastLogon=0, pwdLastSet=NEVER)
    ]
    computed = parse_response(computer_tools.get_computer("WS01$"))["computed"]
    assert computed["days_since_last_logon"] is None
    assert computed["password_age_days"] is None


def test_get_computer_unset_logon_datetime_1601(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry(WS_DN, lastLogon=datetime(1601, 1, 1, tzinfo=timezone.utc))
    ]
    computed = parse_response(computer_tools.get_computer("WS01"))["computed"]
    assert computed["days_since_last_logon"] is None


def test_get_computer_not_found(computer_tools, mock_ldap_manager):
    data = parse_response(computer_tools.get_computer("ghost"))
    assert data["success"] is False
    assert "not found" in data["error"]


def test_get_computer_failure(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("boom")
    data = parse_response(computer_tools.get_computer("WS01"))
    assert data["success"] is False


# -------------------------------------------------------------- create_computer


def test_create_computer_success_adds_dollar_and_enables(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = []
    data = parse_response(
        computer_tools.create_computer("NEWPC", description="d", dns_hostname="newpc.test.local")
    )
    assert data["success"] is True
    assert data["sam_account_name"] == "NEWPC$"
    assert data["dn"] == "CN=NEWPC,CN=Computers,DC=test,DC=local"
    dn, attrs = mock_ldap_manager.add.call_args.args
    assert dn == data["dn"]
    assert attrs["sAMAccountName"] == "NEWPC$"
    assert attrs["cn"] == "NEWPC"
    assert attrs["userAccountControl"] == 4128
    assert attrs["description"] == "d"
    assert attrs["servicePrincipalName"] == ["HOST/NEWPC", "HOST/newpc.test.local"]
    # enable step flips UAC to 4096
    assert mock_ldap_manager.modify.call_args.args[1]["userAccountControl"][0][1] == [4096]


def test_create_computer_trailing_dollar_not_duplicated(computer_tools, mock_ldap_manager):
    data = parse_response(computer_tools.create_computer("PC2$", ou="OU=Lab,DC=test,DC=local"))
    assert data["sam_account_name"] == "PC2$"
    assert data["dn"] == "CN=PC2,OU=Lab,DC=test,DC=local"
    assert data["dns_hostname"] == "PC2.test.local"


def test_create_computer_already_exists(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    data = parse_response(computer_tools.create_computer("WS01"))
    assert data["success"] is False
    assert "already exists" in data["error"]
    mock_ldap_manager.add.assert_not_called()


def test_create_computer_add_returns_false(computer_tools, mock_ldap_manager):
    mock_ldap_manager.add.return_value = False
    data = parse_response(computer_tools.create_computer("PC3"))
    assert data["success"] is False


def test_create_computer_enable_failure_still_succeeds(computer_tools, mock_ldap_manager):
    mock_ldap_manager.modify.side_effect = Exception("no right")
    assert parse_response(computer_tools.create_computer("PC4"))["success"] is True


def test_create_computer_ldap_exception(computer_tools, mock_ldap_manager):
    mock_ldap_manager.add.side_effect = Exception("denied")
    data = parse_response(computer_tools.create_computer("PC5"))
    assert data["success"] is False
    assert "denied" in data["error"]


# -------------------------------------------- modify / delete / enable / disable


def test_modify_computer_success(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    data = parse_response(computer_tools.modify_computer("WS01", {"description": "x", "l": ["a"]}))
    assert data["success"] is True
    assert data["modified_attributes"] == ["description", "l"]
    dn, mods = mock_ldap_manager.modify.call_args.args
    assert dn == WS_DN
    assert mods["description"][0][1] == ["x"]
    assert mods["l"][0][1] == ["a"]


def test_modify_computer_not_found(computer_tools, mock_ldap_manager):
    data = parse_response(computer_tools.modify_computer("ghost", {"description": "x"}))
    assert data["success"] is False
    mock_ldap_manager.modify.assert_not_called()


def test_modify_computer_failure(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    mock_ldap_manager.modify.side_effect = Exception("nope")
    assert parse_response(computer_tools.modify_computer("WS01", {"a": 1}))["success"] is False


def test_delete_computer_success(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    data = parse_response(computer_tools.delete_computer("WS01"))
    assert data["success"] is True
    mock_ldap_manager.delete.assert_called_once_with(WS_DN)


def test_delete_computer_not_found(computer_tools, mock_ldap_manager):
    assert parse_response(computer_tools.delete_computer("ghost"))["success"] is False
    mock_ldap_manager.delete.assert_not_called()


def test_delete_computer_failure(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    mock_ldap_manager.delete.side_effect = Exception("busy")
    assert parse_response(computer_tools.delete_computer("WS01"))["success"] is False


@pytest.mark.parametrize("method,uac", [("enable_computer", 4096), ("disable_computer", 4098)])
def test_enable_disable_computer_success(computer_tools, mock_ldap_manager, method, uac):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    data = parse_response(getattr(computer_tools, method)("WS01"))
    assert data["success"] is True
    assert data["userAccountControl"] == uac
    assert mock_ldap_manager.modify.call_args.args[1]["userAccountControl"][0][1] == [uac]


@pytest.mark.parametrize("method", ["enable_computer", "disable_computer"])
def test_enable_disable_computer_not_found_and_failure(computer_tools, mock_ldap_manager, method):
    assert parse_response(getattr(computer_tools, method)("ghost"))["success"] is False
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    mock_ldap_manager.modify.side_effect = Exception("x")
    assert parse_response(getattr(computer_tools, method)("WS01"))["success"] is False


# ------------------------------------------------------ reset_computer_password


def test_reset_computer_password_success(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    data = parse_response(computer_tools.reset_computer_password("WS01"))
    assert data["success"] is True
    assert len(data["new_password"]) == 120
    assert mock_ldap_manager.modify.call_args.args[1]["pwdLastSet"][0][1] == [0]


def test_reset_computer_password_not_found_and_failure(computer_tools, mock_ldap_manager):
    assert parse_response(computer_tools.reset_computer_password("ghost"))["success"] is False
    mock_ldap_manager.search.return_value = [ldap_entry(WS_DN)]
    mock_ldap_manager.modify.side_effect = Exception("x")
    assert parse_response(computer_tools.reset_computer_password("WS01"))["success"] is False


# --------------------------------------------------------- get_stale_computers


def test_get_stale_computers_datetime_logon(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry("CN=OLD,DC=test,DC=local", sAMAccountName="OLD$", lastLogon=_ago(200)),
        ldap_entry("CN=NEW,DC=test,DC=local", sAMAccountName="NEW$", lastLogon=_ago(2)),
    ]
    data = parse_response(computer_tools.get_stale_computers(days=90))
    assert data["count"] == 1
    stale = data["stale_computers"][0]
    assert stale["sAMAccountName"] == "OLD$"
    assert stale["daysSinceLastLogon"] in (199, 200)


def test_get_stale_computers_filetime_and_never(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.return_value = [
        ldap_entry("CN=A,DC=test,DC=local", sAMAccountName="A$", lastLogon=_filetime(_ago(150))),
        ldap_entry("CN=B,DC=test,DC=local", sAMAccountName="B$", lastLogon=0),
        ldap_entry("CN=C,DC=test,DC=local", sAMAccountName="C$", lastLogon=NEVER),
        ldap_entry("CN=D,DC=test,DC=local", sAMAccountName="D$"),
    ]
    data = parse_response(computer_tools.get_stale_computers(days=90))
    by_name = {c["sAMAccountName"]: c for c in data["stale_computers"]}
    assert set(by_name) == {"A$", "B$", "C$", "D$"}
    for name in ("B$", "C$", "D$"):
        assert by_name[name]["lastLogon"] == "Never"
        assert by_name[name]["daysSinceLastLogon"] is None
    assert by_name["A$"]["daysSinceLastLogon"] in (149, 150)


def test_get_stale_computers_failure(computer_tools, mock_ldap_manager):
    mock_ldap_manager.search.side_effect = Exception("down")
    assert parse_response(computer_tools.get_stale_computers())["success"] is False


# -------------------------------------------------------------- pure helpers


@pytest.mark.parametrize(
    "uac,enabled",
    [(4096, True), (4098, False), ("4096", True), (None, None), ("junk", None)],
)
def test_is_computer_enabled(computer_tools, uac, enabled):
    assert computer_tools._is_computer_enabled(uac) is enabled


@pytest.mark.parametrize(
    "uac,kind",
    [(4096, "workstation"), (8192, "domain_controller"), (532480, "server"), (0, "unknown")],
)
def test_computer_type(computer_tools, uac, kind):
    assert computer_tools._get_computer_type(uac) == kind


def test_trusted_for_delegation(computer_tools):
    assert computer_tools._is_trusted_for_delegation(0x80000 | 4096) is True
    assert computer_tools._is_trusted_for_delegation(4096) is False


def test_schema_info_lists_operations(computer_tools):
    assert "create_computer" in computer_tools.get_schema_info()["operations"]


def test_response_is_valid_json_text(computer_tools):
    result = computer_tools.get_computer("x")
    json.loads(result[0].text)


# ------------------------------------------------- config/validator hardening


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ou": "OU=X,DC=evil,DC=com"},
        {"ou": "not-a-dn"},
        {"filter_criteria": "(name=a*"},
        {"filter_criteria": ")(objectClass=*"},
    ],
    ids=["out-of-base", "malformed-dn", "unbalanced", "breakout"],
)
def test_list_computers_rejects_hostile_input_without_search(
    computer_tools, mock_ldap_manager, kwargs
):
    data = parse_response(computer_tools.list_computers(**kwargs))
    assert data["success"] is False
    mock_ldap_manager.search.assert_not_called()


@pytest.mark.parametrize(
    "call",
    [
        lambda t: t.list_computers(),
        lambda t: t.get_computer("PC"),
        lambda t: t.modify_computer("PC", {"description": "x"}),
        lambda t: t.delete_computer("PC"),
        lambda t: t.enable_computer("PC"),
        lambda t: t.disable_computer("PC"),
        lambda t: t.reset_computer_password("PC"),
        lambda t: t.get_stale_computers(),
    ],
    ids=["list", "get", "modify", "delete", "enable", "disable", "reset", "stale"],
)
def test_filters_use_configured_computer_object_class(
    computer_tools, mock_ldap_manager, ad_settings, call
):
    ad_settings.computer_object_class = "device"
    call(computer_tools)
    flt = mock_ldap_manager.search.call_args.kwargs["search_filter"]
    assert "objectClass=device" in flt
    assert "objectClass=computer" not in flt


def test_create_computer_escapes_rdn(computer_tools, mock_ldap_manager):
    data = parse_response(computer_tools.create_computer("pc,OU=Admins"))
    assert data["success"] is True
    dn = mock_ldap_manager.add.call_args.args[0]
    assert dn.startswith("CN=pc\\,OU=Admins,")
    assert dn.endswith("CN=Computers,DC=test,DC=local")


def test_create_computer_rejects_out_of_base_ou(computer_tools, mock_ldap_manager):
    data = parse_response(computer_tools.create_computer("PC", ou="OU=X,DC=evil,DC=com"))
    assert data["success"] is False
    mock_ldap_manager.search.assert_not_called()
    mock_ldap_manager.add.assert_not_called()
