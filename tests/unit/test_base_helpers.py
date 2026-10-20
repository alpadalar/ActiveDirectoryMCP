"""Tests for the shared AD time helpers on BaseTool (bug B-01a)."""

from datetime import datetime, timedelta, timezone

import pytest

from active_directory_mcp.config.models import SecurityConfig
from active_directory_mcp.tools.base import BaseTool
from tests.support.helpers import parse_response

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
NEVER = 9223372036854775807
SAMPLE = 133500000000000000


class _Tool(BaseTool):
    def get_schema_info(self):
        return {}


@pytest.fixture
def tool(mock_ldap_manager):
    return _Tool(mock_ldap_manager)


def _expected(ticks: int) -> datetime:
    return EPOCH_1601 + timedelta(microseconds=ticks // 10)


def test_ad_datetime_aware_keeps_instant(tool):
    plus3 = timezone(timedelta(hours=3))
    value = datetime(2024, 5, 1, 12, 0, tzinfo=plus3)
    result = tool._ad_datetime(value)
    assert result.tzinfo is not None
    assert result == value
    assert result.utcoffset() == timedelta(0)


def test_ad_datetime_naive_assumed_utc(tool):
    result = tool._ad_datetime(datetime(2024, 5, 1, 12, 0))
    assert result == datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [SAMPLE, str(SAMPLE), float(SAMPLE)])
def test_ad_datetime_filetime_forms(tool, value):
    result = tool._ad_datetime(value)
    assert result == _expected(SAMPLE)
    assert result.tzinfo is not None


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        0,
        "0",
        NEVER,
        str(NEVER),
        -5,
        True,
        False,
        "abc",
        b"123",
        datetime(1601, 1, 1, tzinfo=timezone.utc),
        datetime(1601, 1, 1),
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        10**30,
    ],
)
def test_ad_datetime_unset_or_invalid_returns_none(tool, value):
    assert tool._ad_datetime(value) is None


def test_convert_filetime_to_datetime_never_returns_now(tool):
    assert tool._convert_filetime_to_datetime(0) is None
    assert tool._convert_filetime_to_datetime(None) is None
    assert tool._convert_filetime_to_datetime(SAMPLE) == _expected(SAMPLE)


def test_convert_datetime_to_filetime_round_trip(tool):
    n = SAMPLE + 1234560  # sub-second ticks (microsecond resolution)
    assert tool._convert_datetime_to_filetime(tool._ad_datetime(n)) == n


def test_convert_datetime_to_filetime_exact(tool):
    dt = EPOCH_1601 + timedelta(days=1, microseconds=7)
    assert tool._convert_datetime_to_filetime(dt) == 864000000000 + 70


def test_convert_datetime_to_filetime_naive_and_aware(tool):
    naive = datetime(2024, 5, 1, 12, 0)
    aware_utc = naive.replace(tzinfo=timezone.utc)
    plus3 = aware_utc.astimezone(timezone(timedelta(hours=3)))
    expected = tool._convert_datetime_to_filetime(aware_utc)
    assert tool._convert_datetime_to_filetime(naive) == expected
    assert tool._convert_datetime_to_filetime(plus3) == expected
    assert isinstance(expected, int)


NOW = datetime(2024, 6, 10, 12, 0, tzinfo=timezone.utc)


def test_days_since_whole_days(tool):
    assert tool._days_since(datetime(2024, 6, 1, 6, 0, tzinfo=timezone.utc), now=NOW) == 9
    assert tool._days_since(datetime(2024, 6, 1, 12, 0), now=NOW) == 9


def test_days_since_filetime_int(tool):
    value = tool._convert_datetime_to_filetime(NOW - timedelta(days=3, hours=5))
    assert tool._days_since(value, now=NOW) == 3


def test_days_since_unset_none(tool):
    for v in (None, 0, NEVER, "0"):
        assert tool._days_since(v, now=NOW) is None


def test_days_since_future_clamped(tool):
    assert tool._days_since(NOW + timedelta(days=5), now=NOW) == 0


def test_days_since_default_now(tool):
    assert tool._days_since(datetime.now(timezone.utc) - timedelta(days=2, hours=1)) == 2


def test_is_past(tool):
    assert tool._is_past(NOW - timedelta(seconds=1), now=NOW) is True
    assert tool._is_past(NOW + timedelta(seconds=1), now=NOW) is False
    assert tool._is_past(NOW, now=NOW) is False
    assert tool._is_past(datetime(2020, 1, 1), now=NOW) is True


@pytest.mark.parametrize(
    "value", [None, 0, "0", NEVER, datetime(9999, 12, 31), datetime(1601, 1, 1), "x"]
)
def test_is_past_unset_false(tool, value):
    assert tool._is_past(value, now=NOW) is False


# --- delegation to the central validation module (CONF-02) -------------------

import json
from pathlib import Path

from active_directory_mcp import validation


def test_escape_ldap_filter_delegates(tool):
    raw = "a*(b)\\c\x00"
    assert tool._escape_ldap_filter(raw) == validation.escape_filter_value(raw)
    assert tool._escape_ldap_filter("a\\b*") == "a\\5cb\\2a"
    # ldap3 leaves non-ASCII intact (the old chain did too); noted for parity.
    assert tool._escape_ldap_filter("é") == "é"


def test_validate_dn_confined_to_base(tool):
    assert tool._validate_dn("CN=a,OU=b,DC=test,DC=local") is True
    assert tool._validate_dn("DC=test,DC=local") is True
    assert tool._validate_dn("CN=a,DC=evil,DC=com") is False
    assert tool._validate_dn("DC=local") is False
    assert tool._validate_dn("") is False
    assert tool._validate_dn(None) is False


def test_confined_dn(tool):
    assert tool._confined_dn("CN=a,DC=test,DC=local") == "CN=a,DC=test,DC=local"
    with pytest.raises(validation.ValidationError):
        tool._confined_dn("CN=a,DC=evil,DC=com")


def test_build_dn_escapes_rdn(tool):
    dn = tool._build_dn("x,OU=Admins", "OU=Staff,DC=test,DC=local")
    assert dn == "CN=x\\,OU\\=Admins,OU=Staff,DC=test,DC=local"


def test_build_dn_rejects_outside_parent(tool):
    with pytest.raises(validation.ValidationError):
        tool._build_dn("x", "OU=Staff,DC=evil,DC=com")


def test_validation_error_response_shape(tool):
    exc = validation.ValidationError("DN is outside the configured base DN")
    out = tool._validation_error_response(exc, "get_user", "CN=a,DC=evil")
    data = json.loads(out[0].text)
    assert data["success"] is False
    assert data["error"] == "DN is outside the configured base DN"
    assert data["operation"] == "get_user"
    assert data["type"] == "ValidationError"
    assert data["dn"] == "CN=a,DC=evil"


def test_base_has_no_handrolled_escape_chain():
    src = Path(validation.__file__).parent.joinpath("tools", "base.py").read_text()
    assert "\\2a" not in src
    assert "escape_chars" not in src


# ---------------------------------------------------------------------------
# Security enforcement helpers (SEC-03 / SEC-05 / SEC-06)
# ---------------------------------------------------------------------------


def _payload(result):
    return json.loads(result[0].text)


def test_require_secure_channel_secure(tool):
    assert tool._require_secure_channel("reset_user_password") is None


def test_require_secure_channel_insecure(tool, mock_ldap_manager):
    mock_ldap_manager.is_secure_channel.return_value = False
    data = _payload(tool._require_secure_channel("reset_user_password"))
    assert data["success"] is False
    assert data["error_code"] == "unicodePwd_requires_tls"
    assert data["operation"] == "reset_user_password"


def test_require_secure_channel_exception_fails_closed(tool, mock_ldap_manager):
    mock_ldap_manager.is_secure_channel.side_effect = RuntimeError("boom pw=Hunter2")
    data = _payload(tool._require_secure_channel("reset_user_password"))
    assert data["error_code"] == "unicodePwd_requires_tls"
    assert "Hunter2" not in json.dumps(data)


def test_require_secure_channel_never_echoes_password(tool, mock_ldap_manager):
    mock_ldap_manager.is_secure_channel.return_value = False
    out = tool._require_secure_channel("reset_user_password")
    assert "dummy-password" not in out[0].text


def test_check_modify_attributes_accepts(tool):
    assert tool._check_modify_attributes("user", {"mail": "a@b"}, "modify_user", "CN=x") is None


def test_check_modify_attributes_rejects_shape(tool):
    data = _payload(
        tool._check_modify_attributes(
            "user", {"userAccountControl": "SECRETVAL", "mail": "a"}, "modify_user", "CN=x"
        )
    )
    assert data["success"] is False
    assert data["error_code"] == "attribute_not_allowed"
    assert data["object_type"] == "user"
    assert data["rejected_attributes"] == ["userAccountControl"]
    assert "mail" in data["allowed_attributes"]
    assert data["target"] == "CN=x"
    assert "SECRETVAL" not in json.dumps(data)


def _entries(n):
    return [{"dn": f"CN=e{i}", "attributes": {}} for i in range(n)]


def _set_limit(mock_ldap_manager, limit):
    mock_ldap_manager.security_config = SecurityConfig(max_list_results=limit)


@pytest.mark.parametrize(
    "available,expected_len,truncated",
    [(2, 2, False), (3, 3, False), (4, 3, True), (50, 3, True)],
)
def test_capped_search_boundaries(tool, mock_ldap_manager, available, expected_len, truncated):
    _set_limit(mock_ldap_manager, 3)
    # the server honours size_limit=limit+1
    mock_ldap_manager.search.side_effect = lambda **kw: _entries(available)[: kw["size_limit"]]
    entries, was_truncated, limit = tool._capped_search(search_base="DC=x", search_filter="(a=b)")
    assert (len(entries), was_truncated, limit) == (expected_len, truncated, 3)
    assert mock_ldap_manager.search.call_args.kwargs["size_limit"] == 4


def test_capped_search_unlimited(tool, mock_ldap_manager):
    _set_limit(mock_ldap_manager, 0)
    mock_ldap_manager.search.return_value = _entries(5000)
    entries, truncated, limit = tool._capped_search(search_base="DC=x", search_filter="(a=b)")
    assert (len(entries), truncated, limit) == (5000, False, 0)
    assert "size_limit" not in mock_ldap_manager.search.call_args.kwargs


def test_cap_metadata(tool):
    assert tool._cap_metadata(True, 10) == {"truncated": True, "result_limit": 10}
    assert tool._cap_metadata(False, 0) == {"truncated": False, "result_limit": None}


@pytest.mark.parametrize("bad", ['{"description": "x"}', ["description"], 5])
def test_check_modify_attributes_rejects_non_mapping_clearly(mock_ldap_manager, bad):
    from active_directory_mcp.tools.group import GroupTools

    tools = GroupTools(mock_ldap_manager)
    data = parse_response(tools._check_modify_attributes("group", bad, "modify_group", "g"))
    assert data["success"] is False and data["error_code"] == "invalid_attributes"
    assert "must be an object" in data["error"]
    assert "Attribute(s) not permitted" not in data["error"]
