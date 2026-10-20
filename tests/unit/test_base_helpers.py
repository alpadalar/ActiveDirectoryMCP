"""Tests for the shared AD time helpers on BaseTool (bug B-01a)."""

from datetime import datetime, timedelta, timezone

import pytest

from active_directory_mcp.tools.base import BaseTool

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
        None, "", 0, "0", NEVER, str(NEVER), -5, True, False, "abc", b"123",
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


@pytest.mark.parametrize("value", [None, 0, "0", NEVER, datetime(9999, 12, 31), datetime(1601, 1, 1), "x"])
def test_is_past_unset_false(tool, value):
    assert tool._is_past(value, now=NOW) is False
