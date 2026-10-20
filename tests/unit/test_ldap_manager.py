"""Unit tests for LDAPManager on the patched ldap3 seam (no network).

Fidelity limit: a MagicMock ``connection.result`` does not emulate real paged-search control
encoding, so these tests assert only the application's own cookie handling.
"""

from unittest.mock import MagicMock, patch

import pytest
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError

from active_directory_mcp.config.models import PerformanceConfig, SecurityConfig
from active_directory_mcp.core import ldap_manager as lm
from active_directory_mcp.core.ldap_manager import LDAPManager, _CIDict

PAGED = "1.2.840.113556.1.4.319"


@pytest.fixture
def perf():
    return PerformanceConfig(max_retries=3, retry_delay=0.01, page_size=2)


@pytest.fixture
def make_manager(ad_settings, perf, ldap3_seam):
    server_cls, _ = ldap3_seam
    server_cls.side_effect = lambda url, **kw: MagicMock(host=url, port=636, url=url, kw=kw)

    def _make(security=None, ad=None):
        return LDAPManager(ad or ad_settings, security or SecurityConfig(enable_tls=False), perf)

    return _make


@pytest.fixture
def manager(make_manager):
    return make_manager()


def _entry(dn, **attrs):
    e = MagicMock()
    e.entry_dn = dn
    e.entry_attributes_as_dict = attrs
    return e


def _page(conn, entries, cookie=None):
    conn.entries = entries
    conn.result = {"controls": {PAGED: {"value": {"cookie": cookie}}}} if cookie else {"result": 0}


class TestServerPool:
    def test_primary_only(self, manager, ldap3_seam):
        assert len(manager._server_pool) == 1
        assert manager._server_pool[0].url == "ldaps://dc.test.local"

    def test_pool_extras(self, make_manager, ad_settings):
        ad = ad_settings.model_copy(update={"server_pool": ["ldaps://dc2", "ldaps://dc3"]})
        m = make_manager(ad=ad)
        assert [s.url for s in m._server_pool] == ["ldaps://dc.test.local", "ldaps://dc2", "ldaps://dc3"]

    def test_no_tls_object_when_disabled(self, manager):
        assert manager._server_pool[0].kw["tls"] is None

    def test_tls_configured_when_enabled(self, make_manager):
        with patch.object(lm.ldap3, "Tls") as tls:
            m = make_manager(SecurityConfig(enable_tls=True, validate_certificate=False))
        tls.assert_called_once()
        assert m._server_pool[0].kw["tls"] is tls.return_value


class TestConnect:
    def test_success_and_reuse(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        first = manager.connect()
        assert first is conn_cls.return_value
        first.bound = True
        assert manager.connect() is first
        assert conn_cls.call_count == 1

    def test_password_unwrapped_only_at_connection(self, manager, ldap3_seam, ad_settings):
        _, conn_cls = ldap3_seam
        manager.connect()
        assert conn_cls.call_args.kwargs["password"] == "dummy-password"
        assert "dummy-password" not in repr(manager.ad_config)

    def test_failover_to_second_server(self, make_manager, ldap3_seam, ad_settings):
        _, conn_cls = ldap3_seam
        good = MagicMock()
        conn_cls.side_effect = [LDAPSocketOpenError("dc1 down"), good]
        ad = ad_settings.model_copy(update={"server_pool": ["ldaps://dc2"]})
        m = make_manager(ad=ad)
        assert m.connect() is good
        hosts = [c.args[0].url for c in conn_cls.call_args_list]
        assert hosts == ["ldaps://dc.test.local", "ldaps://dc2"]

    def test_fails_after_max_retries(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.side_effect = LDAPBindError("bad creds")
        with patch.object(lm.time, "sleep") as sleep:
            with pytest.raises(LDAPException, match="after 3 attempts"):
                manager.connect()
        assert conn_cls.call_count == 3
        assert sleep.call_count == 2  # no sleep after the final attempt

    def test_unexpected_error_is_retried_then_wrapped(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.side_effect = RuntimeError("weird")
        with patch.object(lm.time, "sleep"):
            with pytest.raises(LDAPException, match="weird"):
                manager.connect()
        assert conn_cls.call_count == 3

    def test_unbound_result_counts_as_failure(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.return_value.bind.return_value = False
        with patch.object(lm.time, "sleep"):
            with pytest.raises(LDAPException):
                manager.connect()


class TestSearch:
    def test_single_page(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        _page(conn, [_entry("CN=a", sAMAccountName="a", mail=["x@y", "z@y"])])
        result = manager.search("DC=test,DC=local", "(cn=a)", attributes=["sAMAccountName"])
        assert result == [
            {"dn": "CN=a", "attributes": {"sAMAccountName": ["a"], "mail": ["x@y", "z@y"]}}
        ]
        assert conn.search.call_count == 1

    def test_multi_page_follows_cookie(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        pages = iter(
            [
                ([_entry("CN=1"), _entry("CN=2")], b"c1"),
                ([_entry("CN=3")], None),
            ]
        )

        def side_effect(**kwargs):
            entries, cookie = next(pages)
            _page(conn, entries, cookie)
            return True

        conn.search.side_effect = side_effect
        result = manager.search("DC=test,DC=local", "(cn=*)")
        assert [e["dn"] for e in result] == ["CN=1", "CN=2", "CN=3"]
        cookies = [c.kwargs["paged_cookie"] for c in conn.search.call_args_list]
        assert cookies == [None, b"c1"]
        assert conn.search.call_args.kwargs["paged_size"] == 2

    def test_size_limit_returns_early(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        _page(conn, [_entry("CN=1"), _entry("CN=2")], b"more")
        result = manager.search("DC=test,DC=local", "(cn=*)", size_limit=1)
        assert [e["dn"] for e in result] == ["CN=1"]
        assert conn.search.call_count == 1
        assert conn.search.call_args.kwargs["paged_size"] == 1

    def test_time_limit_is_forwarded_only_when_set(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        _page(conn, [_entry("CN=1")], None)
        manager.search("DC=test,DC=local", "(cn=*)")
        assert "time_limit" not in conn.search.call_args.kwargs
        manager.search("DC=test,DC=local", "(cn=*)", time_limit=7)
        assert conn.search.call_args.kwargs["time_limit"] == 7

    def test_failed_search_raises(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = False
        conn.result = {"result": 32, "description": "noSuchObject"}
        with pytest.raises(LDAPException, match="Search failed"):
            manager.search("DC=x", "(cn=*)")

    def test_skip_schema_empty_result_is_not_an_error(self, manager, ldap3_seam, monkeypatch):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = False
        conn.result = {"result": 0}
        monkeypatch.setattr(lm, "SKIP_SCHEMA", True)
        assert manager.search("DC=x", "(cn=*)") == []

    def test_skip_schema_nonzero_result_still_raises(self, manager, ldap3_seam, monkeypatch):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = False
        conn.result = {"result": 50}
        monkeypatch.setattr(lm, "SKIP_SCHEMA", True)
        with pytest.raises(LDAPException):
            manager.search("DC=x", "(cn=*)")

    def test_skip_schema_attributes_are_case_insensitive(self, manager, ldap3_seam, monkeypatch):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        _page(conn, [_entry("CN=a", samaccountname="a")])
        monkeypatch.setattr(lm, "SKIP_SCHEMA", True)
        attrs = manager.search("DC=x", "(cn=*)")[0]["attributes"]
        assert isinstance(attrs, _CIDict)
        assert attrs["sAMAccountName"] == ["a"]

    def test_bytes_values_are_base64(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.search.return_value = True
        _page(conn, [_entry("CN=a", objectGUID=b"\x01\x02")])
        assert manager.search("DC=x", "(cn=*)")[0]["attributes"]["objectGUID"] == ["AQI="]

    def test_connection_exception_propagates(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.return_value.search.side_effect = LDAPSocketOpenError("reset")
        with pytest.raises(LDAPSocketOpenError):
            manager.search("DC=x", "(cn=*)")


class TestHelpers:
    def test_coerce_attribute_value(self):
        assert LDAPManager._coerce_attribute_value(b"\xff") == "/w=="
        assert LDAPManager._coerce_attribute_value("s") == "s"
        assert LDAPManager._coerce_attribute_value(5) == 5

    def test_normalize_attributes(self, manager):
        out = manager._normalize_attributes({"a": None, "b": "x", "c": ("y", b"z"), "d": {"q"}})
        assert out == {"a": [], "b": ["x"], "c": ["y", "eg=="], "d": ["q"]}

    def test_cidict(self):
        d = _CIDict({"sAMAccountName": [1]})
        assert d["samaccountname"] == [1]
        assert "SAMACCOUNTNAME" in d
        assert d.get("missing", "dflt") == "dflt"
        assert d.get("SamAccountName") == [1]
        assert 5 not in d


class TestWriteOperations:
    @pytest.mark.parametrize(
        "method,args,conn_method",
        [
            ("add", ("CN=a", {"cn": "a"}), "add"),
            ("modify", ("CN=a", {"cn": []}), "modify"),
            ("delete", ("CN=a",), "delete"),
            ("move", ("CN=a", "OU=b"), "modify_dn"),
        ],
    )
    def test_success_and_failure(self, manager, ldap3_seam, method, args, conn_method):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        getattr(conn, conn_method).return_value = True
        assert getattr(manager, method)(*args) is True
        getattr(conn, conn_method).assert_called_once()

        getattr(conn, conn_method).return_value = False
        conn.result = {"result": 50}
        with pytest.raises(LDAPException, match="operation failed"):
            getattr(manager, method)(*args)

    def test_move_passes_new_superior(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        manager.move("CN=a,OU=x", "OU=y")
        conn_cls.return_value.modify_dn.assert_called_once_with("CN=a,OU=x", new_superior="OU=y")

    @pytest.mark.parametrize("method,args", [("add", ("CN=a", {})), ("modify", ("CN=a", {})), ("delete", ("CN=a",)), ("move", ("CN=a", "OU=b"))])
    def test_connection_exception_propagates(self, manager, ldap3_seam, method, args):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        for name in ("add", "modify", "delete", "modify_dn"):
            getattr(conn, name).side_effect = LDAPSocketOpenError("reset")
        with pytest.raises(LDAPSocketOpenError):
            getattr(manager, method)(*args)


class TestLifecycle:
    def test_disconnect_idempotent(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        manager.disconnect()  # never connected: no-op
        manager.connect()
        manager.disconnect()
        manager.disconnect()
        conn_cls.return_value.unbind.assert_called_once()
        assert manager._connection is None

    def test_disconnect_swallows_unbind_error(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.return_value.unbind.side_effect = LDAPException("x")
        manager.connect()
        manager.disconnect()
        assert manager._connection is None

    def test_context_manager_disconnects(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        with manager as m:
            m.connect()
        conn_cls.return_value.unbind.assert_called_once()

    def test_test_connection_success(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn = conn_cls.return_value
        conn.server.host, conn.server.port, conn.server.ssl = "dc", 636, True
        conn.bound, conn.user = True, "CN=svc"
        info = manager.test_connection()
        assert info == {
            "connected": True, "server": "dc", "port": 636, "ssl": True,
            "bound": True, "user": "CN=svc", "search_test": True,
        }

    def test_test_connection_search_failure_is_reported(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.return_value.search.side_effect = LDAPException("no rights")
        info = manager.test_connection()
        assert info["connected"] is True
        assert info["search_test"] is False
        assert "no rights" in info["search_error"]

    def test_test_connection_failure(self, manager, ldap3_seam):
        _, conn_cls = ldap3_seam
        conn_cls.side_effect = LDAPSocketOpenError("unreachable")
        with patch.object(lm.time, "sleep"):
            info = manager.test_connection()
        assert info["connected"] is False
        assert "unreachable" in info["error"]


class TestSecureChannel:
    def _conn(self, ldap3_seam, ssl, tls_started=False):
        conn = ldap3_seam[1].return_value
        conn.bind.return_value = True
        conn.bound = True
        conn.server.ssl = ssl
        conn.tls_started = tls_started
        return conn

    def test_ldaps_is_secure(self, manager, ldap3_seam):
        self._conn(ldap3_seam, ssl=True)
        assert manager.is_secure_channel() is True

    def test_plain_ldap_is_not_secure(self, manager, ldap3_seam):
        self._conn(ldap3_seam, ssl=False)
        assert manager.is_secure_channel() is False

    def test_ldaps_without_certificate_validation_is_not_secure(self, make_manager, ldap3_seam):
        manager = make_manager(SecurityConfig(enable_tls=True, validate_certificate=False))
        self._conn(ldap3_seam, ssl=True)
        assert manager.is_secure_channel() is False

    def test_starttls_is_secure(self, manager, ldap3_seam):
        self._conn(ldap3_seam, ssl=False, tls_started=True)
        assert manager.is_secure_channel() is True

    def test_connect_failure_propagates(self, manager, ldap3_seam):
        ldap3_seam[1].side_effect = LDAPSocketOpenError("down")
        with pytest.raises(LDAPException):
            manager.is_secure_channel()
