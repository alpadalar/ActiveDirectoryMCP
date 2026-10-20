"""Unit tests for DirectoryTools.get_tls_posture (mocked LDAPManager)."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from ldap3.core.exceptions import LDAPSocketOpenError

from active_directory_mcp.redaction import clear_secrets, register_secret
from active_directory_mcp.tools.directory import DirectoryTools
from tests.support.helpers import parse_response


def _connection(ssl=False, tls_started=False, sock=None):
    return SimpleNamespace(
        server=SimpleNamespace(ssl=ssl), tls_started=tls_started, socket=sock
    )


@pytest.fixture
def tools(mock_ldap_manager):
    mock_ldap_manager.connect.return_value = _connection(ssl=True)
    return DirectoryTools(mock_ldap_manager)


def _codes(data):
    return {f["code"] for f in data["findings"]}


def test_ldaps_clean(tools):
    data = parse_response(tools.get_tls_posture())
    assert data["success"] is True
    assert data["live"]["connected"] is True and data["live"]["channel"] == "ldaps"
    assert data["live"]["secure_channel"] is True
    assert data["findings"] == []


def test_version_and_cipher_when_exposed(tools, mock_ldap_manager):
    sock = Mock()
    sock.version.return_value = "TLSv1.3"
    sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ldap_manager.connect.return_value = _connection(ssl=True, sock=sock)
    live = parse_response(tools.get_tls_posture())["live"]
    assert live["tls_version"] == "TLSv1.3"
    assert live["cipher"] == "TLS_AES_256_GCM_SHA384"


def test_starttls(tools, mock_ldap_manager):
    mock_ldap_manager.connect.return_value = _connection(ssl=False, tls_started=True)
    data = parse_response(tools.get_tls_posture())
    assert data["live"]["channel"] == "starttls"
    assert "plaintext_channel" not in _codes(data)


def test_plaintext(tools, mock_ldap_manager):
    mock_ldap_manager.connect.return_value = _connection()
    mock_ldap_manager.is_secure_channel.return_value = False
    data = parse_response(tools.get_tls_posture())
    assert data["live"]["channel"] == "plaintext"
    finding = next(f for f in data["findings"] if f["code"] == "plaintext_channel")
    assert finding["severity"] == "high"


def test_validation_and_tls_flags(tools, mock_ldap_manager):
    sec = mock_ldap_manager.security_config
    sec.validate_certificate = False
    sec.enable_tls = False
    sec.require_secure_connection = False
    data = parse_response(tools.get_tls_posture())
    assert {
        "certificate_validation_disabled",
        "tls_disabled",
        "secure_connection_not_required",
    } <= _codes(data)
    assert data["configured"]["validate_certificate"] is False


def test_connect_failure_returns_fixed_code_and_finding(tools, mock_ldap_manager):
    mock_ldap_manager.connect.side_effect = LDAPSocketOpenError(
        "dc01.corp.example (10.1.2.3):636 cn=svc,dc=corp bind hunter2-secret failed"
    )
    data = parse_response(tools.get_tls_posture())
    text = json.dumps(data)
    assert data["live"] == {"connected": False, "error": "connect_failed"}
    for leak in ("dc01", "10.1.2.3", "svc", "hunter2-secret"):
        assert leak not in text
    finding = next(f for f in data["findings"] if f["code"] == "connection_failed")
    assert finding["severity"] == "high"


def test_probe_does_not_retry_binds(tools, mock_ldap_manager):
    tools.get_tls_posture()
    mock_ldap_manager.connect.assert_called_once_with(max_attempts=1)


@pytest.mark.parametrize("version", ["TLSv1", "TLSv1.1", "SSLv3"])
def test_weak_tls_version_flagged(tools, mock_ldap_manager, version):
    sock = Mock()
    sock.version.return_value = version
    sock.cipher.return_value = ("X", version, 128)
    mock_ldap_manager.connect.return_value = _connection(ssl=True, sock=sock)
    data = parse_response(tools.get_tls_posture())
    assert "weak_tls_version" in _codes(data)


def test_modern_tls_version_not_flagged(tools, mock_ldap_manager):
    sock = Mock()
    sock.version.return_value = "TLSv1.3"
    sock.cipher.return_value = ("X", "TLSv1.3", 256)
    mock_ldap_manager.connect.return_value = _connection(ssl=True, sock=sock)
    assert "weak_tls_version" not in _codes(parse_response(tools.get_tls_posture()))


def test_no_secrets_or_paths_in_output(tools, mock_ldap_manager):
    mock_ldap_manager.security_config.ca_cert_file = "/etc/ssl/private/my-ca.pem"
    text = json.dumps(parse_response(tools.get_tls_posture()))
    password = mock_ldap_manager.ad_config.password.get_secret_value()
    assert password not in text
    assert "/etc/ssl/private/my-ca.pem" not in text
    assert json.loads(text)["configured"]["ca_cert_file_set"] is True
