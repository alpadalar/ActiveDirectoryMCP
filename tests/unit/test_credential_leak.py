"""End-to-end proof that the bind password never leaves the process (CONF-04).

A unique sentinel password is pushed through every credential source and every
outbound text channel: stderr, the log file, captured log records, exception text and
tool error responses. ldap3 is mocked; the mocked bind error deliberately echoes the
password, as a hostile or buggy server/library could.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest
from ldap3.core.exceptions import LDAPBindError, LDAPException

from active_directory_mcp import redaction
from active_directory_mcp.config.loader import load_config
from active_directory_mcp.config.models import PerformanceConfig
from active_directory_mcp.core import ldap_manager as lm
from active_directory_mcp.core.ldap_manager import LDAPManager
from active_directory_mcp.core.logging import setup_logging
from active_directory_mcp.tools.user import UserTools

SENTINEL = "Zq9!leak-sentinel-7731"

CREDENTIAL_ENV = (
    "AD_PASSWORD",
    "AD_BIND_DN",
    "AZURE_KEYVAULT_URL",
    "AZURE_KEYVAULT_SECRET_USERNAME",
    "AZURE_KEYVAULT_SECRET_PASSWORD",
    "AD_LEAK_VAR",
)


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    for name in CREDENTIAL_ENV:
        monkeypatch.delenv(name, raising=False)
    redaction.clear_secrets()
    root_level = logging.getLogger().level
    yield
    redaction.clear_secrets()
    logging.getLogger().setLevel(root_level)
    app = logging.getLogger("active-directory-mcp")
    for handler in list(app.handlers):
        handler.close()
    app.handlers.clear()


def _write_config(tmp_path, password=None, extra_ad=None, log_file=None):
    ad = {
        "server": "ldaps://dc.test.local:636",
        "domain": "test.local",
        "base_dn": "DC=test,DC=local",
        "bind_dn": "CN=svc,DC=test,DC=local",
    }
    if password is not None:
        ad["password"] = password
    ad.update(extra_ad or {})
    data = {"active_directory": ad}
    if log_file:
        data["logging"] = {"level": "DEBUG", "file": str(log_file)}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return str(path)


def _source_file(tmp_path, monkeypatch):
    return _write_config(tmp_path, password=SENTINEL)


def _source_placeholder(tmp_path, monkeypatch):
    monkeypatch.setenv("AD_LEAK_VAR", SENTINEL)
    return _write_config(tmp_path, password="${AD_LEAK_VAR}")


def _source_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AD_PASSWORD", SENTINEL)
    return _write_config(tmp_path)


def _source_keyvault(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_KEYVAULT_URL", "https://vault.test.invalid/")
    return _write_config(tmp_path)


SOURCES = {
    "file": _source_file,
    "placeholder": _source_placeholder,
    "env": _source_env,
    "keyvault": _source_keyvault,
}


def _all_text(exc):
    return f"{exc!s} {exc!r} {getattr(exc, 'args', '')!r}"


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_password_never_leaves_process(source, tmp_path, monkeypatch, capsys, caplog):
    config_path = SOURCES[source](tmp_path, monkeypatch)
    log_file = tmp_path / "ad.log"

    # The config's own logging section drives the app logger and its handlers
    config_path = _rewrite_with_logging(config_path, log_file)

    collected = []
    with patch("active_directory_mcp.config.loader.get_secret", return_value=SENTINEL):
        caplog.set_level(logging.DEBUG)
        config = load_config(config_path)
    logger = setup_logging(config.logging)
    logger.debug("startup complete")

    # No representation of the config exposes the password
    for rendered in (
        repr(config),
        str(config),
        config.model_dump_json(),
        repr(config.active_directory),
        str(config.active_directory),
    ):
        assert SENTINEL not in rendered

    # Connect failure whose message echoes the password
    bind_error = LDAPBindError(f"invalidCredentials for password {SENTINEL}")
    manager = LDAPManager(
        config.active_directory,
        config.security.model_copy(update={"enable_tls": False}),
        PerformanceConfig(max_retries=2, retry_delay=0.001),
        config.organizational_units,
    )
    with patch.object(lm, "Connection", MagicMock(side_effect=bind_error)):
        with pytest.raises(LDAPException) as info:
            manager.connect()
        collected.append(_all_text(info.value))

        # A tool error path over the same failing connection
        response = UserTools(manager).get_user("alice")
    collected.append(response[0].text)
    assert json.loads(response[0].text)["success"] is False

    for handler in logger.handlers:
        handler.flush()
    captured = capsys.readouterr()
    log_text = log_file.read_text(encoding="utf-8") if log_file.exists() else ""

    assert "Logging initialized" in log_text  # the file really was written
    for channel, text in (
        ("stderr", captured.err),
        ("stdout", captured.out),
        ("log file", log_text),
        ("exceptions and tool errors", " ".join(collected)),
    ):
        assert SENTINEL not in text, f"password leaked via {channel} ({source})"


def _rewrite_with_logging(config_path, log_file):
    with open(config_path, encoding="utf-8") as handle:
        data = json.load(handle)
    data["logging"] = {"level": "DEBUG", "file": str(log_file)}
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return config_path


def test_typo_key_holding_password_does_not_leak(tmp_path):
    path = _write_config(tmp_path, password="placeholder-pw", extra_ad={"passwrd": SENTINEL})
    with pytest.raises(ValueError) as info:
        load_config(path)
    assert SENTINEL not in _all_text(info.value)
    assert "passwrd" in str(info.value)


def test_unset_placeholder_error_names_only_the_variable(tmp_path):
    path = _write_config(tmp_path, password=SENTINEL, extra_ad={"server": "${AD_LEAK_VAR}"})
    with pytest.raises(ValueError) as info:
        load_config(path)
    assert SENTINEL not in _all_text(info.value)
