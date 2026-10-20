"""Tests for configuration module."""

import pytest
import tempfile
import json
import os
from pathlib import Path

from active_directory_mcp.config.loader import load_config, validate_config
from active_directory_mcp.config.models import Config, ActiveDirectoryConfig


def test_load_config_from_file():
    """Test loading configuration from JSON file."""
    config_data = {
        "active_directory": {
            "server": "ldaps://test.local:636",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name
    
    try:
        config = load_config(config_path)
        assert isinstance(config, Config)
        assert config.active_directory.server == "ldaps://test.local:636"
        assert config.active_directory.domain == "test.local"
    finally:
        os.unlink(config_path)


def test_env_placeholder_resolution(tmp_path, monkeypatch):
    """Config değerlerinin ortam değişkenlerinden okunmasını test et."""
    config_data = {
        "active_directory": {
            "server": "ldaps://secure.local:636",
            "domain": "secure.local",
            "base_dn": "DC=secure,DC=local",
            "bind_dn": "CN=service,DC=secure,DC=local",
            "password": "${AD_BIND_PASSWORD}"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=secure,DC=local",
            "groups_ou": "OU=Groups,DC=secure,DC=local",
            "computers_ou": "OU=Computers,DC=secure,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=secure,DC=local"
        }
    }

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    monkeypatch.setenv("AD_BIND_PASSWORD", "super-secret")

    config = load_config(str(config_path))
    assert config.active_directory.password.get_secret_value() == "super-secret"


def test_env_placeholder_with_default(tmp_path):
    """Varsayılan değer içeren placeholder'ın çözülmesini test et."""
    config_data = {
        "active_directory": {
            "server": "ldaps://secure.local:636",
            "domain": "secure.local",
            "base_dn": "DC=secure,DC=local",
            "bind_dn": "CN=service,DC=secure,DC=local",
            "password": "${AD_BIND_PASSWORD:default-pass}"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=secure,DC=local",
            "groups_ou": "OU=Groups,DC=secure,DC=local",
            "computers_ou": "OU=Computers,DC=secure,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=secure,DC=local"
        }
    }

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    config = load_config(str(config_path))
    assert config.active_directory.password.get_secret_value() == "default-pass"


def test_env_placeholder_missing_env(tmp_path):
    """Ortam değişkeni olmayan placeholder için hata verilmesini test et."""
    config_data = {
        "active_directory": {
            "server": "ldaps://secure.local:636",
            "domain": "secure.local",
            "base_dn": "DC=secure,DC=local",
            "bind_dn": "CN=service,DC=secure,DC=local",
            "password": "${AD_BIND_PASSWORD}"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=secure,DC=local",
            "groups_ou": "OU=Groups,DC=secure,DC=local",
            "computers_ou": "OU=Computers,DC=secure,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=secure,DC=local"
        }
    }

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    with pytest.raises(ValueError, match="Environment variable 'AD_BIND_PASSWORD' is not set"):
        load_config(str(config_path))


def test_load_config_from_env():
    """Test loading configuration from environment variable."""
    config_data = {
        "active_directory": {
            "server": "ldap://env-test.local:389",
            "domain": "env-test.local",
            "base_dn": "DC=env-test,DC=local",
            "bind_dn": "CN=admin,DC=env-test,DC=local",
            "password": "envpassword123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=env-test,DC=local",
            "groups_ou": "OU=Groups,DC=env-test,DC=local",
            "computers_ou": "OU=Computers,DC=env-test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=env-test,DC=local"
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name
    
    try:
        # Set environment variable
        os.environ['AD_MCP_CONFIG'] = config_path
        
        config = load_config()
        assert isinstance(config, Config)
        assert config.active_directory.domain == "env-test.local"
    finally:
        os.unlink(config_path)
        if 'AD_MCP_CONFIG' in os.environ:
            del os.environ['AD_MCP_CONFIG']


def test_config_validation():
    """Test configuration validation."""
    config_data = {
        "active_directory": {
            "server": "ldaps://test.local:636",
            "domain": "test.local", 
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    config = Config(**config_data)
    # Should not raise exception
    validate_config(config)


def test_secure_connection_required_validation():
    """require_secure_connection ayarı için doğrulama kurallarını test et."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123",
            "use_ssl": False
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        },
        "security": {
            "require_secure_connection": True
        }
    }

    cfg = Config(**config_data)
    with pytest.raises(ValueError, match="Secure connection required but 'use_ssl' is disabled"):
        validate_config(cfg)


def test_require_secure_connection_defaults_to_true():
    """Omitting the security section must fail closed for plaintext ldap://."""
    from active_directory_mcp.config.models import SecurityConfig

    assert SecurityConfig().require_secure_connection is True
    cfg = Config(
        active_directory={
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123",
        }
    )
    with pytest.raises(ValueError, match="Secure connection required"):
        validate_config(cfg)


def test_invalid_server_url():
    """Test validation of invalid server URL."""
    with pytest.raises(ValueError, match="Server must start with ldap:// or ldaps://"):
        ActiveDirectoryConfig(
            server="http://invalid.com",
            domain="test.local",
            base_dn="DC=test,DC=local",
            bind_dn="CN=admin,DC=test,DC=local",
            password="password123"
        )


def test_missing_config_file():
    """Test handling of missing configuration file."""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.json")


def test_invalid_json():
    """Test handling of invalid JSON."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("invalid json content")
        config_path = f.name
    
    try:
        with pytest.raises(json.JSONDecodeError):
            load_config(config_path)
    finally:
        os.unlink(config_path)


def test_missing_required_fields():
    """Test validation of missing required fields."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            # Missing required fields
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    with pytest.raises(ValueError):
        Config(**config_data)


def test_default_values():
    """Test default configuration values."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    config = Config(**config_data)
    
    # Test default values
    assert config.security.enable_tls == True
    assert config.logging.level == "INFO"
    assert config.performance.connection_pool_size is None
    assert config.active_directory.use_ssl == True
    assert config.active_directory.ssl_port == 636


def test_env_placeholder_partial_expansion(monkeypatch):
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    monkeypatch.setenv("AD_TEST_HOST", "dc1.example.com")
    monkeypatch.delenv("AD_TEST_UNSET", raising=False)
    assert _resolve_env_placeholders("ldaps://${AD_TEST_HOST}:636") == "ldaps://dc1.example.com:636"
    assert _resolve_env_placeholders("${AD_TEST_HOST}-${AD_TEST_HOST}") == (
        "dc1.example.com-dc1.example.com"
    )
    assert _resolve_env_placeholders(["a-${AD_TEST_HOST}", {"k": "${AD_TEST_HOST}"}]) == [
        "a-dc1.example.com",
        {"k": "dc1.example.com"},
    ]


def test_env_placeholder_default_may_contain_colon(monkeypatch):
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    monkeypatch.delenv("AD_TEST_UNSET", raising=False)
    assert _resolve_env_placeholders("${AD_TEST_UNSET:ldaps://dc:636}") == "ldaps://dc:636"
    assert _resolve_env_placeholders("x-${AD_TEST_UNSET:d}-y") == "x-d-y"


def test_env_placeholder_partial_missing_raises(monkeypatch):
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    monkeypatch.delenv("AD_TEST_UNSET", raising=False)
    with pytest.raises(ValueError, match="AD_TEST_UNSET"):
        _resolve_env_placeholders("prefix-${AD_TEST_UNSET}")


def test_env_placeholder_malformed_text_untouched():
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    assert _resolve_env_placeholders("${not closed") == "${not closed"
    assert _resolve_env_placeholders("pa$$word${") == "pa$$word${"
    assert _resolve_env_placeholders(5) == 5



# --- Strict models, SecretStr, object classes, deprecated pool size (02-02 task 1) ---

_AD = {
    "server": "ldaps://dc.test.local",
    "domain": "test.local",
    "base_dn": "DC=test,DC=local",
    "bind_dn": "CN=svc,DC=test,DC=local",
    "password": "s3cr3t-value-xyz",
}
REPO_ROOT = Path(__file__).resolve().parents[2]


def _full(**overrides):
    data = {"active_directory": dict(_AD)}
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    "section",
    ["active_directory", "organizational_units", "key_vault", "security", "logging", "performance"],
)
def test_unknown_key_rejected_per_section(section):
    from pydantic import ValidationError

    base = {
        "organizational_units": {
            "users_ou": "a", "groups_ou": "b", "computers_ou": "c", "service_accounts_ou": "d",
        },
        "key_vault": {"vault_url": "https://v.vault.azure.net/"},
    }
    data = _full(**{k: dict(v) for k, v in base.items()})
    data.setdefault(section, {})
    data[section] = dict(data[section])
    data[section]["bogus_key"] = 1
    with pytest.raises(ValidationError):
        Config(**data)


def test_unknown_top_level_key_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Config(**_full(bogus=1))


def test_security_check_names_now_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Config(**_full(security={"check_names": True}))


def test_password_is_secretstr_and_masked():
    cfg = Config(**_full())
    secret = _AD["password"]
    assert cfg.active_directory.password.get_secret_value() == secret
    for text in (
        str(cfg),
        repr(cfg),
        str(cfg.active_directory),
        repr(cfg.active_directory),
        str(cfg.model_dump()),
        cfg.model_dump_json(),
        cfg.active_directory.model_dump_json(),
    ):
        assert secret not in text


def test_password_assignment_coerced_to_secretstr():
    from pydantic import SecretStr

    cfg = Config(**_full())
    cfg.active_directory.password = "from-vault-or-env"
    assert isinstance(cfg.active_directory.password, SecretStr)
    assert "from-vault-or-env" not in repr(cfg)


@pytest.mark.parametrize("field", ["user_object_class", "group_object_class", "computer_object_class"])
def test_object_class_injection_rejected(field):
    data = dict(_AD)
    data[field] = "user)(|(objectClass=*"
    with pytest.raises(ValueError):
        ActiveDirectoryConfig(**data)


def test_object_class_defaults_and_custom_accepted():
    ad = ActiveDirectoryConfig(**_AD, user_object_class="inetOrgPerson")
    assert (ad.user_object_class, ad.group_object_class, ad.computer_object_class) == (
        "inetOrgPerson", "group", "computer",
    )


def test_connection_pool_size_deprecated_but_accepted():
    from active_directory_mcp.config.models import PerformanceConfig

    assert PerformanceConfig().connection_pool_size is None
    assert PerformanceConfig(connection_pool_size=5).connection_pool_size == 5
    with pytest.raises(ValueError):
        PerformanceConfig(connection_pool_size=0)
    with pytest.raises(ValueError):
        PerformanceConfig(connection_pool_size=-1)


@pytest.mark.parametrize(
    "rel", ["ad-config/config.example.json", "ad-config/production-config.example.json"]
)
def test_example_configs_parse(rel):
    data = json.loads((REPO_ROOT / rel).read_text(encoding="utf-8"))
    assert Config(**data)
    assert "connection_pool_size" not in data.get("performance", {})


def test_local_ad_config_parses():
    path = REPO_ROOT / "ad-config" / "ad-config.json"
    if not path.exists():
        pytest.skip("ad-config/ad-config.json not present")
    assert Config(**json.loads(path.read_text(encoding="utf-8")))



# --- Loader hardening (02-02 task 2) ---

import logging  # noqa: E402

from active_directory_mcp import redaction  # noqa: E402

SECRET = "hunter2hunter2"


@pytest.fixture(autouse=True)
def _clean_redaction():
    redaction.clear_secrets()
    yield
    redaction.clear_secrets()


def _write(tmp_path, ad_overrides=None, **sections):
    ad = dict(_AD)
    ad.update(ad_overrides or {})
    data = {"active_directory": ad}
    data.update(sections)
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


@pytest.fixture
def clean_env(monkeypatch):
    for var in (
        "AD_PASSWORD", "AD_BIND_DN", "AZURE_KEYVAULT_URL",
        "AZURE_KEYVAULT_SECRET_USERNAME", "AZURE_KEYVAULT_SECRET_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)


def test_placeholder_unset_error_names_only_variable(monkeypatch):
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    monkeypatch.delenv("AD_TEST_UNSET", raising=False)
    with pytest.raises(ValueError) as info:
        _resolve_env_placeholders("topsecret-${AD_TEST_UNSET}")
    assert "AD_TEST_UNSET" in str(info.value)
    assert "topsecret" not in str(info.value)


def test_placeholder_empty_default(monkeypatch):
    from active_directory_mcp.config.loader import _resolve_env_placeholders

    monkeypatch.delenv("AD_TEST_UNSET", raising=False)
    assert _resolve_env_placeholders("a${AD_TEST_UNSET:}b") == "ab"


def test_validation_error_never_echoes_input(tmp_path, clean_env, caplog):
    path = _write(tmp_path, ad_overrides={"passwrd": SECRET})
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ValueError) as info:
            load_config(path)
    assert SECRET not in str(info.value)
    assert "passwrd" in str(info.value)
    assert SECRET not in caplog.text


def test_value_error_in_field_does_not_echo_password(tmp_path, clean_env, caplog):
    path = _write(tmp_path, ad_overrides={"server": SECRET})
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ValueError) as info:
            load_config(path)
    assert SECRET not in str(info.value)
    assert SECRET not in caplog.text


def _assert_registered(secret, caplog):
    assert secret not in redaction.redact(f"token={secret}")
    assert secret not in caplog.text


def test_secret_registered_from_file(tmp_path, clean_env, caplog):
    with caplog.at_level(logging.DEBUG):
        cfg = load_config(_write(tmp_path))
    assert cfg.active_directory.password.get_secret_value() == _AD["password"]
    _assert_registered(_AD["password"], caplog)


def test_secret_registered_from_placeholder(tmp_path, clean_env, monkeypatch, caplog):
    monkeypatch.setenv("AD_BIND_PASSWORD", SECRET)
    path = _write(tmp_path, ad_overrides={"password": "${AD_BIND_PASSWORD}"})
    with caplog.at_level(logging.DEBUG):
        cfg = load_config(path)
    assert cfg.active_directory.password.get_secret_value() == SECRET
    _assert_registered(SECRET, caplog)


def test_secret_registered_from_env(tmp_path, clean_env, monkeypatch, caplog):
    monkeypatch.setenv("AD_PASSWORD", SECRET)
    path = _write(tmp_path, ad_overrides={"password": None})
    with caplog.at_level(logging.DEBUG):
        cfg = load_config(path)
    assert cfg.active_directory.password.get_secret_value() == SECRET
    _assert_registered(SECRET, caplog)


def test_secret_registered_from_keyvault(tmp_path, clean_env, monkeypatch, caplog):
    from unittest.mock import patch

    def fake(vault_url, name):
        return {"user-secret": "CN=kv,DC=test,DC=local", "pw-secret": SECRET}[name]

    path = _write(
        tmp_path,
        ad_overrides={"password": None},
        key_vault={
            "vault_url": "https://v.vault.azure.net/",
            "username_secret_name": "user-secret",
            "password_secret_name": "pw-secret",
        },
    )
    with patch("active_directory_mcp.config.loader.get_secret", side_effect=fake):
        with caplog.at_level(logging.DEBUG):
            cfg = load_config(path)
    assert cfg.active_directory.password.get_secret_value() == SECRET
    assert cfg.active_directory.bind_dn == "CN=kv,DC=test,DC=local"
    _assert_registered(SECRET, caplog)


def test_keyvault_error_surfaces_as_value_error(tmp_path, clean_env):
    from unittest.mock import patch

    from active_directory_mcp.config.keyvault import KeyVaultError

    path = _write(
        tmp_path,
        ad_overrides={"password": None},
        key_vault={"vault_url": "https://v.vault.azure.net/"},
    )
    with patch(
        "active_directory_mcp.config.loader.get_secret", side_effect=KeyVaultError("kv boom")
    ):
        with pytest.raises(ValueError, match="kv boom"):
            load_config(path)


def _cfg(ad=None, security=None, performance=None):
    ad_data = dict(_AD)
    ad_data.update(ad or {})
    return Config(
        active_directory=ad_data,
        security=security or {},
        performance=performance or {},
    )


def test_validate_rejects_plaintext_by_default():
    with pytest.raises(ValueError, match="Secure connection required"):
        validate_config(_cfg(ad={"server": "ldap://dc.test.local"}))
    with pytest.raises(ValueError, match="use_ssl"):
        validate_config(_cfg(ad={"use_ssl": False}))


def test_validate_rejects_tls_disabled():
    with pytest.raises(ValueError, match="TLS disabled"):
        validate_config(_cfg(security={"enable_tls": False}))


def test_validate_explicit_opt_out_warns_plaintext(caplog):
    cfg = _cfg(ad={"server": "ldap://dc.test.local"}, security={"require_secure_connection": False})
    with caplog.at_level(logging.WARNING):
        validate_config(cfg)
    assert "plaintext" in caplog.text


def test_validate_certificate_disabled_warns(caplog):
    cfg = _cfg(security={"validate_certificate": False})
    with caplog.at_level(logging.WARNING):
        validate_config(cfg)
    assert "certificate validation is disabled" in caplog.text


def test_validate_pool_size_ignored_warning(caplog):
    with caplog.at_level(logging.WARNING):
        validate_config(_cfg(performance={"connection_pool_size": 5}))
    assert "ignored" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        validate_config(_cfg())
    assert "connection_pool_size" not in caplog.text


# ---------------------------------------------------------------- SecurityConfig (SEC-01/02)

from pydantic import ValidationError  # noqa: E402

from active_directory_mcp.config.models import HttpAuthConfig, SecurityConfig  # noqa: E402

_DIGEST = "a" * 64


def test_security_defaults_are_read_only_and_authenticated():
    sec = SecurityConfig()
    assert sec.allow_writes is False
    assert sec.allow_destructive is False
    assert sec.max_list_results == 1000
    assert sec.protect_privileged_targets is True
    assert sec.http_auth.required is True
    assert sec.http_auth.api_key_sha256 == []
    assert _cfg().security.allow_writes is False


def test_security_round_trip():
    sec = SecurityConfig(
        allow_writes=True,
        allow_destructive=True,
        max_list_results=0,
        http_auth={"required": False, "api_key_sha256": [_DIGEST.upper()]},
    )
    again = SecurityConfig.model_validate(sec.model_dump())
    assert again == sec
    assert again.http_auth.api_key_sha256 == [_DIGEST]


def test_http_auth_rejects_unknown_key():
    with pytest.raises(ValidationError):
        HttpAuthConfig(api_key="plaintext")
    with pytest.raises(ValidationError):
        SecurityConfig(http_auth={"typo": 1})


def test_http_auth_rejects_bad_digest_without_echo():
    secret = "not-a-digest-secret"
    with pytest.raises(ValidationError) as exc:
        HttpAuthConfig(api_key_sha256=[_DIGEST, secret])
    text = str(exc.value)
    assert "api_key_sha256[1]" in text
    assert secret not in text


def test_allow_destructive_requires_allow_writes():
    with pytest.raises(ValidationError, match="allow_destructive.*allow_writes"):
        SecurityConfig(allow_destructive=True)
    assert SecurityConfig(allow_writes=True, allow_destructive=True).allow_destructive


def test_max_list_results_rejects_negative():
    with pytest.raises(ValidationError):
        SecurityConfig(max_list_results=-1)
    assert SecurityConfig(max_list_results=0).max_list_results == 0


def test_example_configs_still_load():
    root = Path(__file__).resolve().parents[2]
    found = [p for p in (root / "config").glob("*.json")] if (root / "config").is_dir() else []
    for path in found:
        data = json.loads(path.read_text(encoding="utf-8"))
        if "active_directory" in data:
            Config.model_validate(data)
