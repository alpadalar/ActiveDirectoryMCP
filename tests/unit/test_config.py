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
