"""Configuration loader for Active Directory MCP."""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import SecretStr, ValidationError

from ..redaction import install_record_factory, register_secret
from .keyvault import KeyVaultError, get_secret
from .models import Config, MultiDomainFile, SecurityConfig, ServerConfig

logger = logging.getLogger("active-directory-mcp.config")

# Redaction must be active before any config/Key Vault message can be logged
install_record_factory()


ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")


def _resolve_env_placeholders(value: Any) -> Any:
    """Recursively expand ${VAR} / ${VAR:default} placeholders in config strings.

    Placeholders are expanded anywhere inside a string (``ldap://${HOST}:389``). The
    default may itself contain ``:`` (``${URL:ldaps://dc:636}``). An unset variable
    without a default raises ValueError. Text that is not a well-formed placeholder
    (for example a literal password starting with ``${``) is left untouched.
    """
    if isinstance(value, dict):
        return {key: _resolve_env_placeholders(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_resolve_env_placeholders(item) for item in value]
    if isinstance(value, str):

        def _replace(match: "re.Match[str]") -> str:
            env_key, default = match.groups()
            env_value = os.getenv(env_key)
            if env_value is not None:
                return env_value
            if default is not None:
                return default
            raise ValueError(
                f"Environment variable '{env_key}' is not set and its configuration "
                "placeholder has no default"
            )

        return ENV_PATTERN.sub(_replace, value)
    return value


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from JSON file.

    Args:
        config_path: Path to configuration file. If None, uses AD_MCP_CONFIG
                    environment variable.

    Returns:
        Config: Loaded and validated configuration

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
        json.JSONDecodeError: If config file is not valid JSON
    """
    # Determine config file path
    if config_path is None:
        config_path = os.getenv("AD_MCP_CONFIG")
        if not config_path:
            raise ValueError(
                "No configuration file specified. Either provide config_path or set "
                "AD_MCP_CONFIG environment variable."
            )

    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    logger.info(f"Loading configuration from: {config_path}")
    return _build_config(_read_json(config_file))


def _read_json(config_file: Path) -> Any:
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise


def _build_config(config_data: Any, env_credentials: bool = True) -> Config:
    """Validate one single-domain config and resolve its bind credentials."""
    try:
        config_data = _resolve_env_placeholders(config_data)

        # Validate and create config object
        try:
            config = Config(**config_data)
        except ValidationError as exc:
            raise ValueError(_sanitize_validation_error(exc)) from None

        # Resolve bind username/password securely (Azure Key Vault, env vars, or file)
        _resolve_credentials(config, env_credentials)

        # Catch-all: whatever the source, the final password must never appear in logs
        if config.active_directory.password is not None:
            register_secret(config.active_directory.password.get_secret_value())

        logger.info("Configuration loaded successfully")

        # Log configuration summary (without sensitive data)
        logger.debug(f"AD Server: {config.active_directory.server}")
        logger.debug(f"Domain: {config.active_directory.domain}")
        logger.debug(f"Base DN: {config.active_directory.base_dn}")
        logger.debug(f"SSL Enabled: {config.active_directory.use_ssl}")

        return config

    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


# Process-wide credential variables: with several domains they would silently
# overwrite every domain's bind account, so multi-domain mode refuses them.
_GLOBAL_CREDENTIAL_ENV = (
    "AD_BIND_DN",
    "AD_PASSWORD",
    "AZURE_KEYVAULT_URL",
    "AZURE_KEYVAULT_SECRET_USERNAME",
    "AZURE_KEYVAULT_SECRET_PASSWORD",
)


def load_server_config(config_path: Optional[str] = None) -> ServerConfig:
    """Load a single-domain config or a multi-domain file (one with a ``domains`` key).

    A single-domain file becomes a one-domain ServerConfig named after
    ``active_directory.domain``, so existing configurations keep working.
    """
    if config_path is None:
        config_path = os.getenv("AD_MCP_CONFIG")
        if not config_path:
            raise ValueError(
                "No configuration file specified. Either provide config_path or set "
                "AD_MCP_CONFIG environment variable."
            )
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    logger.info(f"Loading configuration from: {config_path}")
    data = _read_json(config_file)
    if not (isinstance(data, dict) and "domains" in data):
        config = _build_config(data)
        name = config.active_directory.domain
        return ServerConfig(
            domains={name: config},
            default_domain=name,
            logging=config.logging,
            security=config.security,
        )

    try:
        # Inline domain configs are expanded once, by _build_config.
        rest = _resolve_env_placeholders({k: v for k, v in data.items() if k != "domains"})
        top = MultiDomainFile(**rest, domains=data["domains"])
    except ValidationError as exc:
        raise ValueError(_sanitize_validation_error(exc)) from None
    multi = len(top.domains) > 1
    if multi:
        present = [name for name in _GLOBAL_CREDENTIAL_ENV if os.getenv(name)]
        if present:
            raise ValueError(
                f"{', '.join(present)} cannot be used with several domains: set credentials "
                "per domain ('password' with a ${VAR} placeholder, or 'key_vault')"
            )
    domains = {}
    for name, value in top.domains.items():
        try:
            if isinstance(value, str):
                path = Path(value)
                if not path.is_absolute():
                    path = config_file.parent / path
                if not path.exists():
                    raise FileNotFoundError(f"Configuration file not found: {value}")
                value = _read_json(path)
            domains[name] = _build_config(value, env_credentials=not multi)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            raise ValueError(f"domain '{name}': {exc}") from None
    return ServerConfig(
        domains=domains,
        default_domain=top.default_domain or next(iter(domains)),
        logging=top.logging,
        security=SecurityConfig(http_auth=top.http_auth),
    )


def _sanitize_validation_error(exc: ValidationError) -> str:
    """Render a pydantic error as location + reason only (never the offending input)."""
    parts = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(item) for item in err.get("loc", ())) or "<root>"
        parts.append(f"{loc}: {err.get('msg', 'invalid value')}")
    return "Invalid configuration: " + "; ".join(parts)


def _set_password(ad: Any, value: str) -> None:
    """Store the bind password as SecretStr and register it for log redaction."""
    ad.password = SecretStr(value)
    register_secret(value)


def _resolve_credentials(config: Config, env_credentials: bool = True) -> None:
    """
    Resolve the AD bind username/password without relying on plaintext storage.

    Resolution order (username and password are resolved independently):
        1. Azure Key Vault - recommended. Configured via 'key_vault' in the
           configuration file, or via environment variables:
               AZURE_KEYVAULT_URL
               AZURE_KEYVAULT_SECRET_USERNAME  (name of the secret holding the bind DN)
               AZURE_KEYVAULT_SECRET_PASSWORD  (name of the secret holding the password)
           Authentication uses DefaultAzureCredential (managed identity, `az login`,
           or a service principal via AZURE_TENANT_ID / AZURE_CLIENT_ID /
           AZURE_CLIENT_SECRET).
        2. AD_BIND_DN / AD_PASSWORD environment variables.
        3. Values already present in the configuration file ('bind_dn' is
           required; a plaintext 'password' is discouraged and logs a warning).

    Raises:
        ValueError: If no password could be resolved from any source.
    """
    ad = config.active_directory
    env: Callable[[str], Optional[str]] = os.getenv if env_credentials else (lambda _name: None)

    vault_url = env("AZURE_KEYVAULT_URL")
    username_secret_name = env("AZURE_KEYVAULT_SECRET_USERNAME")
    password_secret_name = env("AZURE_KEYVAULT_SECRET_PASSWORD")
    if config.key_vault:
        vault_url = vault_url or config.key_vault.vault_url
        username_secret_name = username_secret_name or config.key_vault.username_secret_name
        password_secret_name = password_secret_name or config.key_vault.password_secret_name

    if vault_url:
        password_secret_name = password_secret_name or "ad-bind-password"

        if username_secret_name:
            logger.info(
                f"Retrieving AD bind username from Azure Key Vault '{vault_url}' "
                f"(secret: {username_secret_name})"
            )
            try:
                ad.bind_dn = get_secret(vault_url, username_secret_name)
            except KeyVaultError as exc:
                raise ValueError(str(exc)) from exc

        logger.info(
            f"Retrieving AD bind password from Azure Key Vault '{vault_url}' "
            f"(secret: {password_secret_name})"
        )
        try:
            _set_password(ad, get_secret(vault_url, password_secret_name))
        except KeyVaultError as exc:
            raise ValueError(str(exc)) from exc
        return

    env_bind_dn = env("AD_BIND_DN")
    if env_bind_dn:
        logger.info("Using AD bind DN from AD_BIND_DN environment variable")
        ad.bind_dn = env_bind_dn

    env_password = env("AD_PASSWORD")
    if env_password:
        logger.info("Using AD bind password from AD_PASSWORD environment variable")
        _set_password(ad, env_password)
        return

    if ad.password is not None and ad.password.get_secret_value():
        register_secret(ad.password.get_secret_value())
        logger.warning(
            "AD bind password is stored in plaintext in the configuration file. "
            "For production deployments, configure Azure Key Vault via the "
            "'key_vault.vault_url' setting (or AZURE_KEYVAULT_URL env var) instead."
        )
        return

    raise ValueError(
        "No AD bind password available. Configure Azure Key Vault via "
        "'key_vault.vault_url' in the configuration file (recommended), set the "
        "AD_PASSWORD environment variable, or set 'active_directory.password'."
    )


def validate_config(config: Config) -> None:
    """
    Perform additional validation on configuration.

    Args:
        config: Configuration to validate

    Raises:
        ValueError: If configuration is invalid
    """
    # Check if required OUs are under base DN
    base_dn = config.active_directory.base_dn.lower()

    ous = [
        config.organizational_units.users_ou,
        config.organizational_units.groups_ou,
        config.organizational_units.computers_ou,
        config.organizational_units.service_accounts_ou,
    ]

    for ou in ous:
        if not ou.lower().endswith(base_dn):
            logger.warning(f"OU {ou} is not under base DN {config.active_directory.base_dn}")

    # Validate bind DN
    if not config.active_directory.bind_dn.lower().endswith(base_dn):
        logger.warning(f"Bind DN {config.active_directory.bind_dn} is not under base DN")

    # Check SSL configuration
    if config.active_directory.use_ssl and config.security.enable_tls:
        if not config.active_directory.server.startswith("ldaps://"):
            logger.warning("SSL enabled but server URL doesn't use ldaps://")

    if config.security.require_secure_connection:
        if not config.active_directory.use_ssl:
            raise ValueError("Secure connection required but 'use_ssl' is disabled")
        if not config.active_directory.server.startswith("ldaps://"):
            raise ValueError("Secure connection required but server URL is not ldaps://")
        if not config.security.enable_tls:
            raise ValueError("Secure connection required but TLS disabled ('security.enable_tls')")
        if not config.security.validate_certificate:
            logger.warning(
                "TLS certificate validation is disabled; the server identity is not "
                "verified. Use only for lab/self-signed setups and prefer 'ca_cert_file'."
            )
    elif (
        not config.active_directory.use_ssl
        or not config.security.enable_tls
        or not config.active_directory.server.startswith("ldaps://")
    ):
        logger.warning(
            "require_secure_connection is false and the connection is not secured: "
            "credentials and directory data will travel in plaintext. Do not use "
            "this outside an isolated test environment."
        )

    if config.performance.connection_pool_size is not None:
        logger.warning(
            "performance.connection_pool_size is ignored: a single serialized LDAP "
            "connection is used. Remove it from the configuration."
        )

    logger.info("Configuration validation completed")
