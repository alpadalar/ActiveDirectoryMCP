"""Configuration loader for Active Directory MCP."""

import json
import os
import logging
from pathlib import Path
from typing import Optional

from .models import Config
from .keyvault import get_secret, KeyVaultError

logger = logging.getLogger(__name__)


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
                "No configuration file specified. Either provide config_path or set AD_MCP_CONFIG environment variable."
            )
    
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    logger.info(f"Loading configuration from: {config_path}")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        # Validate and create config object
        config = Config(**config_data)

        # Resolve bind username/password securely (Azure Key Vault, env vars, or file)
        _resolve_credentials(config)

        logger.info("Configuration loaded successfully")
        
        # Log configuration summary (without sensitive data)
        logger.debug(f"AD Server: {config.active_directory.server}")
        logger.debug(f"Domain: {config.active_directory.domain}")
        logger.debug(f"Base DN: {config.active_directory.base_dn}")
        logger.debug(f"SSL Enabled: {config.active_directory.use_ssl}")
        
        return config
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


def _resolve_credentials(config: Config) -> None:
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

    vault_url = os.getenv("AZURE_KEYVAULT_URL")
    username_secret_name = os.getenv("AZURE_KEYVAULT_SECRET_USERNAME")
    password_secret_name = os.getenv("AZURE_KEYVAULT_SECRET_PASSWORD")
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
            ad.password = get_secret(vault_url, password_secret_name)
        except KeyVaultError as exc:
            raise ValueError(str(exc)) from exc
        return

    env_bind_dn = os.getenv("AD_BIND_DN")
    if env_bind_dn:
        logger.info("Using AD bind DN from AD_BIND_DN environment variable")
        ad.bind_dn = env_bind_dn

    env_password = os.getenv("AD_PASSWORD")
    if env_password:
        logger.info("Using AD bind password from AD_PASSWORD environment variable")
        ad.password = env_password
        return

    if ad.password:
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
        if not config.active_directory.server.startswith('ldaps://'):
            logger.warning("SSL enabled but server URL doesn't use ldaps://")
    
    logger.info("Configuration validation completed")
