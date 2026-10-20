"""Configuration models for Active Directory MCP."""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class ActiveDirectoryConfig(BaseModel):
    """Active Directory connection configuration."""
    
    server: str = Field(..., description="Primary LDAP server URL")
    server_pool: Optional[List[str]] = Field(default=None, description="Additional LDAP servers for redundancy")
    use_ssl: bool = Field(default=True, description="Use SSL/TLS connection")
    ssl_port: int = Field(default=636, description="SSL port for LDAP")
    domain: str = Field(..., description="Active Directory domain")
    base_dn: str = Field(..., description="Base Distinguished Name")
    bind_dn: str = Field(..., description="Service account DN for binding")
    password: Optional[str] = Field(
        default=None,
        description=(
            "Service account password. Leave unset and configure 'key_vault' "
            "(recommended) to retrieve it securely from Azure Key Vault instead "
            "of storing it in plaintext."
        ),
    )
    timeout: int = Field(default=30, description="Connection timeout in seconds")
    auto_bind: bool = Field(default=True, description="Automatically bind on connection")
    receive_timeout: int = Field(default=10, description="Receive timeout in seconds")
    user_object_class: str = Field(
        default="user",
        description="Primary objectClass değeri (ör: user, inetOrgPerson)"
    )
    group_object_class: str = Field(
        default="group",
        description="Grup aramalarında kullanılacak objectClass"
    )
    computer_object_class: str = Field(
        default="computer",
        description="Bilgisayar nesneleri için objectClass"
    )
    
    @field_validator('server')
    @classmethod
    def validate_server(cls, v):
        """Validate server URL format."""
        if not v.startswith(('ldap://', 'ldaps://')):
            raise ValueError('Server must start with ldap:// or ldaps://')
        return v


class OrganizationalUnitsConfig(BaseModel):
    """Organizational Units configuration."""
    
    users_ou: str = Field(..., description="Users organizational unit DN")
    groups_ou: str = Field(..., description="Groups organizational unit DN")
    computers_ou: str = Field(..., description="Computers organizational unit DN")
    service_accounts_ou: str = Field(..., description="Service accounts organizational unit DN")

    @classmethod
    def defaults_for(cls, base_dn: str) -> "OrganizationalUnitsConfig":
        """Default OUs derived from the base DN (the built-in Active Directory containers)."""
        return cls(
            users_ou=f"CN=Users,{base_dn}",
            groups_ou=f"CN=Users,{base_dn}",
            computers_ou=f"CN=Computers,{base_dn}",
            service_accounts_ou=f"CN=Users,{base_dn}",
        )


class KeyVaultConfig(BaseModel):
    """Azure Key Vault configuration for secure credential retrieval."""

    vault_url: str = Field(
        ..., description="Azure Key Vault URL, e.g. https://your-vault.vault.azure.net/"
    )
    username_secret_name: Optional[str] = Field(
        default=None,
        description=(
            "Name of the Key Vault secret holding the AD bind DN / username. "
            "Optional - if unset, 'active_directory.bind_dn' from the config file is used."
        ),
    )
    password_secret_name: str = Field(
        default="ad-bind-password",
        description="Name of the Key Vault secret holding the AD service account password",
    )

    @field_validator('vault_url')
    @classmethod
    def validate_vault_url(cls, v):
        """Validate Key Vault URL format."""
        if not v.startswith('https://'):
            raise ValueError('Key Vault URL must start with https://')
        return v


class SecurityConfig(BaseModel):
    """Security configuration for LDAP connections."""
    
    enable_tls: bool = Field(default=True, description="Enable TLS encryption")
    validate_certificate: bool = Field(default=True, description="Validate server certificate")
    ca_cert_file: Optional[str] = Field(default=None, description="CA certificate file path")
    require_secure_connection: bool = Field(default=True, description="Require secure connection")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: str = Field(default="INFO", description="Logging level")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format"
    )
    file: Optional[str] = Field(default=None, description="Log file path")
    
    @field_validator('level')
    @classmethod
    def validate_level(cls, v):
        """Validate logging level."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Level must be one of: {valid_levels}')
        return v.upper()


class PerformanceConfig(BaseModel):
    """Performance configuration."""
    
    connection_pool_size: int = Field(default=10, description="Connection pool size")
    max_retries: int = Field(default=3, description="Maximum connection retries")
    retry_delay: float = Field(default=1.0, description="Retry delay in seconds")
    page_size: int = Field(default=1000, description="LDAP search page size")
    
    @field_validator('connection_pool_size', 'max_retries', 'page_size')
    @classmethod
    def validate_positive_int(cls, v):
        """Validate positive integers."""
        if v <= 0:
            raise ValueError('Value must be positive')
        return v
    
    @field_validator('retry_delay')
    @classmethod
    def validate_positive_float(cls, v):
        """Validate positive float."""
        if v <= 0:
            raise ValueError('Retry delay must be positive')
        return v


class Config(BaseModel):
    """Main configuration class."""
    
    active_directory: ActiveDirectoryConfig
    organizational_units: OrganizationalUnitsConfig = Field(
        default=None,  # type: ignore[assignment]  # always filled by _fill_default_ous
        description=(
            "Default OUs used when a tool call omits the target OU. Optional: any missing "
            "entry (or the whole section) defaults to the built-in containers under base_dn."
        ),
    )
    key_vault: Optional[KeyVaultConfig] = Field(
        default=None,
        description="Azure Key Vault settings used to retrieve secrets such as the bind password",
    )
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)

    @model_validator(mode="before")
    @classmethod
    def _fill_default_ous(cls, data):
        """Fill missing organizational_units entries from base_dn-derived defaults."""
        if not isinstance(data, dict):
            return data
        ad = data.get("active_directory")
        base_dn = ad.get("base_dn") if isinstance(ad, dict) else getattr(ad, "base_dn", None)
        if not isinstance(base_dn, str):
            return data  # let normal validation report the missing/invalid base_dn
        given = data.get("organizational_units")
        if given is None:
            given = {}
        elif isinstance(given, OrganizationalUnitsConfig):
            return data
        elif not isinstance(given, dict):
            return data
        merged = OrganizationalUnitsConfig.defaults_for(base_dn).model_dump()
        merged.update({k: v for k, v in given.items() if v is not None})
        return {**data, "organizational_units": merged}
