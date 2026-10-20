"""Configuration models for Active Directory MCP."""

import re
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ..validation import validate_object_class


class ActiveDirectoryConfig(BaseModel):
    """Active Directory connection configuration."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    server: str = Field(..., description="Primary LDAP server URL")
    server_pool: Optional[List[str]] = Field(
        default=None, description="Additional LDAP servers for redundancy"
    )
    use_ssl: bool = Field(default=True, description="Use SSL/TLS connection")
    ssl_port: int = Field(default=636, description="SSL port for LDAP")
    domain: str = Field(..., description="Active Directory domain")
    base_dn: str = Field(..., description="Base Distinguished Name")
    bind_dn: str = Field(..., description="Service account DN for binding")
    password: Optional[SecretStr] = Field(
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
        default="user", description="Primary objectClass değeri (ör: user, inetOrgPerson)"
    )
    group_object_class: str = Field(
        default="group", description="Grup aramalarında kullanılacak objectClass"
    )
    computer_object_class: str = Field(
        default="computer", description="Bilgisayar nesneleri için objectClass"
    )

    @field_validator("user_object_class", "group_object_class", "computer_object_class")
    @classmethod
    def validate_object_classes(cls, v: Any) -> str:
        """Reject values that could break out of an LDAP filter (WR-05)."""
        return validate_object_class(v)

    @field_validator("server")
    @classmethod
    def validate_server(cls, v: str) -> str:
        """Validate server URL format."""
        if not v.startswith(("ldap://", "ldaps://")):
            raise ValueError("Server must start with ldap:// or ldaps://")
        return v


class OrganizationalUnitsConfig(BaseModel):
    """Organizational Units configuration."""

    model_config = ConfigDict(extra="forbid")

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

    model_config = ConfigDict(extra="forbid")

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

    @field_validator("vault_url")
    @classmethod
    def validate_vault_url(cls, v: str) -> str:
        """Validate Key Vault URL format."""
        if not v.startswith("https://"):
            raise ValueError("Key Vault URL must start with https://")
        return v


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class HttpAuthConfig(BaseModel):
    """Authentication settings for the HTTP transport."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    required: bool = Field(
        default=True, description="Require an API key on every HTTP request (default: true)"
    )
    api_key_sha256: List[str] = Field(
        default_factory=list,
        description=(
            "SHA-256 hex digests of accepted API keys. Plaintext keys are never read "
            "from the config file; supply them through the environment instead."
        ),
    )

    @field_validator("api_key_sha256")
    @classmethod
    def validate_digests(cls, v: List[str]) -> List[str]:
        """Require 64-char hex SHA-256 digests (lowered); never echo the offending value."""
        normalized: List[str] = []
        for index, entry in enumerate(v):
            lowered = entry.lower() if isinstance(entry, str) else ""
            if not _SHA256_HEX.match(lowered):
                raise ValueError(
                    f"api_key_sha256[{index}] must be a 64-character hex SHA-256 digest"
                )
            normalized.append(lowered)
        return normalized


class SecurityConfig(BaseModel):
    """Security configuration for LDAP connections and tool-call enforcement."""

    model_config = ConfigDict(extra="forbid")

    enable_tls: bool = Field(default=True, description="Enable TLS encryption")
    validate_certificate: bool = Field(default=True, description="Validate server certificate")
    ca_cert_file: Optional[str] = Field(default=None, description="CA certificate file path")
    require_secure_connection: bool = Field(default=True, description="Require secure connection")
    allow_writes: bool = Field(
        default=False,
        description="Permit write tools (create/modify/enable/disable/reset/move/membership)",
    )
    allow_destructive: bool = Field(
        default=False,
        description="Additionally permit destructive tools (delete_*); requires allow_writes",
    )
    max_list_results: int = Field(
        default=1000,
        ge=0,
        description=(
            "Maximum entries a list/search tool returns; 0 means unlimited (explicit opt-out)"
        ),
    )
    protect_privileged_targets: bool = Field(
        default=True,
        description=(
            "Refuse add/remove group member and reset password on privileged groups and "
            "accounts (Domain/Enterprise/Schema Admins, Administrators, operator groups, "
            "krbtgt, Administrator, adminCount=1); false is an explicit opt-out"
        ),
    )
    audit_log_path: Optional[str] = Field(
        default=None,
        description=(
            "JSON-lines audit file for write/destructive tool calls; None disables file audit"
        ),
    )
    audit_fail_closed: bool = Field(
        default=False,
        description=(
            "Refuse destructive calls (and write calls) when the audit intent record cannot "
            "be written; requires audit_log_path"
        ),
    )
    http_auth: HttpAuthConfig = Field(default_factory=HttpAuthConfig)

    @field_validator("audit_log_path")
    @classmethod
    def _audit_path_non_blank(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("security.audit_log_path must not be blank")
        return v

    @model_validator(mode="after")
    def _destructive_requires_writes(self) -> "SecurityConfig":
        if self.allow_destructive and not self.allow_writes:
            raise ValueError("security.allow_destructive requires security.allow_writes to be true")
        if self.audit_fail_closed and self.audit_log_path is None:
            raise ValueError("security.audit_fail_closed requires security.audit_log_path")
        return self


class LoggingConfig(BaseModel):
    """Logging configuration."""

    model_config = ConfigDict(extra="forbid")

    level: str = Field(default="INFO", description="Logging level")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format",
    )
    file: Optional[str] = Field(default=None, description="Log file path")

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Level must be one of: {valid_levels}")
        return v.upper()


class PerformanceConfig(BaseModel):
    """Performance configuration."""

    model_config = ConfigDict(extra="forbid")

    connection_pool_size: Optional[int] = Field(
        default=None,
        description=(
            "Deprecated and ignored: LDAPManager uses a single serialized connection. "
            "Still accepted so existing configurations keep loading."
        ),
    )
    max_retries: int = Field(default=3, description="Maximum connection retries")
    retry_delay: float = Field(default=1.0, description="Retry delay in seconds")
    page_size: int = Field(default=1000, description="LDAP search page size")

    @field_validator("connection_pool_size", "max_retries", "page_size")
    @classmethod
    def validate_positive_int(cls, v: Optional[int]) -> Optional[int]:
        """Validate positive integers."""
        if v is not None and v <= 0:
            raise ValueError("Value must be positive")
        return v

    @field_validator("retry_delay")
    @classmethod
    def validate_positive_float(cls, v: float) -> float:
        """Validate positive float."""
        if v <= 0:
            raise ValueError("Retry delay must be positive")
        return v


class Config(BaseModel):
    """Main configuration class."""

    model_config = ConfigDict(extra="forbid")

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
    def _fill_default_ous(cls, data: Any) -> Any:
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
