"""Azure Key Vault integration for secure credential retrieval.

Instead of storing the Active Directory service account password in plaintext
inside a configuration file, this module retrieves it at runtime from Azure
Key Vault using ``azure-identity``'s ``DefaultAzureCredential``.

``DefaultAzureCredential`` transparently supports, in order:
managed identity (recommended for Azure-hosted deployments), environment
variables (``AZURE_CLIENT_ID`` / ``AZURE_TENANT_ID`` / ``AZURE_CLIENT_SECRET``),
``az login`` (Azure CLI) for local development, and other standard Azure
credential sources.
"""

import logging
from functools import lru_cache

logger = logging.getLogger(__name__)


class KeyVaultError(RuntimeError):
    """Raised when a secret cannot be retrieved from Azure Key Vault."""


@lru_cache(maxsize=None)
def _get_client(vault_url: str):
    """Build (and cache) a SecretClient for the given vault URL."""
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise KeyVaultError(
            "Azure Key Vault support requires the 'azure-identity' and "
            "'azure-keyvault-secrets' packages. Install them with: "
            "pip install azure-identity azure-keyvault-secrets"
        ) from exc

    credential = DefaultAzureCredential()
    return SecretClient(vault_url=vault_url, credential=credential)


def get_secret(vault_url: str, secret_name: str) -> str:
    """
    Retrieve a secret's current value from Azure Key Vault.

    Args:
        vault_url: The Key Vault URL, e.g. https://your-vault.vault.azure.net/
        secret_name: Name of the secret to retrieve.

    Returns:
        The secret value.

    Raises:
        KeyVaultError: If the secret cannot be retrieved.
    """
    try:
        client = _get_client(vault_url)
        secret = client.get_secret(secret_name)
    except KeyVaultError:
        raise
    except Exception as exc:
        raise KeyVaultError(
            f"Failed to retrieve secret '{secret_name}' from Key Vault '{vault_url}': {exc}"
        ) from exc

    if not secret.value:
        raise KeyVaultError(f"Secret '{secret_name}' in Key Vault '{vault_url}' is empty")

    return secret.value
