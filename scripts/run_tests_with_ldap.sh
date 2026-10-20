#!/usr/bin/env bash
# Start the local OpenLDAP lab, run the live integration suite, tear down.
# The lab is OpenLDAP, not Active Directory (see docker-compose-openldap.yml).
# Extra arguments are passed through to pytest (for example: -k test_user).
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose-openldap.yml"
CONFIG_DIR="$(mktemp -d)"
CONFIG_FILE="$CONFIG_DIR/lab_config.json"

# Throwaway password, generated per run and never written to the repo.
LAB_LDAP_PASSWORD="$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")"
export LAB_LDAP_PASSWORD

cleanup() {
  docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
}
trap cleanup EXIT

# The config loader resolves ${LAB_LDAP_PASSWORD} from the environment.
cat > "$CONFIG_FILE" <<'JSON'
{
  "active_directory": {
    "server": "ldap://127.0.0.1:389",
    "domain": "test.local",
    "base_dn": "DC=test,DC=local",
    "bind_dn": "CN=admin,DC=test,DC=local",
    "password": "${LAB_LDAP_PASSWORD}",
    "use_ssl": false,
    "auto_bind": true,
    "timeout": 30,
    "receive_timeout": 10,
    "user_object_class": "inetOrgPerson",
    "group_object_class": "groupOfNames",
    "computer_object_class": "device"
  },
  "organizational_units": {
    "users_ou": "ou=people,dc=test,dc=local",
    "groups_ou": "ou=groups,dc=test,dc=local",
    "computers_ou": "ou=computers,dc=test,dc=local",
    "service_accounts_ou": "ou=people,dc=test,dc=local"
  },
  "security": {
    "enable_tls": false,
    "validate_certificate": false,
    "require_secure_connection": false
  },
  "logging": {
    "level": "INFO"
  },
  "performance": {
    "connection_pool_size": 10,
    "max_retries": 3,
    "retry_delay": 1.0,
    "page_size": 1000
  }
}
JSON
chmod 600 "$CONFIG_FILE"

export AD_MCP_CONFIG="$CONFIG_FILE"

echo "Starting OpenLDAP lab container..."
docker compose -f "$COMPOSE_FILE" up -d openldap >/dev/null

echo "Waiting for LDAP port 389 (max 60s)..."
python3 - <<'PY'
import socket
import time

HOST, PORT = "127.0.0.1", 389
for _ in range(60):
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit("Timed out waiting for LDAP port 389.")
PY
# The port opens before the bootstrap LDIF import finishes.
sleep 5

echo "Lab is up. Running integration tests..."
cd "$PROJECT_ROOT"
set +e
uv run --locked pytest -m integration "$@"
TEST_EXIT=$?
set -e

echo "Tests finished (exit code $TEST_EXIT). Cleaning up."
exit "$TEST_EXIT"
