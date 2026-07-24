#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose-ad.yml"
CONFIG_DIR="$PROJECT_ROOT/.tmp-ad-config"
CONFIG_FILE="$CONFIG_DIR/test_config.json"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$CONFIG_DIR"
}
trap cleanup EXIT

mkdir -p "$CONFIG_DIR"

cat > "$CONFIG_FILE" <<'JSON'
{
  "active_directory": {
    "server": "ldap://127.0.0.1:389",
    "domain": "test.local",
    "base_dn": "DC=test,DC=local",
    "bind_dn": "CN=admin,DC=test,DC=local",
    "password": "Admin123!",
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

export AD_MCP_CONFIG="$CONFIG_FILE"

echo "➡️  OpenLDAP konteyneri başlatılıyor..."
docker compose -f "$COMPOSE_FILE" up -d openldap-ad >/dev/null

echo "⏳ LDAP 389 portu hazır olana kadar bekleniyor..."
python - <<'PY'
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
    raise SystemExit("LDAP portu 389 beklenirken zaman aşımı oluştu.")
PY

echo "✅ LDAP hazır. Testler başlatılıyor..."
(cd "$PROJECT_ROOT" && PYTHONPATH=src pytest "$@")
TEST_EXIT=$?

echo "🧹 Testler tamamlandı, Docker kaynakları temizleniyor..."
cleanup
trap - EXIT

exit $TEST_EXIT

