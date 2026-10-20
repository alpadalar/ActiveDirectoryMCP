# Manual smoke scripts

These scripts are manual aids. They are not collected by pytest (no `test_*` names) and are not part of CI.

Install the dev dependencies first (`requests` is in the dev extra):

```bash
uv sync --all-extras
```

## http_server_smoke.py

Exercises a running ActiveDirectoryMCP HTTP server.

```bash
# default URL: http://localhost:8813/activedirectory-mcp
uv run python tests/manual/http_server_smoke.py

# custom URL
uv run python tests/manual/http_server_smoke.py http://your-server:8813/activedirectory-mcp
```

Note: the server now also exposes an unauthenticated `GET /health` liveness route. This script still targets the MCP `health` tool and is unaffected by it. It predates the Phase 4 HTTP authentication, so it is a manual smoke aid only and may need updating once that lands.

## real_ad_smoke.py

Connects to a real directory using the config named by `AD_MCP_CONFIG` and lists a few users. It never prints the bind password.

```bash
export AD_MCP_CONFIG=ad-config/config.json   # copy from ad-config/config.example.json
uv run python tests/manual/real_ad_smoke.py
```

For automated checks use `uv run pytest` (unit) and `scripts/run_tests_with_ldap.sh` (OpenLDAP integration lab).
