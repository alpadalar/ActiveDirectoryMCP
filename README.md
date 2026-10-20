# ActiveDirectoryMCP

A Model Context Protocol (MCP) server that exposes Active Directory (LDAP) administration and
auditing to MCP clients such as Claude Desktop, Claude Code and Cursor. It offers 45 tools for
users, groups, computers, organizational units, domain security reporting and server diagnostics,
over stdio or authenticated HTTP.

Status: the repository is public; the v1.0.0 release is not tagged yet. The
server is tested against a mocked LDAP harness (unit and end-to-end tests) and against an OpenLDAP
lab, which is not Active Directory. Checks against a live Active Directory domain are the
responsibility of the operator before relying on it in production.

## What it does and what it does not do by default

- Read tools (list, get, report, audit, diagnostics) work out of the box.
- The server is read-only by default. Create, modify, enable, disable, reset and membership tools
  are refused until `security.allow_writes` is true. Delete tools additionally need
  `security.allow_destructive`.
- The HTTP transport refuses to start without an API key and answers `401` to every request that
  does not present one (only `GET /health` is open).
- List and report tools return at most `security.max_list_results` entries (default 1000).
- Outbound connections go only to the directory server you configure and, if you configure Azure Key
  Vault, to Azure Key Vault and the Azure identity endpoints. Logs and the optional audit file are
  written locally.

## Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- Network access to a domain controller; LDAPS is strongly recommended
- A dedicated service account with the minimum rights you need (see Service account below)
- Docker, only for the container deployment

## Quickstart (stdio)

```bash
git clone https://github.com/alpadalar/ActiveDirectoryMCP.git
cd ActiveDirectoryMCP
uv sync --locked                 # add --extra azure for Azure Key Vault support
uv run pytest -q                 # optional: unit tests, no directory needed
cp ad-config/config.example.json ad-config/ad-config.json
```

Edit `ad-config/ad-config.json` before the first start: set `active_directory.server`, `domain`,
`base_dn` and `bind_dn` for your domain. The example uses `ldaps://` URLs, which
`security.require_secure_connection` (true by default) requires; for an internal CA add
`security.ca_cert_file` with the path of your CA certificate (see [TLS](#tls)), otherwise the
system trust store is used. The example contains no `key_vault` section; add one only if you use Azure Key Vault. With
the placeholder host names it starts but cannot connect to a directory until you edit it.

Provide the bind credential through the environment (or Key Vault, see
[Credentials](#credentials)) and start the server:

```bash
export AD_BIND_DN='CN=service-account,OU=Service Accounts,DC=example,DC=com'
read -rs AD_PASSWORD && export AD_PASSWORD     # type the password, it is not echoed
AD_MCP_CONFIG=ad-config/ad-config.json uv run activedirectory-mcp
```

The stdio server speaks MCP on stdin/stdout, so it waits for a client and prints log lines on the
console. It has no `--help`; the only required setting is the `AD_MCP_CONFIG` environment variable.
Connect it from an MCP client as shown in [Connect an MCP client](#connect-an-mcp-client).

A failed initial directory connection is logged but does not stop the server, so the tool list is
available even when the domain controller cannot be reached; tool calls then return errors.

## Run over HTTP

The HTTP transport requires an API key. Generate one and export it:

```bash
export AD_MCP_HTTP_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export AD_BIND_DN='CN=service-account,OU=Service Accounts,DC=example,DC=com'
read -rs AD_PASSWORD && export AD_PASSWORD
AD_MCP_CONFIG=ad-config/ad-config.json uv run python -m active_directory_mcp.server_http \
  --host 127.0.0.1 --port 8813 --path /activedirectory-mcp
```

Flags: `--host` (default `0.0.0.0`), `--port` (default `8813`), `--path` (default
`/activedirectory-mcp`), `--config` (overrides `AD_MCP_CONFIG`). Binding to `127.0.0.1` is the safe
choice on a workstation; the default `0.0.0.0` listens on every interface.

Check the server (the endpoint accepts either header):

```bash
curl -s http://127.0.0.1:8813/health                       # 200, no key needed
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8813/activedirectory-mcp   # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $AD_MCP_HTTP_API_KEY" \
  http://127.0.0.1:8813/activedirectory-mcp                 # not 401 (a plain GET gets 406)
curl -s -o /dev/null -w '%{http_code}\n' -H "X-API-Key: $AD_MCP_HTTP_API_KEY" \
  http://127.0.0.1:8813/activedirectory-mcp                 # not 401
```

`/health` returns `{"status", "server", "version"}`, performs no LDAP query and reveals no
hostnames or credentials. For an LDAP-aware status call the `health` or `test_connection` tool
through an MCP client. To avoid keeping the plaintext key in the server environment, supply its
SHA-256 digest instead; see [Security configuration](#security-configuration).

The launcher scripts `start_server.sh`, `start_http_server.sh` and their `.bat` equivalents load a
`.env` file (template: [`.env.example`](.env.example)) and start the same entry points. They print
progress messages to stdout, so do not use `start_server.sh` as an MCP client command: use the
`uv run activedirectory-mcp` commands shown below.

## Docker

```bash
docker build -t activedirectory-mcp .
```

The image runs the HTTP server as a non-root user on port 8813. It exits immediately with
instructions if no API key is configured.

With Compose, which mounts `./ad-config` read-only and refuses to start without a key:

```bash
export AD_MCP_HTTP_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
cp ad-config/config.example.json ad-config/ad-config.json     # then edit it as described above
export AD_BIND_DN='CN=service-account,OU=Service Accounts,DC=example,DC=com'
read -rs AD_PASSWORD && export AD_PASSWORD                     # not echoed; skip both with Key Vault
docker compose up -d
docker compose ps
curl -sf http://127.0.0.1:8813/health
```

Compose passes `AD_BIND_DN` and `AD_PASSWORD` from your shell (or a `.env` file next to
`docker-compose.yml`) into the container. Without them, and without Key Vault, the server exits at
startup with "No AD bind password available" and `restart: unless-stopped` keeps retrying, so check
`docker compose logs` if `/health` does not answer. For Azure Key Vault, uncomment the
`AZURE_KEYVAULT_*` lines in `docker-compose.yml` instead and leave `AD_PASSWORD` unset; the
plaintext variable is visible in `docker inspect`, so prefer Key Vault. Do not bake secrets into the
image or the config file. The HTTP address inside the container is fixed (`0.0.0.0:8813`); change the
published port in `ports`, not an environment variable.

Verification note: `docker build`, the fail-fast start without a key, `/health`, the `401` without a
key and acceptance of both key headers were exercised against a container without a reachable
directory. `docker compose up` against a real domain controller was not verified here.

## Connect an MCP client

Create the config file first (see Quickstart). The bind password must not be written into a file
that is committed or shared. Complete examples are in [`examples/`](examples/).

### Claude Desktop (stdio)

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows:
`%APPDATA%\Claude\`; the Linux location is not covered by the official documentation):

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP": {
            "command": "uv",
            "args": ["--directory", "/absolute/path/to/ActiveDirectoryMCP", "run", "activedirectory-mcp"],
            "env": {
                "AD_MCP_CONFIG": "/absolute/path/to/ActiveDirectoryMCP/ad-config/ad-config.json",
                "AD_BIND_DN": "CN=service-account,OU=Service Accounts,DC=example,DC=com",
                "AD_PASSWORD": "REPLACE_WITH_BIND_PASSWORD"
            }
        }
    }
}
```

Claude Desktop does not document environment-variable interpolation, so the `env` block holds the
value literally in a local file. Prefer Azure Key Vault (leave `AD_PASSWORD` out and configure
`key_vault`) so no password is stored. If `uv` is not found, use its absolute path as `command`.

### Claude Code

Stdio (the command after `--` is the server; `-e` sets its environment, `-s` the scope):

```bash
claude mcp add activedirectory -e AD_MCP_CONFIG="$PWD/ad-config/ad-config.json" \
  -e AD_BIND_DN="$AD_BIND_DN" -e AD_PASSWORD="$AD_PASSWORD" \
  -- uv --directory "$PWD" run activedirectory-mcp
```

Streamable HTTP with the API key header:

```bash
claude mcp add --transport http activedirectory http://localhost:8813/activedirectory-mcp \
  --header "Authorization: Bearer $AD_MCP_HTTP_API_KEY"
```

`claude mcp add` stores the values you pass in your Claude Code configuration. To keep secrets out
of it, commit a project-scoped `.mcp.json` instead, which expands `${VAR}` in `command`, `args`,
`env`, `url` and `headers`:

```json
{
    "mcpServers": {
        "activedirectory-stdio": {
            "type": "stdio",
            "command": "uv",
            "args": ["--directory", "${CLAUDE_PROJECT_DIR:-.}", "run", "activedirectory-mcp"],
            "env": {
                "AD_MCP_CONFIG": "${CLAUDE_PROJECT_DIR:-.}/ad-config/ad-config.json",
                "AD_BIND_DN": "${AD_BIND_DN}",
                "AD_PASSWORD": "${AD_PASSWORD}"
            }
        },
        "activedirectory-http": {
            "type": "http",
            "url": "http://localhost:8813/activedirectory-mcp",
            "headers": {
                "Authorization": "Bearer ${AD_MCP_HTTP_API_KEY}"
            }
        }
    }
}
```

The `claude mcp add` flags above were confirmed with `claude mcp add --help`; the commands were not
executed here because they change the operator's Claude Code configuration.

### Cursor

Put this in `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global). Cursor resolves
`${env:NAME}` in `command`, `args`, `env`, `url` and `headers`:

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP": {
            "command": "uv",
            "args": ["--directory", "/absolute/path/to/ActiveDirectoryMCP", "run", "activedirectory-mcp"],
            "env": {
                "AD_MCP_CONFIG": "/absolute/path/to/ActiveDirectoryMCP/ad-config/ad-config.json",
                "AD_BIND_DN": "${env:AD_BIND_DN}",
                "AD_PASSWORD": "${env:AD_PASSWORD}"
            }
        }
    }
}
```

For an HTTP server started as described above:

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP-HTTP": {
            "url": "http://localhost:8813/activedirectory-mcp",
            "headers": {
                "Authorization": "Bearer ${env:AD_MCP_HTTP_API_KEY}"
            }
        }
    }
}
```

## Security configuration

Write access and the HTTP transport are locked down by default. Example (placeholder values only):

```json
{
    "security": {
        "allow_writes": false,
        "allow_destructive": false,
        "max_list_results": 1000,
        "protect_privileged_targets": true,
        "audit_log_path": "/var/log/ad-mcp/audit.jsonl",
        "http_auth": {
            "required": true,
            "api_key_sha256": ["0000000000000000000000000000000000000000000000000000000000000000"]
        }
    }
}
```

- `security.allow_writes` enables create, modify, enable, disable, reset, move and membership tools;
  `security.allow_destructive` additionally enables the delete tools and requires `allow_writes`.
  Refused calls return a structured error (`write_blocked` or `destructive_blocked`) naming the
  setting to change.
- `security.max_list_results` caps list and report tools (0 = unlimited); responses include
  `truncated` and `result_limit`. The audit tools (`get_inactive_users`,
  `get_password_policy_violations`, `get_stale_computers`) scan the whole directory and cap only
  the findings they return.
- `security.protect_privileged_targets` (default true) makes `add_group_member`,
  `remove_group_member` and `reset_user_password` refuse privileged groups and accounts
  (Domain/Enterprise/Schema Admins, Administrators, operator groups, `krbtgt`, `Administrator`,
  anything with `adminCount=1`). Set it to false only if you accept that anyone with
  `allow_writes` can change them.
- `security.audit_log_path` (default unset) writes one JSON line per write or destructive tool call
  (timestamp, tool, risk, target, outcome, redacted arguments; no passwords) to a file opened in append mode
  with mode `0600` (the service user can still truncate or delete it; use `chattr +a` or ship the
  lines elsewhere if you need tamper resistance). The server refuses to start if the path cannot be opened and logs a
  warning when `allow_writes` is true without a path. Destructive calls also write an `intent`
  record first; HTTP calls add an `actor`.
- `security.audit_fail_closed` (default false, needs `audit_log_path`) refuses write and destructive
  calls when the audit record cannot be written, instead of running them unaudited.
- `security.http_auth.required` (default true) keeps the API key mandatory. Setting it to false
  disables HTTP authentication entirely; this is unsafe and only suitable for an isolated test.
- `security.require_secure_connection` (default true) rejects non-LDAPS connection settings at
  startup. Password tools (`create_user` with a password, `reset_user_password`,
  `reset_computer_password`) additionally require an LDAPS or StartTLS connection and are refused
  otherwise.
- `reset_user_password` and `reset_computer_password` return the new password in the response;
  treat it as sensitive and do not log it client-side. `reset_computer_password` breaks the
  machine's secure channel, so the machine must be rejoined or re-synced.
- `modify_*` tools accept only allow-listed attributes (security-sensitive ones such as
  `userAccountControl`, `servicePrincipalName` and `gPLink` are always rejected). Every DN a tool
  receives must lie inside the configured `base_dn`.

Generate and hash an HTTP API key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"      # the key
python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '<key>'
```

Provide the key through `AD_MCP_HTTP_API_KEY`, or only its digest through
`AD_MCP_HTTP_API_KEY_SHA256` (comma-separated for several keys) or `security.http_auth.api_key_sha256`.
Plaintext keys are never read from the config file. Clients send `Authorization: Bearer <key>` or
`X-API-Key: <key>`.

## Tools

45 tools. The risk column is what `security.allow_writes` and `security.allow_destructive`
enforce: read tools always run, write tools need `allow_writes`, destructive tools need both
settings.

### Users

| Tool | Risk | Description |
|---|---|---|
| `list_users` | read | List users with optional filtering |
| `get_user` | read | Detailed information about one user |
| `get_user_groups` | read | Groups a user is a member of |
| `create_user` | write | Create a user account |
| `modify_user` | write | Modify allow-listed user attributes |
| `enable_user` | write | Enable a user account |
| `disable_user` | write | Disable a user account |
| `reset_user_password` | write | Reset a password, optionally generated (returned in the response) |
| `delete_user` | destructive | Delete a user account |

### Groups

| Tool | Risk | Description |
|---|---|---|
| `list_groups` | read | List groups with filtering |
| `get_group` | read | Detailed information about one group |
| `get_group_members` | read | Members of a group, optionally recursive |
| `get_nested_group_members` | read | All direct and nested members through a server-side chain query |
| `create_group` | write | Create a security or distribution group |
| `modify_group` | write | Modify group attributes |
| `add_group_member` | write | Add a member to a group |
| `remove_group_member` | write | Remove a member from a group |
| `delete_group` | destructive | Delete a group |

### Computers

| Tool | Risk | Description |
|---|---|---|
| `list_computers` | read | List computer accounts |
| `get_computer` | read | Detailed information about one computer |
| `get_stale_computers` | read | Computers that have not logged on for a number of days |
| `create_computer` | write | Create a computer object |
| `modify_computer` | write | Modify computer attributes |
| `enable_computer` | write | Enable a computer account |
| `disable_computer` | write | Disable a computer account |
| `reset_computer_password` | write | Reset a computer account password (returned in the response) |
| `delete_computer` | destructive | Delete a computer object |

### Organizational units

| Tool | Risk | Description |
|---|---|---|
| `list_organizational_units` | read | List OUs with hierarchy |
| `get_organizational_unit` | read | Detailed information about one OU |
| `get_organizational_unit_contents` | read | Objects inside an OU |
| `create_organizational_unit` | write | Create an OU |
| `modify_organizational_unit` | write | Modify OU attributes |
| `move_organizational_unit` | write | Move an OU to a new parent |
| `delete_organizational_unit` | destructive | Delete an OU (also when empty) |

### Security and audit

| Tool | Risk | Description |
|---|---|---|
| `get_domain_info` | read | Domain information and security settings |
| `get_privileged_groups` | read | Privileged group analysis |
| `get_user_permissions` | read | Effective permissions of a user |
| `get_inactive_users` | read | Users that have not logged on for a number of days |
| `get_password_policy_violations` | read | Users violating password policy |
| `audit_admin_accounts` | read | Administrative account audit |

### Diagnostics

| Tool | Risk | Description |
|---|---|---|
| `test_connection` | read | LDAP connectivity test |
| `health` | read | Server health, including the LDAP state |
| `get_schema_info` | read | Schema information for all tools |
| `get_rootdse_info` | read | rootDSE details of the answering domain controller |
| `get_tls_posture` | read | Configured TLS settings, the live channel (ldaps, starttls, plaintext) and findings |

Some LLM clients degrade when many tools are in context; that is a client limit, not a server one.

## Configuration reference

### Credentials

The service account name and password are resolved in this order: Azure Key Vault, then the
`AD_BIND_DN` and `AD_PASSWORD` environment variables, then values in the config file (a plaintext
`password` there logs a deprecation warning). Startup fails with a clear error if no password can
be resolved.

Azure Key Vault is an optional extra (`uv sync --locked --extra azure`):

```json
{
    "key_vault": {
        "vault_url": "https://your-keyvault-name.vault.azure.net/",
        "username_secret_name": "ad-bind-username",
        "password_secret_name": "ad-bind-password"
    }
}
```

The same can be set with `AZURE_KEYVAULT_URL`, `AZURE_KEYVAULT_SECRET_USERNAME` and
`AZURE_KEYVAULT_SECRET_PASSWORD` (see [`.env.example`](.env.example)). Authentication uses
`DefaultAzureCredential`: a managed identity (recommended in Azure), the service principal
variables `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`, or `az login` for local
use. Grant the identity permission to read secrets only. `username_secret_name` is optional; without
it the `bind_dn` from the config file is used.

### Default organizational units

`organizational_units` sets where `create_computer` and `create_group` place objects when no `ou`
is passed. It is optional: missing entries default to the built-in containers under `base_dn`
(`CN=Computers,<base_dn>` for computers, `CN=Users,<base_dn>` otherwise).

### TLS

```json
{
    "security": {
        "enable_tls": true,
        "validate_certificate": true,
        "ca_cert_file": "/path/to/ca-certificate.pem",
        "require_secure_connection": true
    }
}
```

Keep certificate validation on. Use `ca_cert_file` for an internal CA. `get_tls_posture` reports the
effective settings of a running server.

### Performance

```json
{
    "performance": {
        "max_retries": 3,
        "retry_delay": 1.0,
        "page_size": 1000
    }
}
```

`connection_pool_size` is deprecated and ignored; it is accepted only so older configuration files
keep loading.

### Service account

Create a dedicated account with the minimum rights for the tools you enable. Read-only use needs
read access to the relevant subtrees only. Keep `allow_writes` off unless you need it, and delegate
write permissions on specific OUs rather than using a domain admin.

## Testing

Details are in [TESTING_GUIDE.md](TESTING_GUIDE.md).

```bash
uv run pytest -q                    # unit and end-to-end tests with a mocked directory
scripts/run_tests_with_ldap.sh      # live tests against the OpenLDAP lab (needs Docker)
```

Unit tests mock ldap3 and never connect to a directory; integration tests are deselected by default.
The lab (`docker-compose-openldap.yml`) is OpenLDAP, not Active Directory: it does not enforce
`userAccountControl`, `unicodePwd` TLS rules, `lastLogon` replication or AD ACLs. It needs a
throwaway `LAB_LDAP_PASSWORD`, which the script generates per run. The lab client configuration is
[`ad-config/openldap-lab.example.json`](ad-config/openldap-lab.example.json); an example Cursor entry
is in `examples/cursor_openldap_config.json`.

Manual smoke scripts live in `tests/manual/` (`http_server_smoke.py` needs a running HTTP server;
`real_ad_smoke.py` needs `AD_MCP_CONFIG` pointing at a real directory).

## Troubleshooting

- HTTP server exits at start with "requires an API key": set `AD_MCP_HTTP_API_KEY` (or the SHA-256
  digest variable) as shown above.
- `Secure connection required but server URL is not ldaps://`: use an `ldaps://` server URL or, for
  a lab only, set `security.require_secure_connection` to false.
- `invalid CA public key file`: `security.ca_cert_file` points at a missing file; fix or remove it.
- Failed to retrieve a secret from Key Vault: configure the vault correctly or delete the
  `key_vault` section when using `AD_BIND_DN` and `AD_PASSWORD`.
- `write_blocked` or `destructive_blocked` in a tool response: the server is read-only by default;
  set `security.allow_writes` (and `security.allow_destructive` for deletes) deliberately.
- Errors mentioning a DN outside the base DN: the DN passed to a tool must be inside
  `active_directory.base_dn`.
- LDAPS certificate errors: check the chain with `openssl s_client -connect dc.example.com:636
  -showcerts` and point `security.ca_cert_file` at your CA.
- Connectivity: `ldapsearch -H ldaps://dc.example.com -D "<bind DN>" -W -b "<base DN>"
  "(objectClass=domain)"`, then the `test_connection` and `get_tls_posture` tools.
- Port 8813 busy: pass `--port` or set `HTTP_PORT` for the launcher scripts.
- Logs: `docker logs -f activedirectory-mcp` for the container; otherwise the file set in
  `logging.file`.

## Project structure

```
src/active_directory_mcp/   server code (registry, policy, audit, auth, tools/, config/, core/)
tests/                      unit, e2e, integration, golden and manual tests
ad-config/                  example configurations (your ad-config.json stays untracked)
examples/                   MCP client configuration examples
ldap-init/                  OpenLDAP lab seed data
scripts/                    helper scripts
Dockerfile, docker-compose.yml, docker-compose-openldap.yml
pyproject.toml, uv.lock
```

Tools are declared once in `src/active_directory_mcp/registry.py` and served by both transports.

## Contributing, security and license

- [CONTRIBUTING.md](CONTRIBUTING.md) explains how to propose changes.
- [SECURITY.md](SECURITY.md) explains how to report a vulnerability.
- [CHANGELOG.md](CHANGELOG.md) lists user-visible changes, including breaking ones.
- Licensed under the MIT License, see [LICENSE](LICENSE).

## Related projects

- [ProxmoxMCP-Extended](https://github.com/alpadalar/ProxmoxMCP-Extended), the project this one was
  inspired by
- [Model Context Protocol](https://github.com/modelcontextprotocol)
- [FastMCP](https://github.com/modelcontextprotocol/fastmcp)
