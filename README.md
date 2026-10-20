# ActiveDirectoryMCP - Enhanced Active Directory MCP Server

A comprehensive Python-based Model Context Protocol (MCP) server for managing Active Directory environments through LDAP. This project provides powerful tools for user management, group operations, computer account management, organizational unit administration, and security auditing.

## 🚀 Features

### 👥 **Complete User Management**
- Create, modify, and delete user accounts
- Password management and reset functionality
- Enable/disable user accounts
- Group membership analysis
- User permission auditing

### 🔐 **Advanced Group Management**
- Create and manage security and distribution groups
- Group scope management (Global, DomainLocal, Universal)
- Member addition and removal
- Nested group analysis
- Group membership reporting

### 💻 **Computer Account Management**
- Create and manage computer objects
- Computer account lifecycle management
- Stale computer detection
- Computer group memberships
- Service Principal Name management

### 🏢 **Organizational Unit Operations**
- Create, modify, and delete OUs
- OU hierarchy management
- Move objects between OUs
- OU content analysis
- Group Policy link information

### 🛡️ **Security and Audit Tools**
- Domain security policy analysis
- Privileged group monitoring
- Inactive user detection
- Password policy compliance checking
- Administrative account auditing
- Permission analysis and reporting

### 🌐 **Multiple Transport Options**
- **Stdio Transport**: Traditional MCP communication
- **HTTP Transport**: FastMCP-based HTTP transport on port 8813
- **Docker Deployment**: Production-ready containerization
- **MCP Inspector**: Compatible with debugging tools

### 🧪 **Quality Assurance**
- **Unit tests**: mocked ldap3, no server needed (`uv run pytest`)
- **Integration tests**: run against a local OpenLDAP lab (`scripts/run_tests_with_ldap.sh`); the lab is OpenLDAP, not Active Directory
- **Manual smoke scripts**: `tests/manual/`

## 📋 Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- Access to Active Directory with appropriate permissions
- LDAP/LDAPS connectivity to domain controllers

## 🛠️ Installation

### Option 1: Quick Install (Recommended)

1. **Clone and set up environment:**
   ```bash
   # Clone repository
   git clone https://github.com/alpadalar/ActiveDirectoryMCP.git
   cd ActiveDirectoryMCP

   ```

2. **Install dependencies:**
   ```bash
   # Install everything from uv.lock (dev tools and the Azure Key Vault extra)
   uv sync --all-extras

   # Or only what you need: runtime only is `uv sync`;
   # Azure Key Vault support needs `uv sync --extra azure`;
   # dev tools need `uv sync --extra dev`
   ```

3. **Create configuration:**
   ```bash
   # Create config directory and copy template
   mkdir -p ad-config
   cp ad-config/config.example.json ad-config/config.json
   ```

4. **Configure Active Directory connection:**
   ```json
   {
       "active_directory": {
           "server": "ldaps://dc.example.com:636",
           "domain": "example.com",
           "base_dn": "DC=example,DC=com",
           "bind_dn": "CN=service-account,OU=Service Accounts,DC=example,DC=com"
       },
       "key_vault": {
           "vault_url": "https://your-keyvault-name.vault.azure.net/",
           "username_secret_name": "ad-bind-username",
           "password_secret_name": "ad-bind-password"
       },
       "organizational_units": {
           "users_ou": "OU=Users,DC=example,DC=com",
           "groups_ou": "OU=Groups,DC=example,DC=com",
           "computers_ou": "OU=Computers,DC=example,DC=com",
           "service_accounts_ou": "OU=Service Accounts,DC=example,DC=com"
       }
   }
   ```

   > The `organizational_units` section sets the default location for
   > `create_computer` / `create_group` when no `ou` is passed. It is optional:
   > any missing entry defaults to the built-in container under `base_dn`
   > (`CN=Computers,<base_dn>` for computers, `CN=Users,<base_dn>` otherwise).

   > **🔐 Never store the service account password in plaintext.** The
   > `password` field is optional and only intended as a last-resort local
   > fallback. See [Credential Storage with Azure Key Vault](#-credential-storage-with-azure-key-vault)
   > below for the recommended setup.

### Verifying Installation

```bash
# Test configuration
uv run python -c "import active_directory_mcp; print('Installation OK')"

# Run unit tests (no server needed)
uv run pytest

# Test LDAP connection
AD_MCP_CONFIG="ad-config/ad-config.json" uv run python -m active_directory_mcp.server
```

## 🚀 Running the Server

### 🏭 Production Deployment

Deploy to production with existing Active Directory:

```bash
# 1. Configure for your AD environment
cp ad-config/production-config.example.json ad-config/ad-config.json
# Edit ad-config.json with your AD server details

# 2. Deploy ActiveDirectoryMCP
docker compose up -d

# 3. Verify deployment
docker compose ps
docker compose logs activedirectory-mcp
```

**🌐 Production URL:** `http://localhost:8813/activedirectory-mcp`

**Production Features:**
- ✅ Connects to existing AD infrastructure
- ✅ SSL/TLS security
- ✅ Resource limits & health checks
- ✅ Production logging

### 🧪 Development/Test Environment

For development with the included OpenLDAP lab (not Active Directory: no
userAccountControl, unicodePwd or AD ACL semantics):

```bash
# 1. Start the lab (any throwaway password)
export LAB_LDAP_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
docker compose -f docker-compose-openldap.yml up -d

# 2. Run the live integration tests (starts and tears down its own lab)
scripts/run_tests_with_ldap.sh

# 3. Access services
# - ActiveDirectoryMCP: http://localhost:8813/activedirectory-mcp
# - LDAP Admin: http://localhost:8080
```

**Test Features:**
- ✅ Includes an OpenLDAP lab server (not Active Directory)
- ✅ Pre-configured test data
- ✅ Web-based LDAP management
- ✅ No external AD required

### Development Mode (Stdio)

For testing and development with stdio transport:

```bash
# Linux/macOS
./start_server.sh

# Windows
start_server.bat

# Or with custom config
AD_MCP_CONFIG="ad-config/ad-config.json" python -m active_directory_mcp.server
```

### HTTP Mode (Local Development)

For local HTTP transport development:

```bash
# Linux/macOS
./start_http_server.sh

# Windows
start_http_server.bat

# Or with custom settings
python -m active_directory_mcp.server_http --host 0.0.0.0 --port 8813 --path /activedirectory-mcp
```

### ⚙️ Configuring via a `.env` file

`start_server.sh` / `start_server.bat` and `start_http_server.sh` /
`start_http_server.bat` all automatically load a `.env` file from the project
root, if one exists, before starting the server. This is the easiest way to
set the Azure Key Vault / service principal variables described below
without exporting them manually every session.

```bash
# 1. Copy the template
cp .env.example .env        # Linux/macOS
copy .env.example .env      # Windows

# 2. Edit .env and fill in your real values (vault URL, secret names,
#    AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET, ...)

# 3. Just run the launcher - it picks up .env automatically
./start_server.sh           # Linux/macOS
start_server.bat            # Windows
```

`.env` is listed in `.gitignore` and must never be committed - it's meant to
hold real secrets locally (or be provided some other way in production, e.g.
via `docker-compose.yml`'s `environment:` section or your platform's secret
manager).

## 🔧 Cursor/VS Code Integration

### Option 1: Docker Compose (Recommended)

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP": {
            "transport": {
                "type": "http",
                "url": "http://localhost:8813/activedirectory-mcp"
            },
            "description": "Active Directory Management with HTTP Transport"
        }
    }
}
```

### Option 2: Local HTTP Server

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP-Local": {
            "transport": {
                "type": "http",
                "url": "http://localhost:8813/activedirectory-mcp"
            },
            "description": "ActiveDirectoryMCP Local Development"
        }
    }
}
```

### Option 3: Traditional Stdio (Legacy)

```json
{
    "mcpServers": {
        "ActiveDirectoryMCP": {
            "command": "/absolute/path/to/ActiveDirectoryMCP/.venv/bin/python",
            "args": ["-m", "active_directory_mcp.server"],
            "cwd": "/absolute/path/to/ActiveDirectoryMCP",
            "env": {
                "PYTHONPATH": "/absolute/path/to/ActiveDirectoryMCP/src",
                "AD_MCP_CONFIG": "/absolute/path/to/ActiveDirectoryMCP/ad-config/ad-config.json"
            },
            "disabled": false
        }
    }
}
```

## 📚 Available Tools & Operations

### 👥 User Management
- `list_users` - List users with filtering and attributes
- `get_user` - Get detailed user information
- `create_user` - Create new user accounts
- `modify_user` - Update user attributes
- `delete_user` - Remove user accounts
- `enable_user` / `disable_user` - Account status management
- `reset_user_password` - Password reset functionality
- `get_user_groups` - Group membership analysis

### 🔐 Group Management
- `list_groups` - List groups with filtering
- `get_group` - Get detailed group information
- `create_group` - Create security/distribution groups
- `modify_group` - Update group attributes
- `delete_group` - Remove groups
- `add_group_member` / `remove_group_member` - Membership management
- `get_group_members` - Member listing with recursion

### 💻 Computer Management
- `list_computers` - List computer accounts
- `get_computer` - Get computer details
- `create_computer` - Create computer objects
- `modify_computer` - Update computer attributes
- `delete_computer` - Remove computer accounts
- `enable_computer` / `disable_computer` - Account management
- `reset_computer_password` - Password reset
- `get_stale_computers` - Find inactive computers

### 🏢 Organizational Unit Management
- `list_organizational_units` - List OUs with hierarchy
- `get_organizational_unit` - Get OU details
- `create_organizational_unit` - Create new OUs
- `modify_organizational_unit` - Update OU attributes
- `delete_organizational_unit` - Remove OUs
- `move_organizational_unit` - Move OUs
- `get_organizational_unit_contents` - List OU contents

### 🛡️ Security & Audit
- `get_domain_info` - Domain security settings
- `get_privileged_groups` - Privileged group analysis
- `get_user_permissions` - User permission analysis
- `get_inactive_users` - Inactive user detection
- `get_password_policy_violations` - Policy compliance
- `audit_admin_accounts` - Administrative account audit
- `get_nested_group_members` - All direct and nested group members (server-side chain query)
- `get_rootdse_info` - rootDSE details of the answering domain controller

### 🔧 System Tools
- `test_connection` - LDAP connectivity test
- `health` - Server health check
- `get_schema_info` - Tool schema information
- `get_tls_posture` - Configured TLS settings, live channel (ldaps/starttls/plaintext) and findings

> **⚠️ Note**: ActiveDirectoryMCP provides 45 tools total. Some LLM models may experience issues with this many tools.

## 🔒 Security Configuration

### 🔑 Credential Storage with Azure Key Vault

ActiveDirectoryMCP never requires the bind username or password to be stored
in plaintext. Instead, configure Azure Key Vault and both are retrieved at
startup. Key Vault support is an optional extra: install it with
`uv sync --extra azure` (or `uv sync --all-extras`).

1. **Create secrets in Key Vault** holding the service account username (bind DN)
   and password:
   ```bash
   az keyvault secret set \
     --vault-name your-keyvault-name \
     --name ad-bind-username \
     --value "CN=service-account,OU=Service Accounts,DC=example,DC=com"

   az keyvault secret set \
     --vault-name your-keyvault-name \
     --name ad-bind-password \
     --value "YourSecureServiceAccountPassword"
   ```

2. **Reference the vault in your configuration file:**
   ```json
   {
       "key_vault": {
           "vault_url": "https://your-keyvault-name.vault.azure.net/",
           "username_secret_name": "ad-bind-username",
           "password_secret_name": "ad-bind-password"
       }
   }
   ```
   Alternatively, configure it purely via environment variables, instead of
   editing the config file - copy [`.env.example`](.env.example) to `.env`
   (it's automatically loaded by `start_server.sh`/`start_server.bat` and
   `start_http_server.sh`/`start_http_server.bat`):
   ```bash
   # --- Optional: Azure Key Vault (takes priority over AD_BIND_DN/AD_PASSWORD) ---
   AZURE_KEYVAULT_URL=https://your-keyvault-name.vault.azure.net/
   AZURE_KEYVAULT_SECRET_USERNAME=ad-bind-username
   AZURE_KEYVAULT_SECRET_PASSWORD=ad-bind-password
   # Authentication uses DefaultAzureCredential (managed identity, az login, or
   # a service principal via AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET).
   AZURE_TENANT_ID=your-azure-ad-tenant-id
   AZURE_CLIENT_ID=your-app-registration-client-id
   AZURE_CLIENT_SECRET=your-app-registration-client-secret
   ```
   `username_secret_name` / `AZURE_KEYVAULT_SECRET_USERNAME` is optional - if
   omitted, the `bind_dn` from the configuration file is used as-is.

3. **Authenticate to Azure.** ActiveDirectoryMCP uses
   [`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/python/sdk/authentication/credential-chains),
   which automatically tries, in order:
   - **Managed identity** (recommended when running in Azure - App Service,
     Container Apps, AKS, VMs). Grant the identity a Key Vault "Get Secret"
     RBAC role or access policy - no credentials to manage at all.
   - **Environment variables** `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
     `AZURE_CLIENT_SECRET` (service principal), for CI/CD or non-Azure hosts.
   - **Azure CLI** (`az login`), convenient for local development.

4. **Grant access** to the identity/service principal used above:
   ```bash
   az keyvault set-policy \
     --name your-keyvault-name \
     --object-id <identity-object-id> \
     --secret-permissions get
   ```

If Key Vault is not configured, the `AD_BIND_DN` / `AD_PASSWORD` environment
variables are used as a fallback, and only then the values already present in
the configuration file (a deprecation warning is logged if the password is
plaintext there). Startup fails with a clear error if no password can be
resolved from any source.

### Service Account Setup

1. Create a dedicated service account in AD
2. Grant minimum required permissions:
   - Read access to domain
   - User/Group/Computer management permissions
   - Password reset permissions (if needed)

### SSL/TLS Configuration

```json
{
    "active_directory": {
        "server": "ldaps://dc.example.com:636",
        "use_ssl": true
    },
    "security": {
        "enable_tls": true,
        "validate_certificate": true,
        "ca_cert_file": "/path/to/ca-certificate.pem"
    }
}
```

### Performance Configuration

```json
{
    "performance": {
        "connection_pool_size": 10,
        "max_retries": 3,
        "retry_delay": 1.0,
        "page_size": 1000
    }
}
```

## 🔐 Security configuration

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

- `allow_writes` enables create/modify/reset tools; `allow_destructive` additionally enables
  delete tools (destructive tools need both). Refused calls return a structured error.
- `max_list_results` caps list and report tools (0 = unlimited); responses include
  `truncated` and `result_limit`. The audit tools (`get_inactive_users`,
  `get_password_policy_violations`, `get_stale_computers`) scan the whole directory and cap
  only the findings they return.
- `protect_privileged_targets` (default `true`) makes `add_group_member`,
  `remove_group_member` and `reset_user_password` refuse privileged groups and accounts
  (Domain/Enterprise/Schema Admins, Administrators, operator groups, `krbtgt`,
  `Administrator`, anything with `adminCount=1`). Set it to `false` only if you accept that
  anyone with `allow_writes` can change them.
- `audit_log_path` (default unset) writes one JSON line per write or destructive tool call
  (timestamp, tool, risk, target, outcome, redacted arguments; no passwords) to an
  append-only file created with mode `0600`. The server refuses to start if the path
  cannot be opened, and logs a warning when `allow_writes` is true without a path.
- Generate and hash an HTTP API key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"      # the key
python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '<key>'
```

  Provide the key via `AD_MCP_HTTP_API_KEY`, or its digest via `AD_MCP_HTTP_API_KEY_SHA256` or
  `security.http_auth.api_key_sha256`. The server refuses to start over HTTP without one.
  Clients send either header (`/health` stays unauthenticated):

```bash
curl -H "Authorization: Bearer <your-api-key>" http://localhost:8813/activedirectory-mcp
curl -H "X-API-Key: <your-api-key>" http://localhost:8813/activedirectory-mcp
```

- Password tools (`create_user` with a password, `reset_user_password`,
  `reset_computer_password`) require an LDAPS or StartTLS connection and are refused otherwise.
  `reset_user_password` and `reset_computer_password` return the new password in the response;
  treat it as sensitive and do not log it client-side. `reset_computer_password` breaks the
  machine's secure channel, so the machine must be rejoined or re-synced.
- `modify_*` tools accept only allow-listed attributes (security-sensitive ones such as
  `userAccountControl`, `servicePrincipalName` and `gPLink` are always rejected).
- A full security policy document (SECURITY.md) is forthcoming.

## 🧪 Testing

Three kinds of checks, described in detail in [TESTING_GUIDE.md](TESTING_GUIDE.md):

### Unit tests (no server needed)
```bash
uv run pytest
```
ldap3 is mocked; nothing connects to a directory. Integration tests are deselected by default.

### Live integration tests (OpenLDAP lab)
```bash
# Starts the lab with a throwaway password, runs `pytest -m integration`, tears down
scripts/run_tests_with_ldap.sh
```
The lab (`docker-compose-openldap.yml`) is OpenLDAP, not Active Directory: it does not enforce userAccountControl, unicodePwd TLS rules, lastLogon replication or AD ACLs. Requires Docker and free ports 389/636.

Lab data: users admin, jdoe, jsmith, mwilson, testadmin and a few groups from `ldap-init/01-structure.ldif`. Follow the lab logs with `docker logs -f openldap-lab`. The admin password is the per-run `LAB_LDAP_PASSWORD`.

### Manual smoke scripts
```bash
# Needs a running HTTP server
uv run python tests/manual/http_server_smoke.py [URL]

# Needs AD_MCP_CONFIG pointing at a real directory
uv run python tests/manual/real_ad_smoke.py
```

### Test HTTP API
```bash
# Liveness check (unauthenticated GET /health; returns {"status", "server", "version"},
# performs no LDAP probe and discloses no hostnames or credentials)
curl -sf http://localhost:8813/health

# LDAP-aware status: call the `health` MCP tool through the MCP endpoint with an MCP client.
# Tools are declared once in src/active_directory_mcp/registry.py (descriptions live in
# src/active_directory_mcp/tools/definitions.py) and served by both transports.

# List users
curl -X POST "http://localhost:8813/activedirectory-mcp" \
  -H "Content-Type: application/json" \
  -d '{"method": "list_users", "params": {"ou": "OU=Users,DC=example,DC=com"}}'
```

## 📊 Project Structure

```
ActiveDirectoryMCP/
├── 📁 src/                          # Source code
│   └── active_directory_mcp/
│       ├── server.py                # Main MCP server (stdio)
│       ├── server_http.py           # HTTP MCP server
│       ├── config/                  # Configuration handling
│       ├── core/                    # Core functionality
│       │   ├── ldap_manager.py     # LDAP connection manager
│       │   └── logging.py          # Logging configuration
│       └── tools/                   # Tool implementations
│           ├── user.py             # User management
│           ├── group.py            # Group management
│           ├── computer.py         # Computer management
│           ├── organizational_unit.py # OU management
│           └── security.py         # Security & audit tools
│
├── 📁 tests/                       # Test suite
│   ├── unit/                       # Mocked unit tests (default pytest run)
│   ├── integration/                # Live-LDAP tests (pytest -m integration)
│   ├── support/                    # Shared test helpers
│   └── manual/                     # Manual smoke scripts (not collected)
├── 📁 ad-config/                   # Configuration files
│   ├── ad-config.json             # Main server configuration
│   ├── config.example.json        # Example configuration
│   └── production-config.example.json # Production example
│
├── 📄 Configuration Files
│   ├── pyproject.toml             # Project metadata
│   ├── docker-compose.yml         # Production deployment
│   ├── docker-compose-openldap.yml # OpenLDAP integration lab
│   ├── Dockerfile                 # Container definition
│   └── uv.lock                    # Locked dependencies
│
├── 📄 Scripts
│   ├── start_server.sh             # Stdio server launcher (Linux/macOS)
│   ├── start_server.bat            # Stdio server launcher (Windows)
│   ├── start_http_server.sh        # HTTP server launcher (Linux/macOS)
│   └── start_http_server.bat       # HTTP server launcher (Windows)
│
└── 📄 .env.example                 # Template for local .env (Key Vault / Azure creds)
```

## 🔍 Troubleshooting

### Common Issues

1. **LDAP Connection Failed**
   ```bash
   # Test connectivity
   ldapsearch -H ldap://dc.example.com -D "CN=user,DC=example,DC=com" -W -b "DC=example,DC=com" "(objectClass=domain)"
   ```

2. **Permission Denied**
   - Verify service account permissions
   - Check OU access rights
   - Ensure proper LDAP bind DN

3. **SSL/TLS Issues**
   ```bash
   # Test SSL connection
   openssl s_client -connect dc.example.com:636 -showcerts
   ```

4. **Port Already in Use**
   ```bash
   # Check port usage
   netstat -tlnp | grep 8813
   # Change port if needed
   HTTP_PORT=8814 ./start_http_server.sh
   ```

5. **⚠️ LLM Tool Limit Warning**
   
   Some LLM models may experience issues with 40+ tools in context.

### View Logs
```bash
# Container logs
docker logs activedirectory-mcp -f

# Local logs
tail -f active_directory_mcp.log
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [ProxmoxMCP-Extended](https://github.com/alpadalar/ProxmoxMCP-Extended)
- Built with the Model Context Protocol (MCP) SDK
- LDAP integration powered by ldap3 library
- FastMCP for HTTP transport capabilities

---

**Active Directory MCP.** Your comprehensive Active Directory MCP service provides stdio and HTTP transports; see the Testing section for what is and is not covered.

## 🔗 Related Projects

- [ProxmoxMCP-Extended](https://github.com/alpadalar/ProxmoxMCP-Extended) - Proxmox virtualization management
- [Model Context Protocol](https://github.com/modelcontextprotocol) - Official MCP documentation
- [FastMCP](https://github.com/modelcontextprotocol/fastmcp) - FastMCP for HTTP transport
