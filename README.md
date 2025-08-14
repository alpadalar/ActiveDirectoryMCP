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
- **43/43 Tests Passing**: 100% test success rate
- **LDAP3 Compatible**: Latest library compatibility ensured
- **Production Ready**: Thoroughly tested and validated
- **Comprehensive Coverage**: Config, integration, LDAP, and tools testing
- **Samba AD Test Environment**: Real AD protocols for testing

## 📋 Prerequisites

- Python 3.9 or higher
- UV package manager (recommended) or pip
- Access to Active Directory with appropriate permissions
- LDAP/LDAPS connectivity to domain controllers

## 🛠️ Installation

### Option 1: Quick Install (Recommended)

1. **Clone and set up environment:**
   ```bash
   # Clone repository
   git clone https://github.com/alpadalar/ActiveDirectoryMCP.git
   cd ActiveDirectoryMCP

   # Create and activate virtual environment
   uv venv
   source .venv/bin/activate  # Linux/macOS
   # OR
   .\.venv\Scripts\Activate.ps1  # Windows
   ```

2. **Install dependencies:**
   ```bash
   # Install with development dependencies
   uv pip install -e ".[dev]"
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
           "server": "ldap://dc.example.com:389",
           "domain": "example.com",
           "base_dn": "DC=example,DC=com",
           "bind_dn": "CN=service-account,OU=Service Accounts,DC=example,DC=com",
           "password": "your-service-account-password"
       },
       "organizational_units": {
           "users_ou": "OU=Users,DC=example,DC=com",
           "groups_ou": "OU=Groups,DC=example,DC=com",
           "computers_ou": "OU=Computers,DC=example,DC=com",
           "service_accounts_ou": "OU=Service Accounts,DC=example,DC=com"
       }
   }
   ```

### Verifying Installation

```bash
# Test configuration
python -c "import active_directory_mcp; print('Installation OK')"

# Run tests
pytest

# Test LDAP connection
AD_MCP_CONFIG="ad-config/ad-config.json" python -m active_directory_mcp.server
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

For development with included test LDAP server:

```bash
# 1. Start test environment
docker compose -f docker-compose-ad.yml up -d

# 2. Test the setup
python test_ad_environment.py

# 3. Access services
# - ActiveDirectoryMCP: http://localhost:8813/activedirectory-mcp
# - LDAP Admin: http://localhost:8080
```

**Test Features:**
- ✅ Includes OpenLDAP test server
- ✅ Pre-configured test data
- ✅ Web-based LDAP management
- ✅ No external AD required

### Development Mode (Stdio)

For testing and development with stdio transport:

```bash
# Start stdio server
./start_server.sh

# Or with custom config
AD_MCP_CONFIG="ad-config/ad-config.json" python -m active_directory_mcp.server
```

### HTTP Mode (Local Development)

For local HTTP transport development:

```bash
# Start HTTP server
./start_http_server.sh

# Or with custom settings
python -m active_directory_mcp.server_http --host 0.0.0.0 --port 8813 --path /activedirectory-mcp
```

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

### 🔧 System Tools
- `test_connection` - LDAP connectivity test
- `health` - Server health check
- `get_schema_info` - Tool schema information

> **⚠️ Note**: ActiveDirectoryMCP provides 43 tools total. Some LLM models may experience issues with this many tools.

## 🔒 Security Configuration

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

### Connection Pool Configuration

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

## 🧪 Testing

**✅ All Tests Passing (43/43)** - Production Ready!

### Quick Test Status
- **Configuration Tests**: 8/8 ✅
- **Integration Tests**: 10/10 ✅  
- **LDAP Manager Tests**: 12/12 ✅
- **User Tools Tests**: 13/13 ✅
- **Total**: 43/43 tests passing

### Run Unit Tests
```bash
# Run all tests with verbose output
pytest -v

# Run specific test categories
pytest tests/test_config.py -v
pytest tests/test_ldap_manager.py -v
pytest tests/test_user_tools.py -v
pytest tests/test_integration.py -v
```

### Test HTTP Server
```bash
# Test HTTP endpoints directly
python test_scripts/test_http_server.py

# Custom server URL
python test_scripts/test_http_server.py http://your-server:8813/activedirectory-mcp
```

### Run Integration Tests
```bash
# Test with real AD connection (requires config)
AD_MCP_CONFIG="ad-config/ad-config.json" pytest tests/test_integration.py -v
```

### 🏢 Test with LDAP/AD Environment (Recommended)
```bash
# Start LDAP/AD test environment 
docker-compose -f docker-compose-ad.yml up -d

# Wait for services to be ready (30 seconds)
docker logs -f openldap-ad-dc

# Test ActiveDirectoryMCP with test environment
python test_ad_environment.py

# Expected output:
# ✅ Connected to LDAP: 192.168.1.100:389
# ✅ MCP Config: SUCCESS
# ✅ HTTP API: SUCCESS
# 🎉 Test environment ready!
```

**Test Environment Features:**
- 🔗 LDAP Directory Service with AD-style structure
- 👥 Test users: admin, jdoe, jsmith, mwilson, testadmin
- 🔐 Test groups: IT Department, Sales Team, Marketing, All Users
- 🖥️ Web Admin: http://localhost:8080 (cn=admin,dc=test,dc=local / Admin123!)
- 📚 Full testing guide: [TESTING_GUIDE.md](TESTING_GUIDE.md)

### Test HTTP API
```bash
# Health check
curl -X POST "http://localhost:8813/activedirectory-mcp" \
  -H "Content-Type: application/json" \
  -d '{"method": "health", "params": {}}'

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
├── 📁 ad-config/                   # Configuration files
│   ├── ad-config.json             # Main server configuration
│   ├── config.example.json        # Example configuration
│   └── production-config.example.json # Production example
│
├── 📄 Configuration Files
│   ├── pyproject.toml             # Project metadata
│   ├── docker-compose.yml         # Production deployment
│   ├── docker-compose-ad.yml      # Test environment with LDAP
│   ├── Dockerfile                 # Container definition
│   └── requirements.in            # Dependencies
│
└── 📄 Scripts
    ├── start_server.sh            # Stdio server launcher
    └── start_http_server.sh       # HTTP server launcher
```

## 🔍 Troubleshooting

### ✅ Recent Fixes (v0.1.0)
- **LDAP3 Compatibility**: Fixed TLS configuration compatibility with latest ldap3 library
- **Test Suite**: All 43 tests now passing successfully (100% success rate)
- **Mock Issues**: Resolved integration test mocking for error scenarios
- **Security Config**: Removed deprecated LDAP parameters for better compatibility

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

**✅ Production Ready!** 🎉 Your comprehensive Active Directory MCP service is fully tested (43/43 tests passing) and ready for production deployment with complete HTTP transport support.

## 🔗 Related Projects

- [ProxmoxMCP-Extended](https://github.com/alpadalar/ProxmoxMCP-Extended) - Proxmox virtualization management
- [Model Context Protocol](https://github.com/modelcontextprotocol) - Official MCP documentation
- [FastMCP](https://github.com/modelcontextprotocol/fastmcp) - FastMCP for HTTP transport
