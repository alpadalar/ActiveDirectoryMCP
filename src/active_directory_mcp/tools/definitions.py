"""Tool definitions and descriptions for Active Directory MCP."""

from typing import Any, Dict

# User Management Tool Descriptions
LIST_USERS_DESC = """List users in Active Directory with optional filtering.

This tool retrieves users from the specified organizational unit or entire domain.
Supports custom LDAP filters and attribute selection for targeted queries.

Example:
- List all users: list_users()
- List users in specific OU: list_users(ou="OU=Sales,DC=company,DC=com")
- List with filter: list_users(filter_criteria="(department=IT)")

Returns user information including account status, group memberships, and security details."""

GET_USER_DESC = """Get detailed information about a specific user.

Retrieves comprehensive user information including attributes, group memberships,
account status, and computed security fields.

Example:
- get_user(username="jsmith")

Returns detailed user profile with security assessment."""

CREATE_USER_DESC = """Create a new user account in Active Directory.

Creates a user with specified attributes in the designated organizational unit.
Sets the user principal name, sets the initial password and enables the account.

Example:
- create_user(username="jsmith", password="TempPass123!", first_name="John", 
              last_name="Smith", email="jsmith@company.com")

Supports additional attributes and custom OU placement."""

MODIFY_USER_DESC = """Modify user attributes and properties.

Updates existing user attributes including personal information, security settings,
and organizational data.

Example:
- modify_user(username="jsmith", attributes={"department": "Marketing", "title": "Manager"})

The password cannot be changed with this tool; use reset_user_password instead."""

DELETE_USER_DESC = """Delete a user account from Active Directory.

Permanently removes user account and all associated data. Use with caution.

Example:
- delete_user(username="jsmith")

Validates user existence before deletion."""

ENABLE_USER_DESC = """Enable a user account.

Activates a disabled user account by modifying the userAccountControl attribute.

Example:
- enable_user(username="jsmith")

Allows user to log in and access domain resources."""

DISABLE_USER_DESC = """Disable a user account.

Deactivates a user account preventing login while preserving account data.

Example:
- disable_user(username="jsmith")

Useful for temporary access suspension."""

RESET_USER_PASSWORD_DESC = """Reset user password with optional auto-generation.

Resets user password to specified value or generates secure random password.
Optionally forces password change at next logon.

Example:
- reset_user_password(username="jsmith", force_change=True)
- reset_user_password(username="jsmith", new_password="NewPass123!")

Generated passwords meet complexity requirements."""

GET_USER_GROUPS_DESC = """Get groups that a user is member of.

Retrieves detailed group membership information including group types,
scopes, and descriptions.

Example:
- get_user_groups(username="jsmith")

Returns comprehensive group membership analysis."""

# Group Management Tool Descriptions
LIST_GROUPS_DESC = """List groups in Active Directory with filtering options.

Retrieves security and distribution groups with detailed information about
scope, type, and membership counts.

Example:
- list_groups()
- list_groups(ou="OU=Security Groups,DC=company,DC=com")
- list_groups(filter_criteria="(groupType=-2147483646)")

Shows group hierarchy and management information."""

GET_GROUP_DESC = """Get detailed information about a specific group.

Retrieves comprehensive group information including members, parent groups,
and management settings.

Example:
- get_group(group_name="Sales Team")

Returns group configuration and membership details."""

CREATE_GROUP_DESC = """Create a new group in Active Directory.

Creates security or distribution groups with specified scope and attributes.
Supports Global, DomainLocal, and Universal scopes.

Example:
- create_group(group_name="Marketing Team", group_scope="Global", 
               group_type="Security", description="Marketing department")

Fails if a group with that name already exists."""

MODIFY_GROUP_DESC = """Modify group attributes and properties.

Updates group information including description, managed by settings,
and other attributes.

Example:
- modify_group(group_name="Sales Team", attributes={"description": "Updated description"})

Returns an error if the group is not found."""

DELETE_GROUP_DESC = """Delete a group from Active Directory.

Permanently removes the group object.

Example:
- delete_group(group_name="Old Project Team")

Validates group existence before deletion."""

ADD_GROUP_MEMBER_DESC = """Add a member to a group.

Adds user, computer, or group as member of specified group.

Example:
- add_group_member(group_name="Sales Team", member_dn="CN=John Smith,OU=Users,DC=company,DC=com")

Fails if the member is already in the group."""

REMOVE_GROUP_MEMBER_DESC = """Remove a member from a group.

Removes specified member from group membership.

Example:
- remove_group_member(group_name="Sales Team", member_dn="CN=John Smith,OU=Users,DC=company,DC=com")

Validates membership before removal."""

GET_GROUP_MEMBERS_DESC = """Get members of a group with optional recursion.

Lists all group members with option to include nested group members.

Example:
- get_group_members(group_name="Sales Team")
- get_group_members(group_name="All Users", recursive=True)

Shows detailed member information and nesting levels."""

# Computer Management Tool Descriptions
LIST_COMPUTERS_DESC = """List computer objects in Active Directory.

Retrieves computer accounts with operating system information, last logon,
and security status.

Example:
- list_computers()
- list_computers(ou="OU=Workstations,DC=company,DC=com")

Shows computer health and security posture."""

GET_COMPUTER_DESC = """Get detailed information about a specific computer.

Retrieves comprehensive computer information including OS details,
last logon, group memberships, and security settings.

Example:
- get_computer(computer_name="DESKTOP-ABC123")

Returns complete computer profile."""

CREATE_COMPUTER_DESC = """Create a new computer object in Active Directory.

Creates computer account with appropriate attributes and service principal names.
Configures DNS hostname and enables account.

Example:
- create_computer(computer_name="NEW-DESKTOP", description="Marketing workstation")

Fails if a computer with that name already exists."""

MODIFY_COMPUTER_DESC = """Modify computer attributes and properties.

Updates computer information including description, location, and management settings.

Example:
- modify_computer(computer_name="DESKTOP-ABC123", 
                  attributes={"description": "Updated description", "location": "Building A"})

Returns an error if the computer is not found."""

DELETE_COMPUTER_DESC = """Delete a computer object from Active Directory.

Permanently removes computer account and trust relationship.

Example:
- delete_computer(computer_name="OLD-DESKTOP")

Cleans up stale computer accounts."""

ENABLE_COMPUTER_DESC = """Enable a computer account.

Activates disabled computer account allowing domain authentication.

Example:
- enable_computer(computer_name="DESKTOP-ABC123")

Restores computer trust relationship."""

DISABLE_COMPUTER_DESC = """Disable a computer account.

Deactivates computer account preventing domain authentication.

Example:
- disable_computer(computer_name="DESKTOP-ABC123")

Useful for temporary computer isolation."""

RESET_COMPUTER_PASSWORD_DESC = """Reset computer account password.

Sets a new random 120-character machine password on the computer account (unicodePwd) and
returns it once in the response (sensitive; do not log it). Requires an LDAPS/StartTLS connection;
refused otherwise. The machine's secure channel breaks, so it must be rejoined or re-synced.

Example:
- reset_computer_password(computer_name="DESKTOP-ABC123")

Returns an error if the computer is not found."""

GET_STALE_COMPUTERS_DESC = """Get computers that haven't logged in for specified days.

Identifies inactive computer accounts that may need cleanup.

Example:
- get_stale_computers(days=90)

Helps maintain clean computer account inventory."""

# Organizational Unit Tool Descriptions
LIST_ORGANIZATIONAL_UNITS_DESC = """List Organizational Units in Active Directory.

Retrieves OU hierarchy with management information and policy links.

Example:
- list_organizational_units()
- list_organizational_units(parent_ou="OU=Departments,DC=company,DC=com", recursive=True)

Shows OU structure and relationships."""

GET_ORGANIZATIONAL_UNIT_DESC = """Get detailed information about a specific OU.

Retrieves comprehensive OU information including child objects, GP links,
and management settings.

Example:
- get_organizational_unit(ou_dn="OU=Sales,DC=company,DC=com")

Returns complete OU configuration."""

CREATE_ORGANIZATIONAL_UNIT_DESC = """Create a new Organizational Unit.

Creates OU with specified attributes and management settings.

Example:
- create_organizational_unit(name="Marketing", parent_ou="OU=Departments,DC=company,DC=com",
                            description="Marketing department")

Establishes OU hierarchy."""

MODIFY_ORGANIZATIONAL_UNIT_DESC = """Modify OU attributes and properties.

Updates OU information including description, managed by, and location details.

Example:
- modify_organizational_unit(ou_dn="OU=Sales,DC=company,DC=com",
                            attributes={"description": "Updated description"})

Returns an error if the OU is not found."""

DELETE_ORGANIZATIONAL_UNIT_DESC = """Delete an Organizational Unit.

Removes OU and optionally all contained objects. Use with caution.

Example:
- delete_organizational_unit(ou_dn="OU=OldDept,DC=company,DC=com", force=False)

Validates OU emptiness unless force deletion specified."""

MOVE_ORGANIZATIONAL_UNIT_DESC = """Move an OU to a new parent.

Relocates OU within domain hierarchy while preserving contents.

Example:
- move_organizational_unit(ou_dn="OU=Sales,OU=Old,DC=company,DC=com",
                          new_parent_dn="OU=Departments,DC=company,DC=com")

Maintains OU relationships during move."""

GET_ORGANIZATIONAL_UNIT_CONTENTS_DESC = """Get contents of an OU.

Lists all objects within OU including users, groups, computers, and sub-OUs.

Example:
- get_organizational_unit_contents(ou_dn="OU=Sales,DC=company,DC=com")
- get_organizational_unit_contents(ou_dn="OU=IT,DC=company,DC=com", 
                                  object_types=["user", "group"])

Provides OU inventory and organization."""

# Security and Audit Tool Descriptions
GET_DOMAIN_INFO_DESC = """Get domain information and security settings.

Retrieves domain configuration including password policies, lockout settings,
and security parameters.

Example:
- get_domain_info()

Returns comprehensive domain security posture."""

GET_NESTED_GROUP_MEMBERS_DESC = """Get all direct and nested members of a group.

Resolves the group by sAMAccountName and evaluates transitive membership on the
domain controller in a single query (LDAP_MATCHING_RULE_IN_CHAIN), so deep or
cyclic nesting is handled without client-side recursion. Results are confined
to the configured base DN and capped by max_list_results (see "truncated").

Example:
- get_nested_group_members(group_name="Domain Admins")

Returns members with dn, sAMAccountName, displayName and type."""

GET_ROOTDSE_INFO_DESC = """Get rootDSE information from the domain controller.

Returns naming contexts, DC host name, functional levels, supported LDAP
versions and SASL mechanisms, current time and sync/global-catalog state.
Takes no input; a fixed attribute allow-list is read.

Example:
- get_rootdse_info()

Useful to confirm which DC answered and its functional level."""

GET_TLS_POSTURE_DESC = """Report the TLS posture of the connection to the domain controller.

Returns the configured values (use_ssl, ssl_port, enable_tls, validate_certificate,
whether a CA file is set, require_secure_connection), the live channel (ldaps,
starttls or plaintext, plus TLS version and cipher when available) and a list of
findings {severity, code, message}. Takes no input; no secrets or paths are returned.

Example:
- get_tls_posture()

Useful to verify that the bind is encrypted and the certificate is validated."""

GET_PRIVILEGED_GROUPS_DESC = """Get information about privileged groups.

Identifies and analyzes high-privilege groups including Domain Admins,
Enterprise Admins, and other administrative groups.

Example:
- get_privileged_groups()

Essential for security auditing and compliance."""

GET_USER_PERMISSIONS_DESC = """Get effective permissions for a user.

Analyzes user's effective permissions through group memberships and
identifies potential security risks.

Example:
- get_user_permissions(username="jsmith")

Provides security risk assessment."""

GET_INACTIVE_USERS_DESC = """Get users who haven't logged in for specified days.

Identifies inactive user accounts that may pose security risks.

Example:
- get_inactive_users(days=90, include_disabled=False)

Critical for security hygiene and compliance."""

GET_PASSWORD_POLICY_VIOLATIONS_DESC = """Get users with password policy violations.

Identifies accounts with password policy non-compliance including
expired passwords, never-expiring passwords, and policy violations.

Example:
- get_password_policy_violations()

Essential for password security compliance."""

AUDIT_ADMIN_ACCOUNTS_DESC = """Audit administrative accounts for security compliance.

Comprehensive security audit of privileged accounts including
access patterns, policy compliance, and risk assessment.

Example:
- audit_admin_accounts()

Critical for administrative account security."""

# System Tool Descriptions
TEST_CONNECTION_DESC = """Test LDAP connection and get server information.

Validates Active Directory connectivity and retrieves server status.

Example:
- test_connection()

Useful for troubleshooting and monitoring."""

HEALTH_DESC = """Health check for Active Directory MCP server.

Returns server status, LDAP connectivity, and system health information.

Example:
- health()

Essential for monitoring and alerting."""

GET_SCHEMA_INFO_DESC = """Get schema information for all available tools.

Retrieves comprehensive information about all tools, their parameters,
and capabilities.

Example:
- get_schema_info()

Useful for API documentation and integration."""


# Single description source: exposed tool name -> description (consumed by registry.py)
TOOL_DESCRIPTIONS: Dict[str, str] = {
    "list_users": LIST_USERS_DESC,
    "get_user": GET_USER_DESC,
    "create_user": CREATE_USER_DESC,
    "modify_user": MODIFY_USER_DESC,
    "delete_user": DELETE_USER_DESC,
    "enable_user": ENABLE_USER_DESC,
    "disable_user": DISABLE_USER_DESC,
    "reset_user_password": RESET_USER_PASSWORD_DESC,
    "get_user_groups": GET_USER_GROUPS_DESC,
    "list_groups": LIST_GROUPS_DESC,
    "get_group": GET_GROUP_DESC,
    "create_group": CREATE_GROUP_DESC,
    "modify_group": MODIFY_GROUP_DESC,
    "delete_group": DELETE_GROUP_DESC,
    "add_group_member": ADD_GROUP_MEMBER_DESC,
    "remove_group_member": REMOVE_GROUP_MEMBER_DESC,
    "get_group_members": GET_GROUP_MEMBERS_DESC,
    "list_computers": LIST_COMPUTERS_DESC,
    "get_computer": GET_COMPUTER_DESC,
    "create_computer": CREATE_COMPUTER_DESC,
    "modify_computer": MODIFY_COMPUTER_DESC,
    "delete_computer": DELETE_COMPUTER_DESC,
    "enable_computer": ENABLE_COMPUTER_DESC,
    "disable_computer": DISABLE_COMPUTER_DESC,
    "reset_computer_password": RESET_COMPUTER_PASSWORD_DESC,
    "get_stale_computers": GET_STALE_COMPUTERS_DESC,
    "list_organizational_units": LIST_ORGANIZATIONAL_UNITS_DESC,
    "get_organizational_unit": GET_ORGANIZATIONAL_UNIT_DESC,
    "create_organizational_unit": CREATE_ORGANIZATIONAL_UNIT_DESC,
    "modify_organizational_unit": MODIFY_ORGANIZATIONAL_UNIT_DESC,
    "delete_organizational_unit": DELETE_ORGANIZATIONAL_UNIT_DESC,
    "move_organizational_unit": MOVE_ORGANIZATIONAL_UNIT_DESC,
    "get_organizational_unit_contents": GET_ORGANIZATIONAL_UNIT_CONTENTS_DESC,
    "get_domain_info": GET_DOMAIN_INFO_DESC,
    "get_nested_group_members": GET_NESTED_GROUP_MEMBERS_DESC,
    "get_rootdse_info": GET_ROOTDSE_INFO_DESC,
    "get_tls_posture": GET_TLS_POSTURE_DESC,
    "get_privileged_groups": GET_PRIVILEGED_GROUPS_DESC,
    "get_user_permissions": GET_USER_PERMISSIONS_DESC,
    "get_inactive_users": GET_INACTIVE_USERS_DESC,
    "get_password_policy_violations": GET_PASSWORD_POLICY_VIOLATIONS_DESC,
    "audit_admin_accounts": AUDIT_ADMIN_ACCOUNTS_DESC,
    "test_connection": TEST_CONNECTION_DESC,
    "health": HEALTH_DESC,
    "get_schema_info": GET_SCHEMA_INFO_DESC,
}

# Stdio input schemas, moved verbatim from the former server.py _define_tools
TOOL_INPUT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "list_users": {
        "type": "object",
        "properties": {
            "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
            "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
    },
    "get_user": {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "description": "Username (sAMAccountName) to search for",
            },
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
        "required": ["username"],
    },
    "create_user": {
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "Username (sAMAccountName)"},
            "password": {"type": "string", "description": "User password"},
            "first_name": {"type": "string", "description": "User's first name"},
            "last_name": {"type": "string", "description": "User's last name"},
            "email": {"type": "string", "description": "User's email address"},
            "ou": {"type": "string", "description": "Organizational Unit DN to create user in"},
            "additional_attributes": {
                "type": "object",
                "description": "Additional attributes to set",
            },
        },
        "required": ["username", "password", "first_name", "last_name"],
    },
    "modify_user": {
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "Username to modify"},
            "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
        },
        "required": ["username", "attributes"],
    },
    "delete_user": {
        "type": "object",
        "properties": {"username": {"type": "string", "description": "Username to delete"}},
        "required": ["username"],
    },
    "enable_user": {
        "type": "object",
        "properties": {"username": {"type": "string", "description": "Username to enable"}},
        "required": ["username"],
    },
    "disable_user": {
        "type": "object",
        "properties": {"username": {"type": "string", "description": "Username to disable"}},
        "required": ["username"],
    },
    "reset_user_password": {
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "Username to reset password for"},
            "new_password": {
                "type": "string",
                "description": "New password (auto-generated if not provided)",
            },
            "force_change": {
                "type": "boolean",
                "description": "Force user to change password at next logon",
                "default": True,
            },
        },
        "required": ["username"],
    },
    "get_user_groups": {
        "type": "object",
        "properties": {"username": {"type": "string", "description": "Username to get groups for"}},
        "required": ["username"],
    },
    "list_groups": {
        "type": "object",
        "properties": {
            "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
            "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
    },
    "get_group": {
        "type": "object",
        "properties": {
            "group_name": {
                "type": "string",
                "description": "Group name (sAMAccountName) to search for",
            },
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
        "required": ["group_name"],
    },
    "create_group": {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Group name (sAMAccountName)"},
            "display_name": {"type": "string", "description": "Display name for the group"},
            "description": {"type": "string", "description": "Group description"},
            "ou": {"type": "string", "description": "Organizational Unit DN to create group in"},
            "group_scope": {
                "type": "string",
                "description": "Group scope (Global, DomainLocal, Universal)",
                "default": "Global",
            },
            "group_type": {
                "type": "string",
                "description": "Group type (Security, Distribution)",
                "default": "Security",
            },
            "additional_attributes": {
                "type": "object",
                "description": "Additional attributes to set",
            },
        },
        "required": ["group_name"],
    },
    "modify_group": {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Group name to modify"},
            "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
        },
        "required": ["group_name", "attributes"],
    },
    "delete_group": {
        "type": "object",
        "properties": {"group_name": {"type": "string", "description": "Group name to delete"}},
        "required": ["group_name"],
    },
    "add_group_member": {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Group name to add member to"},
            "member_dn": {"type": "string", "description": "Distinguished name of member to add"},
        },
        "required": ["group_name", "member_dn"],
    },
    "remove_group_member": {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Group name to remove member from"},
            "member_dn": {
                "type": "string",
                "description": "Distinguished name of member to remove",
            },
        },
        "required": ["group_name", "member_dn"],
    },
    "get_group_members": {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "description": "Group name to get members for"},
            "recursive": {
                "type": "boolean",
                "description": "Include members of nested groups",
                "default": False,
            },
        },
        "required": ["group_name"],
    },
    "list_computers": {
        "type": "object",
        "properties": {
            "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
            "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
    },
    "get_computer": {
        "type": "object",
        "properties": {
            "computer_name": {
                "type": "string",
                "description": "Computer name (sAMAccountName) to search for",
            },
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
        "required": ["computer_name"],
    },
    "create_computer": {
        "type": "object",
        "properties": {
            "computer_name": {"type": "string", "description": "Computer name (without $ suffix)"},
            "description": {"type": "string", "description": "Computer description"},
            "ou": {"type": "string", "description": "Organizational Unit DN to create computer in"},
            "dns_hostname": {"type": "string", "description": "DNS hostname"},
            "additional_attributes": {
                "type": "object",
                "description": "Additional attributes to set",
            },
        },
        "required": ["computer_name"],
    },
    "modify_computer": {
        "type": "object",
        "properties": {
            "computer_name": {"type": "string", "description": "Computer name to modify"},
            "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
        },
        "required": ["computer_name", "attributes"],
    },
    "delete_computer": {
        "type": "object",
        "properties": {
            "computer_name": {"type": "string", "description": "Computer name to delete"}
        },
        "required": ["computer_name"],
    },
    "enable_computer": {
        "type": "object",
        "properties": {
            "computer_name": {"type": "string", "description": "Computer name to enable"}
        },
        "required": ["computer_name"],
    },
    "disable_computer": {
        "type": "object",
        "properties": {
            "computer_name": {"type": "string", "description": "Computer name to disable"}
        },
        "required": ["computer_name"],
    },
    "reset_computer_password": {
        "type": "object",
        "properties": {
            "computer_name": {
                "type": "string",
                "description": "Computer name to reset password for",
            }
        },
        "required": ["computer_name"],
    },
    "get_stale_computers": {
        "type": "object",
        "properties": {
            "days": {
                "type": "integer",
                "description": "Number of days to consider stale",
                "default": 90,
            }
        },
    },
    "list_organizational_units": {
        "type": "object",
        "properties": {
            "parent_ou": {"type": "string", "description": "Parent OU DN to search in"},
            "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
            "recursive": {
                "type": "boolean",
                "description": "Search recursively in sub-OUs",
                "default": True,
            },
        },
    },
    "get_organizational_unit": {
        "type": "object",
        "properties": {
            "ou_dn": {"type": "string", "description": "Distinguished name of the OU"},
            "attributes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific attributes to retrieve",
            },
        },
        "required": ["ou_dn"],
    },
    "create_organizational_unit": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Name of the OU"},
            "parent_ou": {"type": "string", "description": "Parent OU DN"},
            "description": {"type": "string", "description": "OU description"},
            "managed_by": {"type": "string", "description": "DN of user/group managing this OU"},
            "additional_attributes": {
                "type": "object",
                "description": "Additional attributes to set",
            },
        },
        "required": ["name"],
    },
    "modify_organizational_unit": {
        "type": "object",
        "properties": {
            "ou_dn": {"type": "string", "description": "OU distinguished name to modify"},
            "attributes": {"type": "object", "description": "Dictionary of attributes to modify"},
        },
        "required": ["ou_dn", "attributes"],
    },
    "delete_organizational_unit": {
        "type": "object",
        "properties": {
            "ou_dn": {"type": "string", "description": "OU distinguished name to delete"},
            "force": {
                "type": "boolean",
                "description": "Force deletion even if OU contains objects",
                "default": False,
            },
        },
        "required": ["ou_dn"],
    },
    "move_organizational_unit": {
        "type": "object",
        "properties": {
            "ou_dn": {"type": "string", "description": "OU distinguished name to move"},
            "new_parent_dn": {"type": "string", "description": "New parent OU distinguished name"},
        },
        "required": ["ou_dn", "new_parent_dn"],
    },
    "get_organizational_unit_contents": {
        "type": "object",
        "properties": {
            "ou_dn": {"type": "string", "description": "OU distinguished name"},
            "object_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Types of objects to include",
            },
        },
        "required": ["ou_dn"],
    },
    "get_domain_info": {"type": "object", "properties": {}},
    "get_rootdse_info": {"type": "object", "properties": {}},
    "get_tls_posture": {"type": "object", "properties": {}},
    "get_nested_group_members": {
        "type": "object",
        "properties": {
            "group_name": {
                "type": "string",
                "description": "Group name (sAMAccountName) whose nested members to list",
            },
        },
        "required": ["group_name"],
    },
    "get_privileged_groups": {"type": "object", "properties": {}},
    "get_user_permissions": {
        "type": "object",
        "properties": {
            "username": {"type": "string", "description": "Username to analyze permissions for"}
        },
        "required": ["username"],
    },
    "get_inactive_users": {
        "type": "object",
        "properties": {
            "days": {
                "type": "integer",
                "description": "Number of days to consider inactive",
                "default": 90,
            },
            "include_disabled": {
                "type": "boolean",
                "description": "Include disabled accounts in results",
                "default": False,
            },
        },
    },
    "get_password_policy_violations": {"type": "object", "properties": {}},
    "audit_admin_accounts": {"type": "object", "properties": {}},
    "test_connection": {"type": "object", "properties": {}},
    "health": {"type": "object", "properties": {}},
    "get_schema_info": {"type": "object", "properties": {}},
}
