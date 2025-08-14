"""Tool definitions and descriptions for Active Directory MCP."""

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
Automatically sets up user principal name, enables account, and applies security settings.

Example:
- create_user(username="jsmith", password="TempPass123!", first_name="John", 
              last_name="Smith", email="jsmith@company.com")

Supports additional attributes and custom OU placement."""

MODIFY_USER_DESC = """Modify user attributes and properties.

Updates existing user attributes including personal information, security settings,
and organizational data.

Example:
- modify_user(username="jsmith", attributes={"department": "Marketing", "title": "Manager"})

Supports password changes and account property modifications."""

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

Automatically configures group properties."""

MODIFY_GROUP_DESC = """Modify group attributes and properties.

Updates group information including description, managed by settings,
and other attributes.

Example:
- modify_group(group_name="Sales Team", attributes={"description": "Updated description"})

Preserves group membership during modifications."""

DELETE_GROUP_DESC = """Delete a group from Active Directory.

Permanently removes group and all membership associations.

Example:
- delete_group(group_name="Old Project Team")

Validates group existence and membership before deletion."""

ADD_GROUP_MEMBER_DESC = """Add a member to a group.

Adds user, computer, or group as member of specified group.

Example:
- add_group_member(group_name="Sales Team", member_dn="CN=John Smith,OU=Users,DC=company,DC=com")

Supports nested group memberships."""

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

Automatically sets up computer trust relationship."""

MODIFY_COMPUTER_DESC = """Modify computer attributes and properties.

Updates computer information including description, location, and management settings.

Example:
- modify_computer(computer_name="DESKTOP-ABC123", 
                  attributes={"description": "Updated description", "location": "Building A"})

Preserves critical computer account settings."""

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

Forces computer to re-establish trust relationship with domain.

Example:
- reset_computer_password(computer_name="DESKTOP-ABC123")

Resolves computer authentication issues."""

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

Preserves OU structure during modifications."""

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
