"""User management tools for Active Directory."""

import hashlib
import secrets
import string
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.logging import log_ldap_operation


class UserTools(BaseTool):
    """Tools for managing Active Directory users."""
    
    def list_users(self, ou: Optional[str] = None, filter_criteria: Optional[str] = None, 
                   attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List users in Active Directory.
        
        Args:
            ou: Organizational Unit to search in (optional)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with user information
        """
        try:
            # Determine search base
            if ou:
                search_base = ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter
            base_filter = "(objectClass=user)"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
                    'givenName', 'sn', 'telephoneNumber', 'department', 'title',
                    'whenCreated', 'whenChanged', 'userAccountControl', 'lastLogon',
                    'pwdLastSet', 'accountExpires'
                ]
            
            self.logger.info(f"Listing users from {search_base}")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )
            
            # Process results
            users = []
            for entry in results:
                user_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                    'displayName': self._get_attr(entry['attributes'], 'displayName', ''),
                    'mail': self._get_attr(entry['attributes'], 'mail', ''),
                    'enabled': self._is_user_enabled(self._get_attr(entry['attributes'], 'userAccountControl', 0))
                }
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'displayName', 'mail'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if isinstance(value, list) and len(value) == 1:
                            user_info[attr] = value[0]
                        else:
                            user_info[attr] = value
                
                users.append(user_info)
            
            log_ldap_operation("list_users", search_base, True, f"Found {len(users)} users")
            
            response_data = {
                "users": users,
                "count": len(users),
                "search_base": search_base,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_users")
            
        except Exception as e:
            return self._handle_ldap_error(e, "list_users", search_base)
    
    def get_user(self, username: str, attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get detailed information about a specific user.
        
        Args:
            username: Username (sAMAccountName) to search for
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with user information
        """
        try:
            # Build search filter
            escaped_username = self._escape_ldap_filter(username)
            search_filter = f"(&(objectClass=user)(sAMAccountName={escaped_username}))"
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
                    'givenName', 'sn', 'telephoneNumber', 'department', 'title',
                    'manager', 'directReports', 'memberOf', 'whenCreated', 'whenChanged',
                    'userAccountControl', 'lastLogon', 'pwdLastSet', 'accountExpires',
                    'description', 'physicalDeliveryOfficeName', 'company'
                ]
            
            self.logger.info(f"Getting user information for: {username}")
            
            # Perform search
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            if not results:
                log_ldap_operation("get_user", username, False, "User not found")
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user")
            
            user_entry = results[0]
            user_info = {
                'dn': user_entry['dn'],
                'attributes': user_entry['attributes']
            }
            
            # Add computed fields
            uac = self._get_attr(user_entry['attributes'], 'userAccountControl', 0)
            user_info['computed'] = {
                'enabled': self._is_user_enabled(uac),
                'locked': self._is_user_locked(uac),
                'password_expired': self._is_password_expired(user_entry['attributes']),
                'account_expired': self._is_account_expired(user_entry['attributes'])
            }
            
            log_ldap_operation("get_user", username, True, f"Retrieved user: {user_entry['dn']}")
            
            return self._format_response(user_info, "get_user")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_user", username)
    
    def create_user(self, username: str, password: str, first_name: str, last_name: str,
                   email: Optional[str] = None, ou: Optional[str] = None,
                   additional_attributes: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Create a new user in Active Directory.
        
        Args:
            username: Username (sAMAccountName)
            password: User password
            first_name: User's first name
            last_name: User's last name
            email: User's email address (optional)
            ou: Organizational Unit to create user in (optional)
            additional_attributes: Additional attributes to set (optional)
            
        Returns:
            List of MCP content objects with creation result
        """
        try:
            # Determine OU
            if ou is None:
                # Default to CN=Users under base DN if organizational_units not configured
                ou = f"CN=Users,{self.ldap.ad_config.base_dn}"
            
            # Build DN
            user_dn = f"CN={first_name} {last_name},{ou}"
            
            # Check if user already exists
            existing_user = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(sAMAccountName={self._escape_ldap_filter(username)})",
                attributes=['sAMAccountName']
            )
            
            if existing_user:
                log_ldap_operation("create_user", user_dn, False, "User already exists")
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' already exists",
                    "username": username
                }, "create_user")
            
            # Prepare user attributes
            user_attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.ldap.ad_config.domain}",
                'givenName': first_name,
                'sn': last_name,
                'cn': f"{first_name} {last_name}",
                'displayName': f"{first_name} {last_name}",
                'userAccountControl': 514  # Disabled account initially
            }
            
            if email:
                user_attributes['mail'] = email
            
            # Add additional attributes
            if additional_attributes:
                user_attributes.update(additional_attributes)
            
            self.logger.info(f"Creating user: {username} ({user_dn})")
            
            # Create user
            success = self.ldap.add(user_dn, user_attributes)
            
            if success:
                # Set password
                try:
                    self._set_user_password(user_dn, password)
                    
                    # Enable the account
                    self.ldap.modify(user_dn, {
                        'userAccountControl': [(MODIFY_REPLACE, [512])]  # Enabled account
                    })
                    
                    log_ldap_operation("create_user", user_dn, True, f"Created user: {username}")
                    
                    return self._success_response(
                        f"User '{username}' created successfully",
                        {
                            "username": username,
                            "dn": user_dn,
                            "upn": f"{username}@{self.ldap.ad_config.domain}"
                        }
                    )
                    
                except Exception as pwd_error:
                    # If password setting fails, delete the created user
                    try:
                        self.ldap.delete(user_dn)
                    except:
                        pass
                    
                    raise Exception(f"User created but password setting failed: {pwd_error}")
            else:
                raise Exception("Failed to create user account")
            
        except Exception as e:
            return self._handle_ldap_error(e, "create_user", user_dn if 'user_dn' in locals() else username)
    
    def modify_user(self, username: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify user attributes.
        
        Args:
            username: Username to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Find user DN
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "modify_user")
            
            user_dn = user_results[0]['dn']
            
            # Prepare modifications
            modifications = {}
            for attr, value in attributes.items():
                if attr.lower() == 'password':
                    # Handle password separately
                    continue
                elif isinstance(value, list):
                    modifications[attr] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[attr] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying user: {username} ({user_dn})")
            
            # Apply modifications
            if modifications:
                success = self.ldap.modify(user_dn, modifications)
                if not success:
                    raise Exception("Failed to modify user attributes")
            
            # Handle password change separately
            if 'password' in attributes:
                self._set_user_password(user_dn, attributes['password'])
            
            log_ldap_operation("modify_user", user_dn, True, f"Modified user: {username}")
            
            return self._success_response(
                f"User '{username}' modified successfully",
                {
                    "username": username,
                    "dn": user_dn,
                    "modified_attributes": list(attributes.keys())
                }
            )
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_user", username)
    
    def delete_user(self, username: str) -> List[Dict[str, Any]]:
        """
        Delete a user from Active Directory.
        
        Args:
            username: Username to delete
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Find user DN
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "delete_user")
            
            user_dn = user_results[0]['dn']
            
            self.logger.info(f"Deleting user: {username} ({user_dn})")
            
            # Delete user
            success = self.ldap.delete(user_dn)
            
            if success:
                log_ldap_operation("delete_user", user_dn, True, f"Deleted user: {username}")
                
                return self._success_response(
                    f"User '{username}' deleted successfully",
                    {
                        "username": username,
                        "dn": user_dn
                    }
                )
            else:
                raise Exception("Failed to delete user")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_user", username)
    
    def enable_user(self, username: str) -> List[Dict[str, Any]]:
        """
        Enable a user account.
        
        Args:
            username: Username to enable
            
        Returns:
            List of MCP content objects with result
        """
        return self._set_user_account_control(username, 512, "enable")  # 512 = Normal account
    
    def disable_user(self, username: str) -> List[Dict[str, Any]]:
        """
        Disable a user account.
        
        Args:
            username: Username to disable
            
        Returns:
            List of MCP content objects with result
        """
        return self._set_user_account_control(username, 514, "disable")  # 514 = Disabled account
    
    def reset_password(self, username: str, new_password: Optional[str] = None, 
                      force_change: bool = True,
                      password_never_expires: bool = False) -> List[Dict[str, Any]]:
        """
        Reset user password.
        
        Args:
            username: Username to reset password for
            new_password: New password (if None, generates random password)
            force_change: Force user to change password at next logon
            password_never_expires: Set password to never expire (adds DONT_EXPIRE_PASSWORD flag)
            
        Returns:
            List of MCP content objects with result
            
        Note:
            force_change and password_never_expires are mutually exclusive in practice.
            If password_never_expires is True, force_change will be ignored as the password
            will be set to never expire.
        """
        try:
            # Find user DN and current userAccountControl
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "reset_password")
            
            user_dn = user_results[0]['dn']
            current_uac = self._get_attr(user_results[0]['attributes'], 'userAccountControl', 512)
            if isinstance(current_uac, list):
                current_uac = current_uac[0] if current_uac else 512
            current_uac = int(current_uac)
            
            # Generate password if not provided
            if new_password is None:
                new_password = self._generate_password()
            
            self.logger.info(f"Resetting password for user: {username}")
            
            # Set new password
            self._set_user_password(user_dn, new_password)
            
            # Handle password expiration settings
            if password_never_expires:
                # Add DONT_EXPIRE_PASSWORD flag (65536) to userAccountControl
                # Also ensure account is enabled (remove disabled flag 2 if present)
                new_uac = (current_uac | 65536) & ~2  # Add never expire, remove disabled
                self.ldap.modify(user_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                })
                self.logger.info(f"Set password never expires for user: {username} (UAC: {current_uac} -> {new_uac})")
            elif force_change:
                # Force password change at next logon by setting pwdLastSet to 0
                self.ldap.modify(user_dn, {
                    'pwdLastSet': [(MODIFY_REPLACE, [0])]
                })
            
            log_ldap_operation("reset_password", user_dn, True, f"Reset password for: {username}")
            
            return self._success_response(
                f"Password reset successfully for user '{username}'",
                {
                    "username": username,
                    "dn": user_dn,
                    "new_password": new_password,
                    "force_change": force_change and not password_never_expires,
                    "password_never_expires": password_never_expires
                }
            )
            
        except Exception as e:
            return self._handle_ldap_error(e, "reset_password", username)


    def get_user_groups(self, username: str) -> List[Dict[str, Any]]:
        """
        Get groups that a user is member of.
        
        Args:
            username: Username to get groups for
            
        Returns:
            List of MCP content objects with group information
        """
        try:
            # Get user's memberOf attribute
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['memberOf']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user_groups")
            
            user_dn = user_results[0]['dn']
            member_of = user_results[0]['attributes'].get('memberOf', [])
            
            # Get detailed group information
            groups = []
            for group_dn in member_of:
                try:
                    group_info = self.ldap.search(
                        search_base=group_dn,
                        search_filter="(objectClass=group)",
                        attributes=['sAMAccountName', 'displayName', 'description', 'groupType'],
                        search_scope=ldap3.BASE
                    )
                    
                    if group_info:
                        group_data = group_info[0]['attributes']
                        groups.append({
                            'dn': group_dn,
                            'sAMAccountName': self._get_attr(group_data, 'sAMAccountName', ''),
                            'displayName': self._get_attr(group_data, 'displayName', ''),
                            'description': self._get_attr(group_data, 'description', ''),
                            'groupType': self._get_attr(group_data, 'groupType', 0)
                        })
                except:
                    # Skip if group info cannot be retrieved
                    groups.append({'dn': group_dn, 'error': 'Could not retrieve group details'})
            
            log_ldap_operation("get_user_groups", user_dn, True, f"Retrieved {len(groups)} groups")
            
            return self._format_response({
                "username": username,
                "user_dn": user_dn,
                "groups": groups,
                "group_count": len(groups)
            }, "get_user_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_user_groups", username)
    
    def _set_user_account_control(self, username: str, uac_value: int, operation: str) -> List[Dict[str, Any]]:
        """Set user account control value."""
        try:
            # Find user DN
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, operation)
            
            user_dn = user_results[0]['dn']
            
            # Modify userAccountControl
            success = self.ldap.modify(user_dn, {
                'userAccountControl': [(MODIFY_REPLACE, [uac_value])]
            })
            
            if success:
                log_ldap_operation(operation, user_dn, True, f"{operation.capitalize()}d user: {username}")
                
                return self._success_response(
                    f"User '{username}' {operation}d successfully",
                    {
                        "username": username,
                        "dn": user_dn,
                        "userAccountControl": uac_value
                    }
                )
            else:
                raise Exception(f"Failed to {operation} user")
            
        except Exception as e:
            return self._handle_ldap_error(e, operation, username)
    
    def _set_user_password(self, user_dn: str, password: str) -> None:
        """Set user password using LDAP modify operation."""
        # Encode password for Active Directory
        password_encoded = f'"{password}"'.encode('utf-16-le')
        
        # Set password
        success = self.ldap.modify(user_dn, {
            'unicodePwd': [(MODIFY_REPLACE, [password_encoded])]
        })
        
        if not success:
            raise Exception("Failed to set user password")
    
    def _generate_password(self, length: int = 12) -> str:
        """Generate a random password."""
        # Ensure password meets complexity requirements
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        
        # Ensure at least one character from each category
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def _is_user_enabled(self, uac_value: int) -> bool:
        """Check if user account is enabled based on userAccountControl."""
        return not bool(uac_value & 0x0002)  # Check ACCOUNTDISABLE flag
    
    def _is_user_locked(self, uac_value: int) -> bool:
        """Check if user account is locked based on userAccountControl."""
        return bool(uac_value & 0x0010)  # Check LOCKOUT flag
    
    def _is_password_expired(self, attributes: Dict[str, Any]) -> bool:
        """Check if user password is expired."""
        pwd_last_set = self._get_attr(attributes, 'pwdLastSet', 0)
        return pwd_last_set == 0
    
    def _is_account_expired(self, attributes: Dict[str, Any]) -> bool:
        """Check if user account is expired."""
        account_expires = self._get_attr(attributes, 'accountExpires', 0)
        if account_expires == 0 or account_expires == 9223372036854775807:  # Never expires
            return False
        
        # Convert Windows timestamp to datetime
        try:
            expire_date = datetime(1601, 1, 1) + timedelta(microseconds=account_expires / 10)
            return expire_date < datetime.now()
        except:
            return False
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for user operations."""
        return {
            "operations": [
                "list_users", "get_user", "create_user", "modify_user", 
                "delete_user", "enable_user", "disable_user", "reset_password",
                "get_user_groups"
            ],
            "user_attributes": [
                "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn",
                "mail", "telephoneNumber", "department", "title", "manager", "description",
                "physicalDeliveryOfficeName", "company", "userAccountControl"
            ],
            "required_permissions": [
                "Create User Objects", "Delete User Objects", "Reset Password",
                "Enable/Disable User Account", "Modify User Attributes"
            ]
        }
