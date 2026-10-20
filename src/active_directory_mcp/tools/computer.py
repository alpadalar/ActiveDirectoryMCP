"""Computer management tools for Active Directory."""

import secrets
import string
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from .. import validation
from ..validation import ValidationError
from ..core.logging import log_ldap_operation
from ..redaction import register_secret


class ComputerTools(BaseTool):
    """Tools for managing Active Directory computer objects."""
    
    def _computer_filter(self) -> str:
        """Base filter for computer objects using the configured (validated) objectClass."""
        return f"(objectClass={self.ldap.ad_config.computer_object_class})"

    def list_computers(self, ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                      attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List computer objects in Active Directory.
        
        Args:
            ou: Organizational Unit to search in (optional)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with computer information
        """
        search_base = ou or self.ldap.ad_config.base_dn
        try:
            # Determine search base (confined to base_dn)
            if ou:
                search_base = self._confined_dn(ou)

            # Build search filter (filter_criteria validated before any LDAP call)
            search_filter = validation.combine_filters(
                self._computer_filter(), filter_criteria or None
            )
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                    'operatingSystemServicePack', 'description', 'whenCreated', 'whenChanged',
                    'lastLogon', 'userAccountControl', 'pwdLastSet', 'servicePrincipalName'
                ]
            
            self.logger.info(f"Listing computers from {search_base}")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )
            
            # Process results
            computers = []
            for entry in results:
                entry_attrs = entry['attributes']
                computer_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr_value(entry['attributes'], 'sAMAccountName', ''),
                    'dNSHostName': self._get_attr_value(entry['attributes'], 'dNSHostName', ''),
                    'operatingSystem': self._get_attr_value(entry['attributes'], 'operatingSystem', ''),
                    'description': self._get_attr_value(entry['attributes'], 'description', ''),
                    'enabled': self._is_computer_enabled(self._get_attr_value(entry['attributes'], 'userAccountControl', 0))
                }

                # Add last logon information
                last_logon = self._ad_datetime(self._get_attr_value(entry['attributes'], 'lastLogon'))
                if last_logon is not None:
                    computer_info['lastLogon'] = last_logon
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'description'] and attr in entry_attrs:
                        value = entry_attrs[attr]
                        if isinstance(value, list) and len(value) == 1:
                            computer_info[attr] = value[0]
                        else:
                            computer_info[attr] = value
                
                computers.append(computer_info)
            
            log_ldap_operation("list_computers", search_base, True, f"Found {len(computers)} computers")
            
            response_data = {
                "computers": computers,
                "count": len(computers),
                "search_base": search_base,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_computers")
            
        except ValidationError as e:
            return self._validation_error_response(e, "list_computers", search_base)
        except Exception as e:
            return self._handle_ldap_error(e, "list_computers", search_base)
    
    def get_computer(self, computer_name: str, attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get detailed information about a specific computer.
        
        Args:
            computer_name: Computer name (sAMAccountName) to search for
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with computer information
        """
        try:
            # Normalize computer name (add $ if not present)
            if not computer_name.endswith('$'):
                computer_name += '$'
            
            # Build search filter
            escaped_computer_name = self._escape_ldap_filter(computer_name)
            search_filter = f"(&{self._computer_filter()}(sAMAccountName={escaped_computer_name}))"
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                    'operatingSystemServicePack', 'description', 'whenCreated', 'whenChanged',
                    'lastLogon', 'userAccountControl', 'pwdLastSet', 'servicePrincipalName',
                    'memberOf', 'location', 'managedBy'
                ]
            
            self.logger.info(f"Getting computer information for: {computer_name}")
            
            # Perform search
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            if not results:
                log_ldap_operation("get_computer", computer_name, False, "Computer not found")
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' not found",
                    "computer_name": computer_name
                }, "get_computer")
            
            computer_entry = results[0]
            computer_attrs = computer_entry['attributes']
            computer_info = {
                'dn': computer_entry['dn'],
                'attributes': computer_attrs
            }

            # Add computed fields
            uac = self._get_attr_value(computer_entry['attributes'], 'userAccountControl', 0)
            computer_info['computed'] = {
                'enabled': self._is_computer_enabled(uac),
                'computer_type': self._get_computer_type(uac),
                'trusted_for_delegation': self._is_trusted_for_delegation(uac),
                'days_since_last_logon': self._get_days_since_last_logon(computer_attrs),
                'password_age_days': self._get_password_age_days(computer_attrs)
            }
            
            log_ldap_operation("get_computer", computer_name, True, f"Retrieved computer: {computer_entry['dn']}")
            
            return self._format_response(computer_info, "get_computer")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_computer", computer_name)
    
    def create_computer(self, computer_name: str, description: Optional[str] = None,
                       ou: Optional[str] = None, dns_hostname: Optional[str] = None,
                       additional_attributes: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Create a new computer object in Active Directory.
        
        Args:
            computer_name: Computer name (without $ suffix)
            description: Computer description (optional)
            ou: Organizational Unit to create computer in (optional)
            dns_hostname: DNS hostname (optional)
            additional_attributes: Additional attributes to set (optional)
            
        Returns:
            List of MCP content objects with creation result
        """
        try:
            # Normalize computer name
            sam_account_name = computer_name if computer_name.endswith('$') else f"{computer_name}$"
            computer_cn = computer_name.rstrip('$')
            
            # Determine OU
            if ou is None:
                ou = self.ldap.organizational_units.computers_ou
            
            # Build DN (escaped RDN value, parent confined to base_dn)
            computer_dn = self._build_dn(computer_cn, ou)
            
            # Check if computer already exists
            existing_computer = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(sAMAccountName={self._escape_ldap_filter(sam_account_name)})",
                attributes=['sAMAccountName']
            )
            
            if existing_computer:
                log_ldap_operation("create_computer", computer_dn, False, "Computer already exists")
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' already exists",
                    "computer_name": computer_name
                }, "create_computer")
            
            # Prepare computer attributes
            computer_attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                'sAMAccountName': sam_account_name,
                'cn': computer_cn,
                'userAccountControl': 4128  # Workstation trust account, disabled
            }
            
            if dns_hostname:
                computer_attributes['dNSHostName'] = dns_hostname
            else:
                computer_attributes['dNSHostName'] = f"{computer_cn}.{self.ldap.ad_config.domain}"
            
            if description:
                computer_attributes['description'] = description
            
            # Add Service Principal Names
            spns = [
                f"HOST/{computer_cn}",
                f"HOST/{computer_attributes['dNSHostName']}"
            ]
            computer_attributes['servicePrincipalName'] = spns
            
            # Add additional attributes
            if additional_attributes:
                computer_attributes.update(additional_attributes)
            
            self.logger.info(f"Creating computer: {computer_name} ({computer_dn})")
            
            # Create computer
            success = self.ldap.add(computer_dn, computer_attributes)
            
            if success:
                # Enable the computer account
                try:
                    self.ldap.modify(computer_dn, {
                        'userAccountControl': [(MODIFY_REPLACE, [4096])]  # Enabled workstation trust account
                    })
                except Exception as enable_error:
                    self.logger.warning(f"Computer created but enabling failed: {enable_error}")
                
                log_ldap_operation("create_computer", computer_dn, True, f"Created computer: {computer_name}")
                
                return self._success_response(
                    f"Computer '{computer_name}' created successfully",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn,
                        "sam_account_name": sam_account_name,
                        "dns_hostname": computer_attributes['dNSHostName']
                    }
                )
            else:
                raise Exception("Failed to create computer object")
            
        except ValidationError as e:
            return self._validation_error_response(e, "create_computer", ou or "")
        except Exception as e:
            return self._handle_ldap_error(e, "create_computer", computer_dn if 'computer_dn' in locals() else computer_name)
    
    def modify_computer(self, computer_name: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify computer attributes.
        
        Args:
            computer_name: Computer name to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Normalize computer name
            if not computer_name.endswith('$'):
                computer_name += '$'

            # Find computer DN
            computer_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&{self._computer_filter()}(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['sAMAccountName']  # DN is always returned separately, not as an attribute
            )

            if not computer_results:
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' not found",
                    "computer_name": computer_name
                }, "modify_computer")
            
            computer_dn = computer_results[0]['dn']
            
            # Prepare modifications
            modifications = {}
            for attr, value in attributes.items():
                if isinstance(value, list):
                    modifications[attr] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[attr] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying computer: {computer_name} ({computer_dn})")
            
            # Apply modifications
            success = self.ldap.modify(computer_dn, modifications)
            
            if success:
                log_ldap_operation("modify_computer", computer_dn, True, f"Modified computer: {computer_name}")
                
                return self._success_response(
                    f"Computer '{computer_name}' modified successfully",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn,
                        "modified_attributes": list(attributes.keys())
                    }
                )
            else:
                raise Exception("Failed to modify computer attributes")
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_computer", computer_name)
    
    def delete_computer(self, computer_name: str) -> List[Dict[str, Any]]:
        """
        Delete a computer from Active Directory.
        
        Args:
            computer_name: Computer name to delete
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Normalize computer name
            if not computer_name.endswith('$'):
                computer_name += '$'

            # Find computer DN
            computer_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&{self._computer_filter()}(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['sAMAccountName']  # DN is always returned separately, not as an attribute
            )

            if not computer_results:
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' not found",
                    "computer_name": computer_name
                }, "delete_computer")
            
            computer_dn = computer_results[0]['dn']
            
            self.logger.info(f"Deleting computer: {computer_name} ({computer_dn})")
            
            # Delete computer
            success = self.ldap.delete(computer_dn)
            
            if success:
                log_ldap_operation("delete_computer", computer_dn, True, f"Deleted computer: {computer_name}")
                
                return self._success_response(
                    f"Computer '{computer_name}' deleted successfully",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn
                    }
                )
            else:
                raise Exception("Failed to delete computer")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_computer", computer_name)
    
    def enable_computer(self, computer_name: str) -> List[Dict[str, Any]]:
        """
        Enable a computer account.
        
        Args:
            computer_name: Computer name to enable
            
        Returns:
            List of MCP content objects with result
        """
        return self._set_computer_account_control(computer_name, 4096, "enable")  # 4096 = Enabled workstation trust account
    
    def disable_computer(self, computer_name: str) -> List[Dict[str, Any]]:
        """
        Disable a computer account.
        
        Args:
            computer_name: Computer name to disable
            
        Returns:
            List of MCP content objects with result
        """
        return self._set_computer_account_control(computer_name, 4098, "disable")  # 4098 = Disabled workstation trust account
    
    def reset_computer_password(self, computer_name: str) -> List[Dict[str, Any]]:
        """
        Set a new random machine-account password (TLS required).

        The generated password is applied via unicodePwd and returned once in the
        response (sensitive; never logged). The machine's secure channel breaks and
        it must be rejoined or re-synced afterwards.

        Args:
            computer_name: Computer name to reset password for

        Returns:
            List of MCP content objects with result
        """
        try:
            refusal = self._require_secure_channel("reset_computer_password")
            if refusal is not None:
                return refusal

            # Normalize computer name
            if not computer_name.endswith('$'):
                computer_name += '$'

            # Find computer DN
            computer_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&{self._computer_filter()}(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['sAMAccountName']  # DN is always returned separately, not as an attribute
            )

            if not computer_results:
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' not found",
                    "computer_name": computer_name
                }, "reset_computer_password")
            
            computer_dn = computer_results[0]['dn']
            
            self.logger.info(f"Resetting password for computer: {computer_name}")
            
            # Generate new computer password (computers use complex passwords)
            new_password = self._generate_computer_password()
            
            register_secret(new_password, persistent=False)

            # Apply the password (unicodePwd: quoted UTF-16-LE)
            success = self.ldap.modify(computer_dn, {
                'unicodePwd': [(MODIFY_REPLACE, [f'"{new_password}"'.encode('utf-16-le')])]
            })
            
            if success:
                log_ldap_operation("reset_computer_password", computer_dn, True, f"Reset password for: {computer_name}")
                
                return self._success_response(
                    f"password reset successfully for computer '{computer_name}'",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn,
                        "new_password": new_password,
                        "sensitive": True
                    }
                )
            else:
                raise Exception("Failed to reset computer password")
            
        except Exception as e:
            return self._handle_ldap_error(e, "reset_computer_password", computer_name)
    
    def get_stale_computers(self, days: int = 90) -> List[Dict[str, Any]]:
        """
        Get computers that haven't logged in for specified number of days.
        
        Args:
            days: Number of days to consider stale (default: 90)
            
        Returns:
            List of MCP content objects with stale computer information
        """
        try:
            # Calculate cutoff date (UTC-aware, matching the shared AD time helpers)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

            # Search for all computers
            search_filter = self._computer_filter()
            attributes = ['sAMAccountName', 'dNSHostName', 'lastLogon', 'pwdLastSet', 'operatingSystem', 'description']

            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )

            stale_computers = []
            for entry in results:
                entry_attrs = entry['attributes']
                last_logon = self._ad_datetime(self._get_attr_value(entry_attrs, 'lastLogon'))

                # Never logged on (None) or logged on before the cutoff is stale
                if last_logon is None or last_logon < cutoff_date:
                    computer_info = {
                        'dn': entry['dn'],
                        'sAMAccountName': self._get_attr_value(entry_attrs, 'sAMAccountName', ''),
                        'dNSHostName': self._get_attr_value(entry_attrs, 'dNSHostName', ''),
                        'operatingSystem': self._get_attr_value(entry_attrs, 'operatingSystem', ''),
                        'description': self._get_attr_value(entry_attrs, 'description', ''),
                        'lastLogon': last_logon if last_logon is not None else 'Never',
                        'daysSinceLastLogon': self._get_days_since_last_logon(entry_attrs)
                    }
                    stale_computers.append(computer_info)

            log_ldap_operation("get_stale_computers", self.ldap.ad_config.base_dn, True, f"Found {len(stale_computers)} stale computers")
            
            return self._format_response({
                "stale_computers": stale_computers,
                "count": len(stale_computers),
                "criteria_days": days,
                "cutoff_date": cutoff_date.isoformat()
            }, "get_stale_computers")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_stale_computers", self.ldap.ad_config.base_dn)
    
    def _set_computer_account_control(self, computer_name: str, uac_value: int, operation: str) -> List[Dict[str, Any]]:
        """Set computer account control value."""
        try:
            # Normalize computer name
            if not computer_name.endswith('$'):
                computer_name += '$'

            # Find computer DN
            computer_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&{self._computer_filter()}(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['sAMAccountName']  # DN is always returned separately, not as an attribute
            )

            if not computer_results:
                return self._format_response({
                    "success": False,
                    "error": f"Computer '{computer_name}' not found",
                    "computer_name": computer_name
                }, operation)
            
            computer_dn = computer_results[0]['dn']
            
            # Modify userAccountControl
            success = self.ldap.modify(computer_dn, {
                'userAccountControl': [(MODIFY_REPLACE, [uac_value])]
            })
            
            if success:
                log_ldap_operation(operation, computer_dn, True, f"{operation.capitalize()}d computer: {computer_name}")
                
                return self._success_response(
                    f"Computer '{computer_name}' {operation}d successfully",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn,
                        "userAccountControl": uac_value
                    }
                )
            else:
                raise Exception(f"Failed to {operation} computer")
            
        except Exception as e:
            return self._handle_ldap_error(e, operation, computer_name)
    
    def _is_computer_enabled(self, uac_value: int) -> Optional[bool]:
        """Check if computer account is enabled (None if userAccountControl is unknown)."""
        value = self._to_int(uac_value)
        if value is None:
            return None
        return not bool(value & 0x0002)  # Check ACCOUNTDISABLE flag
    
    def _is_trusted_for_delegation(self, uac_value: int) -> bool:
        """Check if computer is trusted for delegation."""
        value = self._to_int(uac_value, 0)
        return bool(value & 0x80000)  # Check TRUSTED_FOR_DELEGATION flag
    
    def _get_days_since_last_logon(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Days since last logon; None when the computer never logged on."""
        return self._days_since(self._get_attr_value(attributes, 'lastLogon'))

    def _get_password_age_days(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Days since the machine password was set; None when unset."""
        return self._days_since(self._get_attr_value(attributes, 'pwdLastSet'))

    def _get_computer_type(self, uac_value: int) -> str:
        """Determine computer type from userAccountControl value."""
        value = self._to_int(uac_value, 0)
        if value & 0x1000:  # WORKSTATION_TRUST_ACCOUNT (4096)
            return 'workstation'
        elif value == 8192:  # Domain controller (exact value)
            return 'domain_controller'
        elif value & 0x2000:  # SERVER_TRUST_ACCOUNT
            return 'server'
        elif value & 0x800:   # INTERDOMAIN_TRUST_ACCOUNT
            return 'domain_controller'
        else:
            return 'unknown'
    
    def _generate_computer_password(self) -> str:
        """Generate a secure password for computer accounts."""
        # 120 characters from a CSPRNG (standard length for computer accounts)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(120))

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for computer operations."""
        return {
            "operations": [
                "list_computers", "get_computer", "create_computer", "modify_computer",
                "delete_computer", "enable_computer", "disable_computer", 
                "reset_computer_password", "get_stale_computers"
            ],
            "computer_attributes": [
                "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                "operatingSystemServicePack", "description", "servicePrincipalName",
                "userAccountControl", "lastLogon", "pwdLastSet", "memberOf"
            ],
            "computer_types": ["workstation", "server", "domain_controller", "unknown"],
            "required_permissions": [
                "Create Computer Objects", "Delete Computer Objects",
                "Reset Computer Password", "Enable/Disable Computer Account",
                "Modify Computer Attributes"
            ]
        }
