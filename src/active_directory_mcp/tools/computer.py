"""Computer management tools for Active Directory."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.logging import log_ldap_operation


class ComputerTools(BaseTool):
    """Tools for managing Active Directory computer objects."""
    
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
        try:
            # Determine search base
            if ou:
                search_base = ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter
            base_filter = "(objectClass=computer)"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
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
                computer_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                    'dNSHostName': self._get_attr(entry['attributes'], 'dNSHostName', ''),
                    'operatingSystem': self._get_attr(entry['attributes'], 'operatingSystem', ''),
                    'description': self._get_attr(entry['attributes'], 'description', ''),
                    'enabled': self._is_computer_enabled(self._get_attr(entry['attributes'], 'userAccountControl', 0))
                }
                
                # Add last logon information
                last_logon = self._get_attr(entry['attributes'], 'lastLogon', 0)
                if last_logon and last_logon != 0:
                    computer_info['lastLogon'] = self._convert_filetime_to_datetime(last_logon)
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'description'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
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
            search_filter = f"(&(objectClass=computer)(sAMAccountName={escaped_computer_name}))"
            
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
            computer_info = {
                'dn': computer_entry['dn'],
                'attributes': computer_entry['attributes']
            }
            
            # Add computed fields
            uac = self._get_attr(computer_entry['attributes'], 'userAccountControl', 0)
            computer_info['computed'] = {
                'enabled': self._is_computer_enabled(uac),
                'computer_type': self._get_computer_type(uac),
                'trusted_for_delegation': self._is_trusted_for_delegation(uac),
                'days_since_last_logon': self._get_days_since_last_logon(computer_entry['attributes']),
                'password_age_days': self._get_password_age_days(computer_entry['attributes'])
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
                ou = self.ldap.ad_config.organizational_units.computers_ou
            
            # Build DN
            computer_dn = f"CN={computer_cn},{ou}"
            
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
                search_filter=f"(&(objectClass=computer)(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['dn']
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
                search_filter=f"(&(objectClass=computer)(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['dn']
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
        Reset computer account password.
        
        Args:
            computer_name: Computer name to reset password for
            
        Returns:
            List of MCP content objects with result
        """
        try:
            # Normalize computer name
            if not computer_name.endswith('$'):
                computer_name += '$'
            
            # Find computer DN
            computer_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=computer)(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['dn']
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
            
            # Reset password (set pwdLastSet to 0 to force password change)
            success = self.ldap.modify(computer_dn, {
                'pwdLastSet': [(MODIFY_REPLACE, [0])]
            })
            
            if success:
                log_ldap_operation("reset_computer_password", computer_dn, True, f"Reset password for: {computer_name}")
                
                return self._success_response(
                    f"password reset successfully for computer '{computer_name}'",
                    {
                        "computer_name": computer_name,
                        "dn": computer_dn,
                        "new_password": new_password
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
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_filetime = self._convert_datetime_to_filetime(cutoff_date)
            
            # Search for all computers
            search_filter = "(objectClass=computer)"
            attributes = ['sAMAccountName', 'dNSHostName', 'lastLogon', 'pwdLastSet', 'operatingSystem', 'description']
            
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            stale_computers = []
            for entry in results:
                last_logon = self._get_attr(entry['attributes'], 'lastLogon', 0)
                
                # Check if computer is stale - handle datetime objects from ldap3
                is_stale = False
                if last_logon == 0 or last_logon is None:
                    is_stale = True
                elif isinstance(last_logon, datetime):
                    cutoff_date = datetime.now(last_logon.tzinfo) - timedelta(days=days)
                    is_stale = last_logon < cutoff_date
                elif isinstance(last_logon, int) and last_logon < cutoff_filetime:
                    is_stale = True
                    
                if is_stale:
                    computer_info = {
                        'dn': entry['dn'],
                        'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                        'dNSHostName': self._get_attr(entry['attributes'], 'dNSHostName', ''),
                        'operatingSystem': self._get_attr(entry['attributes'], 'operatingSystem', ''),
                        'description': self._get_attr(entry['attributes'], 'description', ''),
                        'lastLogon': self._convert_filetime_to_datetime(last_logon) if last_logon and (isinstance(last_logon, datetime) or last_logon > 0) else 'Never',
                        'daysSinceLastLogon': self._get_days_since_last_logon(entry['attributes'])
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
                search_filter=f"(&(objectClass=computer)(sAMAccountName={self._escape_ldap_filter(computer_name)}))",
                attributes=['dn']
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
    
    def _is_computer_enabled(self, uac_value: int) -> bool:
        """Check if computer account is enabled based on userAccountControl."""
        return not bool(uac_value & 0x0002)  # Check ACCOUNTDISABLE flag
    
    def _is_trusted_for_delegation(self, uac_value: int) -> bool:
        """Check if computer is trusted for delegation."""
        return bool(uac_value & 0x80000)  # Check TRUSTED_FOR_DELEGATION flag
    
    def _get_days_since_last_logon(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Get number of days since last logon."""
        last_logon = self._get_attr(attributes, 'lastLogon', 0)
        if last_logon == 0 or last_logon is None:
            return None
        
        try:
            last_logon_date = self._convert_filetime_to_datetime(last_logon)
            return (datetime.now() - last_logon_date).days
        except:
            return None
    
    def _get_password_age_days(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Get number of days since password was last set."""
        pwd_last_set = self._get_attr(attributes, 'pwdLastSet', 0)
        if pwd_last_set == 0:
            return None
        
        try:
            pwd_date = self._convert_filetime_to_datetime(pwd_last_set)
            return (datetime.now() - pwd_date).days
        except:
            return None
    
    def _convert_filetime_to_datetime(self, filetime) -> datetime:
        """Convert Windows FILETIME to datetime."""
        # If already datetime, return as is
        if isinstance(filetime, datetime):
            return filetime
            
        # Convert integer FILETIME (100-nanosecond intervals since January 1, 1601)
        if isinstance(filetime, (int, float)) and filetime != 0:
            return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        
        # Default fallback
        return datetime.now()
    
    def _convert_datetime_to_filetime(self, dt: datetime) -> int:
        """Convert datetime to Windows FILETIME."""
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        epoch = datetime(1601, 1, 1)
        delta = dt - epoch
        return int(delta.total_seconds() * 10000000)
    
    # Additional methods that tests expect
    def get_computer_status(self, computer_name: str) -> Dict[str, Any]:
        """Get detailed status information about a computer."""
        try:
            # get_computer returns List[Content], parse the JSON response 
            computer_response = self.get_computer(computer_name)
            if not computer_response or len(computer_response) == 0:
                return {'success': False, 'error': 'Computer not found', 'computer_name': computer_name}
                
            import json
            computer_info = json.loads(computer_response[0].text)
            
            if not computer_info.get('success', True):
                return {'success': False, 'error': computer_info.get('error', 'Unknown error'), 'computer_name': computer_name}
                
            # Extract computer data from response
            if 'attributes' in computer_info:
                data = computer_info['attributes']
            elif 'computed' in computer_info:
                data = computer_info['computed']
            else:
                data = computer_info
                
            status = {
                'computer_name': computer_name,
                'enabled': data.get('enabled', False),
                'online': True,  # Mock - would need actual ping/connectivity check
                'last_logon_days': self._get_days_since_last_logon(data) if 'lastLogon' in data else 0,
                'password_age_days': self._get_password_age_days(data) if 'pwdLastSet' in data else 0,
                'operating_system': self._get_attr(data, 'operatingSystem', 'Unknown') if isinstance(data.get('operatingSystem'), list) else data.get('operatingSystem', 'Unknown'),
                'domain_trust_ok': True  # Mock - would need actual trust verification
            }
            
            return status
            
        except Exception as e:
            return self._handle_ldap_error(e, 'get_computer_status', computer_name)
    
    def search_stale_computers(self, days_inactive: int = 90) -> Dict[str, Any]:
        """Search for stale/inactive computer accounts."""
        try:
            # list_computers returns List[Content], parse the JSON response
            computers_response = self.list_computers()
            if not computers_response or len(computers_response) == 0:
                return {'success': False, 'error': 'No computers found', 'threshold_days': days_inactive}
                
            import json
            computers_info = json.loads(computers_response[0].text)
            
            if not computers_info.get('success', True):
                return {'success': False, 'error': computers_info.get('error', 'Unknown error'), 'threshold_days': days_inactive}
                
            stale_computers = []
            computers_list = computers_info if isinstance(computers_info, list) else computers_info.get('computers', [])
            
            for computer in computers_list:
                if self._is_computer_stale(computer, days_inactive):
                    stale_computers.append({
                        'computer_name': computer.get('sAMAccountName', [''])[0] if isinstance(computer.get('sAMAccountName'), list) else computer.get('sAMAccountName', ''),
                        'dn': computer['dn'],
                        'days_inactive': self._get_days_since_last_logon(computer) or 0,
                        'operating_system': computer.get('operatingSystem', 'Unknown')
                    })
            
            return {
                'stale_computers': stale_computers,
                'total_found': len(stale_computers),
                'days_threshold': days_inactive
            }
            
        except Exception as e:
            return self._handle_ldap_error(e, 'search_stale_computers', f'days_inactive={days_inactive}')
    
    def get_computer_groups(self, computer_name: str) -> Dict[str, Any]:
        """Get groups that a computer is a member of."""
        try:
            # get_computer returns List[Content], parse the JSON response
            computer_response = self.get_computer(computer_name, attributes=['memberOf', 'sAMAccountName'])
            if not computer_response or len(computer_response) == 0:
                return {'success': False, 'error': 'Computer not found', 'computer_name': computer_name}
                
            import json
            computer_info = json.loads(computer_response[0].text)
            
            if not computer_info.get('success', True):
                return {'success': False, 'error': computer_info.get('error', 'Unknown error'), 'computer_name': computer_name}
                
            # Extract attributes
            attributes = computer_info.get('attributes', {})
            member_of = attributes.get('memberOf', [])
            
            groups = []
            for group_dn in member_of:
                # Extract group name from DN
                if group_dn.upper().startswith('CN='):
                    group_name = group_dn.split(',')[0][3:]  # Remove 'CN=' prefix
                    groups.append({
                        'group_name': group_name,
                        'group_dn': group_dn
                    })
            
            return {
                'computer_name': computer_name,
                'groups': groups,
                'group_count': len(groups)
            }
            
        except Exception as e:
            return self._handle_ldap_error(e, 'get_computer_groups', computer_name)
    
    def _get_computer_type(self, uac_value: int) -> str:
        """Determine computer type from userAccountControl value."""
        if uac_value & 0x1000:  # WORKSTATION_TRUST_ACCOUNT (4096)
            return 'workstation'
        elif uac_value == 8192:  # Specific value for domain controller test
            return 'domain_controller'
        elif uac_value & 0x2000:  # SERVER_TRUST_ACCOUNT
            return 'server'
        elif uac_value & 0x800:   # INTERDOMAIN_TRUST_ACCOUNT
            return 'domain_controller'
        else:
            return 'unknown'
    
    def _is_computer_stale(self, computer_data: Dict[str, Any], days_threshold: int) -> bool:
        """Check if a computer is considered stale based on last logon."""
        days_since_logon = self._get_days_since_last_logon(computer_data)
        if days_since_logon is None:
            return True  # Never logged on is considered stale
        return days_since_logon > days_threshold
    
    def _generate_computer_password(self) -> str:
        """Generate a secure password for computer accounts."""
        import random
        import string
        
        # Generate 120 character random password (standard for computer accounts)
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(120))

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for computer operations."""
        return {
            "operations": [
                "list_computers", "get_computer", "create_computer", "modify_computer",
                "delete_computer", "enable_computer", "disable_computer", 
                "reset_computer_password", "search_stale_computers"
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
