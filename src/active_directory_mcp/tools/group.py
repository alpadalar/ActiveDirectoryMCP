"""Group management tools for Active Directory."""

from typing import List, Dict, Any, Optional

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.logging import log_ldap_operation


class GroupTools(BaseTool):
    """Tools for managing Active Directory groups."""
    
    def list_groups(self, ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                   attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List groups in Active Directory.
        
        Args:
            ou: Organizational Unit to search in (optional)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with group information
        """
        try:
            # Determine search base
            if ou:
                search_base = ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter
            base_filter = "(objectClass=group)"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'description', 'mail',
                    'groupType', 'member', 'memberOf',
                    'whenCreated', 'whenChanged', 'managedBy'
                ]
            
            self.logger.info(f"Listing groups from {search_base}")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )
            
            # Process results
            groups = []
            for entry in results:
                group_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                    'displayName': self._get_attr(entry['attributes'], 'displayName', ''),
                    'description': self._get_attr(entry['attributes'], 'description', ''),
                    'groupType': self._get_attr(entry['attributes'], 'groupType', 0),
                    'memberCount': len(entry['attributes'].get('member') or [])
                }
                
                # Add group scope information
                group_type = self._get_attr(entry['attributes'], 'groupType', 0)
                group_info['scope'] = self._get_group_scope(group_type)
                group_info['type'] = self._get_group_type(group_type)
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'displayName', 'description', 'groupType'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if value is not None and isinstance(value, list) and len(value) == 1:
                            group_info[attr] = value[0]
                        else:
                            group_info[attr] = value
                
                groups.append(group_info)
            
            log_ldap_operation("list_groups", search_base, True, f"Found {len(groups)} groups")
            
            response_data = {
                "groups": groups,
                "count": len(groups),
                "search_base": search_base,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "list_groups", search_base)
    
    def get_group(self, group_name: str, attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get detailed information about a specific group.
        
        Args:
            group_name: Group name (sAMAccountName) to search for
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with group information
        """
        try:
            # Build search filter
            escaped_group_name = self._escape_ldap_filter(group_name)
            search_filter = f"(&(objectClass=group)(sAMAccountName={escaped_group_name}))"
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'description', 'mail',
                    'groupType', 'member', 'memberOf',
                    'whenCreated', 'whenChanged', 'managedBy', 'info'
                ]
            
            self.logger.info(f"Getting group information for: {group_name}")
            
            # Perform search
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=attributes
            )
            
            if not results:
                log_ldap_operation("get_group", group_name, False, "Group not found")
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "get_group")
            
            group_entry = results[0]
            group_info = {
                'dn': group_entry['dn'],
                'attributes': group_entry['attributes']
            }
            
            # Add computed fields
            group_type = self._get_attr(group_entry['attributes'], 'groupType', 0)
            group_info['computed'] = {
                'scope': self._get_group_scope(group_type),
                'type': self._get_group_type(group_type),
                'member_count': len(group_entry['attributes'].get('member') or []),
                'parent_groups_count': len(group_entry['attributes'].get('memberOf') or [])
            }
            
            log_ldap_operation("get_group", group_name, True, f"Retrieved group: {group_entry['dn']}")
            
            return self._format_response(group_info, "get_group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_group", group_name)
    
    def create_group(self, group_name: str, display_name: Optional[str] = None,
                    description: Optional[str] = None, ou: Optional[str] = None,
                    group_scope: str = "Global", group_type: str = "Security",
                    additional_attributes: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Create a new group in Active Directory.
        
        Args:
            group_name: Group name (sAMAccountName)
            display_name: Display name for the group (optional)
            description: Group description (optional)
            ou: Organizational Unit to create group in (optional)
            group_scope: Group scope (Global, DomainLocal, Universal)
            group_type: Group type (Security, Distribution)
            additional_attributes: Additional attributes to set (optional)
            
        Returns:
            List of MCP content objects with creation result
        """
        try:
            # Determine OU
            if ou is None:
                ou = self.ldap.ad_config.organizational_units.groups_ou
            
            # Use display_name if provided, otherwise use group_name
            if display_name is None:
                display_name = group_name
            
            # Build DN
            group_dn = f"CN={display_name},{ou}"
            
            # Check if group already exists
            existing_group = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(sAMAccountName={self._escape_ldap_filter(group_name)})",
                attributes=['sAMAccountName']
            )
            
            if existing_group:
                log_ldap_operation("create_group", group_dn, False, "Group already exists")
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' already exists",
                    "group_name": group_name
                }, "create_group")
            
            # Calculate groupType value
            group_type_value = self._calculate_group_type(group_scope, group_type)
            
            # Prepare group attributes
            group_attributes = {
                'objectClass': ['top', 'group'],
                'sAMAccountName': group_name,
                'cn': display_name,
                'displayName': display_name,
                'groupType': group_type_value
            }
            
            if description:
                group_attributes['description'] = description
            
            # Add additional attributes
            if additional_attributes:
                group_attributes.update(additional_attributes)
            
            self.logger.info(f"Creating group: {group_name} ({group_dn})")
            
            # Create group
            success = self.ldap.add(group_dn, group_attributes)
            
            if success:
                log_ldap_operation("create_group", group_dn, True, f"Created group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' created successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn,
                        "display_name": display_name,
                        "scope": group_scope,
                        "type": group_type
                    }
                )
            else:
                raise Exception("Failed to create group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "create_group", group_dn if 'group_dn' in locals() else group_name)
    
    def modify_group(self, group_name: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify group attributes.
        
        Args:
            group_name: Group name to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['dn']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "modify_group")
            
            group_dn = group_results[0]['dn']
            
            # Prepare modifications
            modifications = {}
            for attr, value in attributes.items():
                if isinstance(value, list):
                    modifications[attr] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[attr] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying group: {group_name} ({group_dn})")
            
            # Apply modifications
            success = self.ldap.modify(group_dn, modifications)
            
            if success:
                log_ldap_operation("modify_group", group_dn, True, f"Modified group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' modified successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn,
                        "modified_attributes": list(attributes.keys())
                    }
                )
            else:
                raise Exception("Failed to modify group attributes")
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_group", group_name)
    
    def delete_group(self, group_name: str) -> List[Dict[str, Any]]:
        """
        Delete a group from Active Directory.
        
        Args:
            group_name: Group name to delete
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['dn']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "delete_group")
            
            group_dn = group_results[0]['dn']
            
            self.logger.info(f"Deleting group: {group_name} ({group_dn})")
            
            # Delete group
            success = self.ldap.delete(group_dn)
            
            if success:
                log_ldap_operation("delete_group", group_dn, True, f"Deleted group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' deleted successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn
                    }
                )
            else:
                raise Exception("Failed to delete group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_group", group_name)
    
    def add_member(self, group_name: str, member_dn: str) -> List[Dict[str, Any]]:
        """
        Add a member to a group.
        
        Args:
            group_name: Group name to add member to
            member_dn: Distinguished name of member to add
            
        Returns:
            List of MCP content objects with result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['member']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "add_member")
            
            group_dn = group_results[0]['dn']
            current_members = group_results[0]['attributes'].get('member', [])
            
            # Check if member is already in group
            if member_dn in current_members:
                return self._format_response({
                    "success": False,
                    "error": f"Member '{member_dn}' is already in group '{group_name}'",
                    "group_name": group_name,
                    "member_dn": member_dn
                }, "add_member")
            
            self.logger.info(f"Adding member {member_dn} to group {group_name}")
            
            # Add member to group
            success = self.ldap.modify(group_dn, {
                'member': [(MODIFY_ADD, [member_dn])]
            })
            
            if success:
                log_ldap_operation("add_member", group_dn, True, f"Added member {member_dn} to group {group_name}")
                
                return self._success_response(
                    f"Member added to group '{group_name}' successfully",
                    {
                        "group_name": group_name,
                        "group_dn": group_dn,
                        "member_dn": member_dn
                    }
                )
            else:
                raise Exception("Failed to add member to group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "add_member", f"{group_name} -> {member_dn}")
    
    def remove_member(self, group_name: str, member_dn: str) -> List[Dict[str, Any]]:
        """
        Remove a member from a group.
        
        Args:
            group_name: Group name to remove member from
            member_dn: Distinguished name of member to remove
            
        Returns:
            List of MCP content objects with result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['member']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "remove_member")
            
            group_dn = group_results[0]['dn']
            current_members = group_results[0]['attributes'].get('member', [])
            
            # Check if member is in group
            if member_dn not in current_members:
                return self._format_response({
                    "success": False,
                    "error": f"Member '{member_dn}' is not in group '{group_name}'",
                    "group_name": group_name,
                    "member_dn": member_dn
                }, "remove_member")
            
            self.logger.info(f"Removing member {member_dn} from group {group_name}")
            
            # Remove member from group
            success = self.ldap.modify(group_dn, {
                'member': [(MODIFY_DELETE, [member_dn])]
            })
            
            if success:
                log_ldap_operation("remove_member", group_dn, True, f"Removed member {member_dn} from group {group_name}")
                
                return self._success_response(
                    f"Member removed from group '{group_name}' successfully",
                    {
                        "group_name": group_name,
                        "group_dn": group_dn,
                        "member_dn": member_dn
                    }
                )
            else:
                raise Exception("Failed to remove member from group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "remove_member", f"{group_name} -> {member_dn}")
    
    def get_members(self, group_name: str, recursive: bool = False) -> List[Dict[str, Any]]:
        """
        Get members of a group.
        
        Args:
            group_name: Group name to get members for
            recursive: Include members of nested groups
            
        Returns:
            List of MCP content objects with member information
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['member']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "get_members")
            
            group_dn = group_results[0]['dn']
            member_dns = group_results[0]['attributes'].get('member', [])
            
            members = []
            processed_groups = set()  # To avoid infinite recursion
            
            def process_members(dns_to_process, level=0):
                for member_dn in dns_to_process:
                    try:
                        # Get member details
                        member_info = self.ldap.search(
                            search_base=member_dn,
                            search_filter="(|(objectClass=user)(objectClass=group))",
                            attributes=['objectClass', 'sAMAccountName', 'displayName', 'member'],
                            search_scope=ldap3.BASE
                        )
                        
                        if member_info:
                            member_data = member_info[0]['attributes']
                            object_classes = member_data.get('objectClass', [])
                            
                            member_entry = {
                                'dn': member_dn,
                                'sAMAccountName': self._get_attr(member_data, 'sAMAccountName', ''),
                                'displayName': self._get_attr(member_data, 'displayName', ''),
                                'type': 'group' if 'group' in object_classes else 'user',
                                'level': level
                            }
                            
                            members.append(member_entry)
                            
                            # If recursive and this is a group, process its members
                            if recursive and 'group' in object_classes and member_dn not in processed_groups:
                                processed_groups.add(member_dn)
                                nested_members = member_data.get('member', [])
                                if nested_members:
                                    process_members(nested_members, level + 1)
                        
                    except Exception as e:
                        # Add error entry for members that can't be processed
                        members.append({
                            'dn': member_dn,
                            'error': f"Could not retrieve member details: {str(e)}",
                            'level': level
                        })
            
            # Process all members
            process_members(member_dns)
            
            log_ldap_operation("get_members", group_dn, True, f"Retrieved {len(members)} members")
            
            return self._format_response({
                "group_name": group_name,
                "group_dn": group_dn,
                "members": members,
                "member_count": len(members),
                "recursive": recursive
            }, "get_members")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_members", group_name)
    
    def _get_group_scope(self, group_type: int) -> str:
        """Get group scope from groupType value."""
        if group_type & 0x00000002:  # ADS_GROUP_TYPE_GLOBAL_GROUP  
            return "Global"
        elif group_type & 0x00000004:  # ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
            return "DomainLocal"
        elif group_type & 0x00000008:  # ADS_GROUP_TYPE_UNIVERSAL_GROUP
            return "Universal"
        else:
            return "Unknown"
    
    def _get_group_type(self, group_type: int) -> str:
        """Get group type from groupType value."""
        if group_type & 0x80000000:  # ADS_GROUP_TYPE_SECURITY_ENABLED
            return "Security"
        else:
            return "Distribution"
    
    def _calculate_group_type(self, scope: str, group_type: str) -> int:
        """Calculate groupType value from scope and type."""
        base_value = 0
        
        # Set scope
        if scope.lower() == "domainlocal":
            base_value |= 0x00000004  # ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
        elif scope.lower() == "global":
            base_value |= 0x00000002  # ADS_GROUP_TYPE_GLOBAL_GROUP
        elif scope.lower() == "universal":
            base_value |= 0x00000008  # ADS_GROUP_TYPE_UNIVERSAL_GROUP
        else:
            base_value |= 0x00000002  # Default to Global
        
        # Set type
        if group_type.lower() == "security":
            base_value |= 0x80000000  # ADS_GROUP_TYPE_SECURITY_ENABLED
        
        return base_value
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for group operations."""
        return {
            "operations": [
                "list_groups", "get_group", "create_group", "modify_group",
                "delete_group", "add_member", "remove_member", "get_members"
            ],
            "group_attributes": [
                "sAMAccountName", "displayName", "description", "mail",
                "groupType", "member", "memberOf", "managedBy"
            ],
            "group_scopes": ["Global", "DomainLocal", "Universal"],
            "group_types": ["Security", "Distribution"],
            "required_permissions": [
                "Create Group Objects", "Delete Group Objects",
                "Modify Group Membership", "Modify Group Attributes"
            ]
        }
