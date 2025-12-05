"""Base class for Active Directory tools."""

import json
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime

from mcp.types import TextContent as Content
from ldap3.core.exceptions import LDAPException

from ..core.ldap_manager import LDAPManager
from ..core.logging import get_logger, log_ldap_operation


class BaseTool(ABC):
    """Base class for all Active Directory tools."""
    
    def __init__(self, ldap_manager: LDAPManager):
        """
        Initialize base tool.
        
        Args:
            ldap_manager: LDAP manager instance
        """
        self.ldap = ldap_manager
        self.logger = get_logger(self.__class__.__name__)
    
    def _serialize_datetime(self, obj):
        """Helper function to serialize datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj
    
    def _format_response(self, data: Any, operation: str = "operation") -> List[Content]:
        """
        Format response data for MCP.
        
        Args:
            data: Data to format
            operation: Operation name for logging
            
        Returns:
            List of MCP content objects
        """
        try:
            # Serialize datetime objects before JSON conversion
            serialized_data = self._serialize_datetime(data)
            
            if isinstance(serialized_data, dict):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            elif isinstance(serialized_data, list):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(serialized_data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]
    
    def _handle_ldap_error(self, e: Exception, operation: str, dn: str = "") -> List[Content]:
        """
        Handle LDAP errors and format error response.
        
        Args:
            e: Exception that occurred
            operation: Operation that failed
            dn: Distinguished name (if applicable)
            
        Returns:
            List of MCP content objects with error information
        """
        error_msg = str(e)
        
        if isinstance(e, LDAPException):
            self.logger.error(f"LDAP error during {operation}: {error_msg}")
        else:
            self.logger.error(f"Unexpected error during {operation}: {error_msg}")
        
        # Log for audit
        if dn:
            log_ldap_operation(operation, dn, False, error_msg)
        
        error_response = {
            "success": False,
            "error": error_msg,
            "operation": operation,
            "type": type(e).__name__
        }
        
        if dn:
            error_response["dn"] = dn
        
        return [Content(type="text", text=json.dumps(error_response, indent=2))]
    
    def _validate_dn(self, dn: str) -> bool:
        """
        Validate Distinguished Name format.
        
        Args:
            dn: Distinguished name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not dn or not isinstance(dn, str):
            return False
        
        # Basic DN validation - should contain at least one component
        dn_parts = dn.split(',')
        for part in dn_parts:
            part = part.strip()
            if '=' not in part:
                return False
            
            key, value = part.split('=', 1)
            if not key.strip() or not value.strip():
                return False
        
        return True
    
    def _build_dn(self, name: str, ou: str) -> str:
        """
        Build Distinguished Name from name and organizational unit.
        
        Args:
            name: Object name (CN)
            ou: Organizational unit DN
            
        Returns:
            Complete DN
        """
        return f"CN={name},{ou}"
    
    def _success_response(self, message: str, data: Optional[Dict[str, Any]] = None) -> List[Content]:
        """
        Create success response.
        
        Args:
            message: Success message
            data: Optional additional data
            
        Returns:
            List of MCP content objects
        """
        response = {
            "success": True,
            "message": message
        }
        
        if data:
            response.update(data)
        
        return [Content(type="text", text=json.dumps(response, indent=2, ensure_ascii=False))]
    
    def _escape_ldap_filter(self, value: str) -> str:
        """
        Escape special characters in LDAP filter values.
        
        Args:
            value: Value to escape
            
        Returns:
            Escaped value
        """
        # Escape special LDAP filter characters
        escape_chars = {
            '*': r'\2a',
            '(': r'\28',
            ')': r'\29',
            '\\': r'\5c',
            '\x00': r'\00'
        }
        
        for char, escaped in escape_chars.items():
            value = value.replace(char, escaped)
        
        return value
    
    @abstractmethod
    def get_schema_info(self) -> Dict[str, Any]:
        """
        Get schema information for this tool's operations.
        
        Returns:
            Dictionary with schema information
        """
        pass

    def _get_attr(self, attributes: Dict, key: str, default=None):
        """
        Safely get attribute value from LDAP response.
        Handles both list and single value returns from ldap3.
        
        Args:
            attributes: Dict of attributes from LDAP response
            key: Attribute name
            default: Default value if not found
            
        Returns:
            Attribute value (first item if list, otherwise direct value)
        """
        value = attributes.get(key, default)
        if value is None:
            return default
        if isinstance(value, list):
            return value[0] if value else default
        return value
