"""LDAP connection manager for Active Directory."""

import logging
import ssl
import time
from typing import Optional, List, Dict, Any, Union
from threading import Lock

import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError

from ..config.models import ActiveDirectoryConfig, SecurityConfig, PerformanceConfig

logger = logging.getLogger(__name__)


class LDAPManager:
    """
    LDAP connection manager for Active Directory operations.
    
    Provides connection pooling, automatic reconnection, and error handling
    for LDAP operations against Active Directory.
    """
    
    def __init__(self, 
                 ad_config: ActiveDirectoryConfig,
                 security_config: SecurityConfig,
                 performance_config: PerformanceConfig):
        """
        Initialize LDAP manager.
        
        Args:
            ad_config: Active Directory configuration
            security_config: Security configuration
            performance_config: Performance configuration
        """
        self.ad_config = ad_config
        self.security_config = security_config
        self.performance_config = performance_config
        
        self._connection: Optional[Connection] = None
        self._server_pool: Optional[List[Server]] = None
        self._lock = Lock()
        
        self._setup_servers()
        
    def _setup_servers(self) -> None:
        """Setup LDAP servers and server pool."""
        try:
            # Setup TLS configuration
            tls_config = None
            if self.security_config.enable_tls:
                tls_config = ldap3.Tls(
                    validate=ssl.CERT_REQUIRED if self.security_config.validate_certificate else ssl.CERT_NONE,
                    ca_certs_file=self.security_config.ca_cert_file
                )
            
            # Create primary server
            primary_server = Server(
                self.ad_config.server,
                get_info=ALL,
                tls=tls_config,
                connect_timeout=self.ad_config.timeout
            )
            
            servers = [primary_server]
            
            # Add additional servers from pool
            if self.ad_config.server_pool:
                for server_url in self.ad_config.server_pool:
                    server = Server(
                        server_url,
                        get_info=ALL,
                        tls=tls_config,
                        connect_timeout=self.ad_config.timeout
                    )
                    servers.append(server)
            
            # Create server pool for failover
            self._server_pool = servers
            logger.info(f"Configured {len(servers)} LDAP servers")
            
        except Exception as e:
            logger.error(f"Error setting up LDAP servers: {e}")
            raise
    
    def connect(self) -> Connection:
        """
        Establish LDAP connection with retry logic.
        
        Returns:
            Connection: Active LDAP connection
            
        Raises:
            LDAPException: If connection fails after all retries
        """
        with self._lock:
            if self._connection and self._connection.bound:
                return self._connection
            
            last_error = None
            
            for attempt in range(self.performance_config.max_retries):
                try:
                    # Try each server in the pool
                    for server in self._server_pool:
                        try:
                            logger.debug(f"Attempting connection to {server.host}:{server.port}")
                            
                            connection = Connection(
                                server,
                                user=self.ad_config.bind_dn,
                                password=self.ad_config.password,
                                auto_bind=self.ad_config.auto_bind,
                                receive_timeout=self.ad_config.receive_timeout,
                                authentication=ldap3.SIMPLE,
                                check_names=True,
                                raise_exceptions=True
                            )
                            
                            # Test the connection
                            if connection.bind():
                                self._connection = connection
                                logger.info(f"Successfully connected to {server.host}:{server.port}")
                                return connection
                            else:
                                logger.warning(f"Failed to bind to {server.host}:{server.port}")
                                
                        except (LDAPSocketOpenError, LDAPBindError) as e:
                            logger.warning(f"Connection failed to {server.host}:{server.port}: {e}")
                            last_error = e
                            continue
                    
                    # If we get here, all servers failed for this attempt
                    if attempt < self.performance_config.max_retries - 1:
                        logger.info(f"Retry {attempt + 1}/{self.performance_config.max_retries} after {self.performance_config.retry_delay}s")
                        time.sleep(self.performance_config.retry_delay)
                    
                except Exception as e:
                    logger.error(f"Unexpected error during connection attempt {attempt + 1}: {e}")
                    last_error = e
                    
                    if attempt < self.performance_config.max_retries - 1:
                        time.sleep(self.performance_config.retry_delay)
            
            # All attempts failed
            error_msg = f"Failed to connect to any LDAP server after {self.performance_config.max_retries} attempts"
            if last_error:
                error_msg += f". Last error: {last_error}"
            
            logger.error(error_msg)
            raise LDAPException(error_msg)
    
    def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        with self._lock:
            if self._connection:
                try:
                    self._connection.unbind()
                    logger.info("Disconnected from LDAP server")
                except Exception as e:
                    logger.warning(f"Error during disconnect: {e}")
                finally:
                    self._connection = None
    
    def search(self, 
               search_base: str,
               search_filter: str,
               attributes: Union[List[str], str] = ALL_ATTRIBUTES,
               search_scope: str = SUBTREE,
               size_limit: int = 0) -> List[Dict[str, Any]]:
        """
        Perform LDAP search operation.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: Attributes to retrieve
            search_scope: Search scope (SUBTREE, ONELEVEL, BASE)
            size_limit: Maximum number of results (0 = no limit)
            
        Returns:
            List of LDAP entries as dictionaries
            
        Raises:
            LDAPException: If search fails
        """
        connection = self.connect()
        
        # Auto-reconnect if connection was lost (thread-safe)
        try:
            if not connection.bound:
                logger.info("Connection lost, reconnecting...")
                with self._lock:
                    self._connection = None
                    connection = self.connect()
        except Exception as e:
            logger.warning(f"Connection check failed: {e}, reconnecting...")
            with self._lock:
                self._connection = None
                connection = self.connect()
        
        try:
            logger.debug(f"Searching: base={search_base}, filter={search_filter}")
            
            # Perform paged search for large result sets
            paged_size = min(self.performance_config.page_size, size_limit) if size_limit > 0 else self.performance_config.page_size
            
            entries = []
            cookie = None
            
            while True:
                success = connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    paged_size=paged_size,
                    paged_cookie=cookie
                )
                
                if not success:
                    logger.error(f"Search failed: {connection.result}")
                    raise LDAPException(f"Search failed: {connection.result}")
                
                # Add entries to results
                for entry in connection.entries:
                    entry_dict = {
                        'dn': entry.entry_dn,
                        'attributes': {}
                    }
                    
                    for attr_name in entry.entry_attributes:
                        attr_value = getattr(entry, attr_name)
                        if hasattr(attr_value, 'value'):
                            entry_dict['attributes'][attr_name] = attr_value.value
                        else:
                            entry_dict['attributes'][attr_name] = str(attr_value)
                    
                    entries.append(entry_dict)
                    
                    # Check size limit
                    if size_limit > 0 and len(entries) >= size_limit:
                        logger.debug(f"Size limit reached: {size_limit}")
                        return entries[:size_limit]
                
                # Check for more pages
                cookie = connection.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                if not cookie:
                    break
            
            logger.debug(f"Search returned {len(entries)} entries")
            return entries
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            raise
    
    def add(self, dn: str, attributes: Dict[str, Any]) -> bool:
        """
        Add LDAP entry.
        
        Args:
            dn: Distinguished name of new entry
            attributes: Entry attributes
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self.connect()
        
        try:
            logger.debug(f"Adding entry: {dn}")
            
            success = connection.add(dn, attributes=attributes)
            
            if success:
                logger.info(f"Successfully added entry: {dn}")
                return True
            else:
                logger.error(f"Failed to add entry {dn}: {connection.result}")
                raise LDAPException(f"Add operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Add error for {dn}: {e}")
            raise
    
    def modify(self, dn: str, changes: Dict[str, Any]) -> bool:
        """
        Modify LDAP entry.
        
        Args:
            dn: Distinguished name of entry to modify
            changes: Dictionary of changes to apply
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self.connect()
        
        try:
            logger.debug(f"Modifying entry: {dn}")
            
            success = connection.modify(dn, changes)
            
            if success:
                logger.info(f"Successfully modified entry: {dn}")
                return True
            else:
                logger.error(f"Failed to modify entry {dn}: {connection.result}")
                raise LDAPException(f"Modify operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Modify error for {dn}: {e}")
            raise
    
    def delete(self, dn: str) -> bool:
        """
        Delete LDAP entry.
        
        Args:
            dn: Distinguished name of entry to delete
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self.connect()
        
        try:
            logger.debug(f"Deleting entry: {dn}")
            
            success = connection.delete(dn)
            
            if success:
                logger.info(f"Successfully deleted entry: {dn}")
                return True
            else:
                logger.error(f"Failed to delete entry {dn}: {connection.result}")
                raise LDAPException(f"Delete operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Delete error for {dn}: {e}")
            raise
    
    def move(self, dn: str, new_parent: str) -> bool:
        """
        Move LDAP entry to new parent.
        
        Args:
            dn: Distinguished name of entry to move
            new_parent: New parent DN
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self.connect()
        
        try:
            logger.debug(f"Moving entry {dn} to {new_parent}")
            
            success = connection.modify_dn(dn, new_superior=new_parent)
            
            if success:
                logger.info(f"Successfully moved entry {dn} to {new_parent}")
                return True
            else:
                logger.error(f"Failed to move entry {dn}: {connection.result}")
                raise LDAPException(f"Move operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Move error for {dn}: {e}")
            raise
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test LDAP connection and return server information.
        
        Returns:
            Dictionary with connection test results
        """
        try:
            connection = self.connect()
            
            # Get server info
            server_info = {
                'connected': True,
                'server': connection.server.host,
                'port': connection.server.port,
                'ssl': connection.server.ssl,
                'bound': connection.bound,
                'user': connection.user
            }
            
            # Try a simple search to test functionality
            try:
                connection.search(
                    search_base=self.ad_config.base_dn,
                    search_filter='(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=['namingContexts']
                )
                server_info['search_test'] = True
            except Exception as e:
                server_info['search_test'] = False
                server_info['search_error'] = str(e)
            
            logger.info("Connection test successful")
            return server_info
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                'connected': False,
                'error': str(e)
            }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
