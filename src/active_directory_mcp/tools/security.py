"""Security and audit tools for Active Directory."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import base64

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.logging import log_ldap_operation


class SecurityTools(BaseTool):
    """Tools for Active Directory security operations and auditing."""
    
    def get_domain_info(self) -> List[Dict[str, Any]]:
        """
        Get domain information and security settings.
        
        Returns:
            List of MCP content objects with domain information
        """
        try:
            # Get domain root object
            domain_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter="(objectClass=domain)",
                attributes=[
                    'name', 'dc', 'objectSid', 'whenCreated', 'whenChanged',
                    'lockoutThreshold', 'lockoutDuration', 'maxPwdAge', 'minPwdAge',
                    'minPwdLength', 'pwdHistoryLength', 'forceLogoff',
                    'functionalLevel', 'gPLink'
                ],
                search_scope=ldap3.BASE
            )
            
            if not domain_results:
                raise Exception("Domain information not found")
            
            domain_entry = domain_results[0]
            domain_info = {
                'dn': domain_entry['dn'],
                'name': domain_entry['attributes'].get('name', [''])[0],
                'domain_component': domain_entry['attributes'].get('dc', [''])[0],
                'object_sid': domain_entry['attributes'].get('objectSid', [b''])[0],
                'when_created': domain_entry['attributes'].get('whenCreated', [None])[0],
                'when_changed': domain_entry['attributes'].get('whenChanged', [None])[0]
            }
            
            # Password policy information
            password_policy = {
                'lockout_threshold': domain_entry['attributes'].get('lockoutThreshold', [0])[0],
                'lockout_duration': self._convert_time_interval(domain_entry['attributes'].get('lockoutDuration', [0])[0]),
                'max_password_age': self._convert_time_interval(domain_entry['attributes'].get('maxPwdAge', [0])[0]),
                'min_password_age': self._convert_time_interval(domain_entry['attributes'].get('minPwdAge', [0])[0]),
                'min_password_length': domain_entry['attributes'].get('minPwdLength', [0])[0],
                'password_history_length': domain_entry['attributes'].get('pwdHistoryLength', [0])[0]
            }
            
            domain_info['password_policy'] = password_policy
            
            log_ldap_operation("get_domain_info", self.ldap.ad_config.base_dn, True, "Retrieved domain information")
            
            return self._format_response(domain_info, "get_domain_info")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_domain_info", self.ldap.ad_config.base_dn)
    
    def get_privileged_groups(self) -> List[Dict[str, Any]]:
        """
        Get information about privileged groups in the domain.
        
        Returns:
            List of MCP content objects with privileged group information
        """
        try:
            # Well-known privileged groups
            privileged_groups = [
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Account Operators", "Backup Operators",
                "Print Operators", "Server Operators", "Domain Controllers"
            ]
            
            groups_info = []
            
            for group_name in privileged_groups:
                try:
                    # Search for the group
                    group_results = self.ldap.search(
                        search_base=self.ldap.ad_config.base_dn,
                        search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                        attributes=['sAMAccountName', 'displayName', 'description', 'member', 'objectSid']
                    )
                    
                    if group_results:
                        group_entry = group_results[0]
                        members = group_entry['attributes'].get('member', [])
                        
                        group_info = {
                            'dn': group_entry['dn'],
                            'sam_account_name': group_entry['attributes'].get('sAMAccountName', [''])[0],
                            'display_name': group_entry['attributes'].get('displayName', [''])[0],
                            'description': group_entry['attributes'].get('description', [''])[0],
                            'member_count': len(members),
                            'members': members[:10],  # First 10 members
                            'object_sid': group_entry['attributes'].get('objectSid', [b''])[0]
                        }
                        
                        if len(members) > 10:
                            group_info['members_truncated'] = True
                            group_info['total_members'] = len(members)
                        
                        groups_info.append(group_info)
                        
                except Exception as group_error:
                    # Continue with other groups if one fails
                    self.logger.warning(f"Failed to get info for group {group_name}: {group_error}")
                    continue
            
            log_ldap_operation("get_privileged_groups", self.ldap.ad_config.base_dn, True, f"Retrieved {len(groups_info)} privileged groups")
            
            return self._format_response({
                "privileged_groups": groups_info,
                "total_found": len(groups_info)
            }, "get_privileged_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_privileged_groups", self.ldap.ad_config.base_dn)
    
    def get_user_permissions(self, username: str) -> List[Dict[str, Any]]:
        """
        Get effective permissions for a user by analyzing group memberships.
        
        Args:
            username: Username to analyze permissions for
            
        Returns:
            List of MCP content objects with user permission information
        """
        try:
            # Get user information
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName', 'displayName', 'memberOf', 'userAccountControl']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user_permissions")
            
            user_entry = user_results[0]
            member_of = user_entry['attributes'].get('memberOf', [])
            
            # Analyze group memberships
            group_analysis = []
            privileged_groups = []
            
            for group_dn in member_of:
                try:
                    group_info = self.ldap.search(
                        search_base=group_dn,
                        search_filter="(objectClass=group)",
                        attributes=['sAMAccountName', 'displayName', 'description', 'objectSid'],
                        search_scope=ldap3.BASE
                    )
                    
                    if group_info:
                        group_data = group_info[0]['attributes']
                        group_name = group_data.get('sAMAccountName', [''])[0]
                        
                        group_entry = {
                            'dn': group_dn,
                            'sam_account_name': group_name,
                            'display_name': group_data.get('displayName', [''])[0],
                            'description': group_data.get('description', [''])[0]
                        }
                        
                        # Check if it's a privileged group
                        if self._is_privileged_group(group_name):
                            group_entry['privileged'] = True
                            privileged_groups.append(group_entry)
                        else:
                            group_entry['privileged'] = False
                        
                        group_analysis.append(group_entry)
                        
                except Exception:
                    # Skip groups that can't be analyzed
                    continue
            
            # Check account status
            uac = user_entry['attributes'].get('userAccountControl', [0])[0]
            account_status = {
                'enabled': not bool(uac & 0x0002),  # ACCOUNTDISABLE
                'locked': bool(uac & 0x0010),       # LOCKOUT
                'password_not_required': bool(uac & 0x0020),  # PASSWD_NOTREQD
                'password_cant_change': bool(uac & 0x0040),   # PASSWD_CANT_CHANGE
                'password_never_expires': bool(uac & 0x10000)  # DONT_EXPIRE_PASSWORD
            }
            
            user_permissions = {
                'username': username,
                'user_dn': user_entry['dn'],
                'display_name': user_entry['attributes'].get('displayName', [''])[0],
                'account_status': account_status,
                'total_groups': len(member_of),
                'privileged_groups_count': len(privileged_groups),
                'privileged_groups': privileged_groups,
                'all_groups': group_analysis,
                'security_assessment': self._assess_user_security(account_status, privileged_groups)
            }
            
            log_ldap_operation("get_user_permissions", username, True, f"Analyzed permissions for user: {username}")
            
            return self._format_response(user_permissions, "get_user_permissions")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_user_permissions", username)
    
    def get_inactive_users(self, days: int = 90, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """
        Get users who haven't logged in for specified number of days.
        
        Args:
            days: Number of days to consider inactive (default: 90)
            include_disabled: Include disabled accounts in results (default: False)
            
        Returns:
            List of MCP content objects with inactive user information
        """
        try:
            # Calculate cutoff date
            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_filetime = self._convert_datetime_to_filetime(cutoff_date)
            
            # Build search filter
            search_filter = "(objectClass=user)"
            if not include_disabled:
                search_filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            
            # Search for all users
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=[
                    'sAMAccountName', 'displayName', 'mail', 'lastLogon',
                    'pwdLastSet', 'userAccountControl', 'whenCreated', 'memberOf'
                ]
            )
            
            inactive_users = []
            for entry in results:
                last_logon = entry['attributes'].get('lastLogon', [0])[0]
                
                # Check if user is inactive
                if last_logon == 0 or last_logon < cutoff_filetime:
                    uac = entry['attributes'].get('userAccountControl', [0])[0]
                    member_of = entry['attributes'].get('memberOf', [])
                    
                    user_info = {
                        'dn': entry['dn'],
                        'sam_account_name': entry['attributes'].get('sAMAccountName', [''])[0],
                        'display_name': entry['attributes'].get('displayName', [''])[0],
                        'mail': entry['attributes'].get('mail', [''])[0],
                        'last_logon': self._convert_filetime_to_datetime(last_logon) if last_logon > 0 else 'Never',
                        'days_inactive': self._get_days_since_last_logon({'lastLogon': [last_logon]}),
                        'enabled': not bool(uac & 0x0002),
                        'group_count': len(member_of),
                        'has_privileged_groups': self._has_privileged_groups(member_of)
                    }
                    
                    inactive_users.append(user_info)
            
            # Sort by days inactive (descending)
            inactive_users.sort(key=lambda x: x['days_inactive'] or 99999, reverse=True)
            
            log_ldap_operation("get_inactive_users", self.ldap.ad_config.base_dn, True, f"Found {len(inactive_users)} inactive users")
            
            return self._format_response({
                "inactive_users": inactive_users,
                "count": len(inactive_users),
                "criteria_days": days,
                "include_disabled": include_disabled,
                "cutoff_date": cutoff_date.isoformat()
            }, "get_inactive_users")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_inactive_users", self.ldap.ad_config.base_dn)
    
    def get_password_policy_violations(self) -> List[Dict[str, Any]]:
        """
        Get users with password policy violations.
        
        Returns:
            List of MCP content objects with password policy violation information
        """
        try:
            # Get domain password policy first
            domain_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter="(objectClass=domain)",
                attributes=['maxPwdAge', 'minPwdAge'],
                search_scope=ldap3.BASE
            )
            
            if not domain_results:
                raise Exception("Could not retrieve domain password policy")
            
            max_pwd_age = domain_results[0]['attributes'].get('maxPwdAge', [0])[0]
            
            # Search for users
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter="(objectClass=user)",
                attributes=[
                    'sAMAccountName', 'displayName', 'pwdLastSet',
                    'userAccountControl', 'accountExpires'
                ]
            )
            
            violations = []
            current_time = self._convert_datetime_to_filetime(datetime.now())
            
            for entry in user_results:
                uac = entry['attributes'].get('userAccountControl', [0])[0]
                pwd_last_set = entry['attributes'].get('pwdLastSet', [0])[0]
                account_expires = entry['attributes'].get('accountExpires', [0])[0]
                
                user_violations = []
                
                # Check if password never expires but should
                if bool(uac & 0x10000) and max_pwd_age != 0:  # DONT_EXPIRE_PASSWORD
                    user_violations.append("Password set to never expire")
                
                # Check if password not required
                if bool(uac & 0x0020):  # PASSWD_NOTREQD
                    user_violations.append("Password not required")
                
                # Check if account expired
                if account_expires != 0 and account_expires != 9223372036854775807 and account_expires < current_time:
                    user_violations.append("Account expired")
                
                # Check if password is old (only if max age is set)
                if max_pwd_age != 0 and pwd_last_set != 0:
                    password_age = current_time - pwd_last_set
                    if password_age > abs(max_pwd_age):
                        user_violations.append("Password expired")
                
                # Check if password never set
                if pwd_last_set == 0:
                    user_violations.append("Password never set")
                
                if user_violations:
                    violation_info = {
                        'dn': entry['dn'],
                        'sam_account_name': entry['attributes'].get('sAMAccountName', [''])[0],
                        'display_name': entry['attributes'].get('displayName', [''])[0],
                        'violations': user_violations,
                        'enabled': not bool(uac & 0x0002),
                        'pwd_last_set': self._convert_filetime_to_datetime(pwd_last_set) if pwd_last_set > 0 else 'Never'
                    }
                    
                    violations.append(violation_info)
            
            log_ldap_operation("get_password_policy_violations", self.ldap.ad_config.base_dn, True, f"Found {len(violations)} violations")
            
            return self._format_response({
                "password_violations": violations,
                "count": len(violations)
            }, "get_password_policy_violations")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_password_policy_violations", self.ldap.ad_config.base_dn)
    
    def audit_admin_accounts(self) -> List[Dict[str, Any]]:
        """
        Audit administrative accounts for security compliance.
        
        Returns:
            List of MCP content objects with admin account audit information
        """
        try:
            # Get members of privileged groups
            privileged_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
            
            admin_accounts = []
            
            for group_name in privileged_groups:
                try:
                    group_results = self.ldap.search(
                        search_base=self.ldap.ad_config.base_dn,
                        search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                        attributes=['member']
                    )
                    
                    if group_results:
                        members = group_results[0]['attributes'].get('member', [])
                        
                        for member_dn in members:
                            # Get user details
                            user_results = self.ldap.search(
                                search_base=member_dn,
                                search_filter="(objectClass=user)",
                                attributes=[
                                    'sAMAccountName', 'displayName', 'mail',
                                    'userAccountControl', 'lastLogon', 'pwdLastSet',
                                    'logonCount', 'badPwdCount'
                                ],
                                search_scope=ldap3.BASE
                            )
                            
                            if user_results:
                                user_entry = user_results[0]
                                uac = user_entry['attributes'].get('userAccountControl', [0])[0]
                                
                                # Check for security issues
                                security_issues = []
                                
                                # Check if account is enabled
                                if bool(uac & 0x0002):  # ACCOUNTDISABLE
                                    security_issues.append("Account disabled")
                                
                                # Check if password never expires
                                if bool(uac & 0x10000):  # DONT_EXPIRE_PASSWORD
                                    security_issues.append("Password never expires")
                                
                                # Check if password not required
                                if bool(uac & 0x0020):  # PASSWD_NOTREQD
                                    security_issues.append("Password not required")
                                
                                # Check last logon
                                last_logon = user_entry['attributes'].get('lastLogon', [0])[0]
                                days_since_logon = self._get_days_since_last_logon({'lastLogon': [last_logon]})
                                if days_since_logon and days_since_logon > 90:
                                    security_issues.append(f"No logon for {days_since_logon} days")
                                
                                admin_info = {
                                    'dn': user_entry['dn'],
                                    'sam_account_name': user_entry['attributes'].get('sAMAccountName', [''])[0],
                                    'display_name': user_entry['attributes'].get('displayName', [''])[0],
                                    'mail': user_entry['attributes'].get('mail', [''])[0],
                                    'privileged_group': group_name,
                                    'enabled': not bool(uac & 0x0002),
                                    'last_logon': self._convert_filetime_to_datetime(last_logon) if last_logon > 0 else 'Never',
                                    'days_since_logon': days_since_logon,
                                    'logon_count': user_entry['attributes'].get('logonCount', [0])[0],
                                    'bad_pwd_count': user_entry['attributes'].get('badPwdCount', [0])[0],
                                    'security_issues': security_issues,
                                    'risk_level': self._calculate_admin_risk_level(security_issues, days_since_logon)
                                }
                                
                                # Avoid duplicates
                                if not any(acc['sam_account_name'] == admin_info['sam_account_name'] for acc in admin_accounts):
                                    admin_accounts.append(admin_info)
                                
                except Exception as group_error:
                    self.logger.warning(f"Failed to audit group {group_name}: {group_error}")
                    continue
            
            # Sort by risk level and name
            admin_accounts.sort(key=lambda x: (x['risk_level'], x['sam_account_name']))
            
            log_ldap_operation("audit_admin_accounts", self.ldap.ad_config.base_dn, True, f"Audited {len(admin_accounts)} admin accounts")
            
            return self._format_response({
                "admin_accounts": admin_accounts,
                "count": len(admin_accounts),
                "high_risk_count": len([acc for acc in admin_accounts if acc['risk_level'] == 'high']),
                "medium_risk_count": len([acc for acc in admin_accounts if acc['risk_level'] == 'medium']),
                "low_risk_count": len([acc for acc in admin_accounts if acc['risk_level'] == 'low'])
            }, "audit_admin_accounts")
            
        except Exception as e:
            return self._handle_ldap_error(e, "audit_admin_accounts", self.ldap.ad_config.base_dn)
    
    def _convert_time_interval(self, value: int) -> Dict[str, Any]:
        """Convert AD time interval to human readable format."""
        if value == 0:
            return {"raw": 0, "description": "Never"}
        
        # AD time intervals are in 100-nanosecond units (negative for intervals)
        seconds = abs(value) / 10000000
        
        if seconds < 60:
            return {"raw": value, "seconds": seconds, "description": f"{seconds:.0f} seconds"}
        elif seconds < 3600:
            minutes = seconds / 60
            return {"raw": value, "seconds": seconds, "description": f"{minutes:.0f} minutes"}
        elif seconds < 86400:
            hours = seconds / 3600
            return {"raw": value, "seconds": seconds, "description": f"{hours:.0f} hours"}
        else:
            days = seconds / 86400
            return {"raw": value, "seconds": seconds, "description": f"{days:.0f} days"}
    
    def _is_privileged_group(self, group_name: str) -> bool:
        """Check if a group is considered privileged."""
        privileged_groups = [
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "account operators", "backup operators",
            "print operators", "server operators", "domain controllers",
            "cert publishers", "dns admins", "group policy creator owners"
        ]
        return group_name.lower() in privileged_groups
    
    def _has_privileged_groups(self, member_of: List[str]) -> bool:
        """Check if user is member of any privileged groups."""
        for group_dn in member_of:
            # Extract CN from DN
            if group_dn.upper().startswith('CN='):
                cn_end = group_dn.find(',')
                if cn_end > 3:
                    group_name = group_dn[3:cn_end]
                    if self._is_privileged_group(group_name):
                        return True
        return False
    
    def _assess_user_security(self, account_status: Dict[str, Any], privileged_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess user security risk level."""
        risk_factors = []
        risk_level = "low"
        
        if not account_status['enabled']:
            risk_factors.append("Account disabled")
        
        if account_status['password_not_required']:
            risk_factors.append("Password not required")
            risk_level = "high"
        
        if account_status['password_never_expires'] and privileged_groups:
            risk_factors.append("Privileged account with non-expiring password")
            risk_level = "high"
        
        if len(privileged_groups) > 0:
            risk_factors.append(f"Member of {len(privileged_groups)} privileged groups")
            if risk_level == "low":
                risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": self._get_security_recommendation(risk_level, risk_factors)
        }
    
    def _calculate_admin_risk_level(self, security_issues: List[str], days_since_logon: Optional[int]) -> str:
        """Calculate risk level for admin accounts."""
        if not security_issues:
            return "low"
        
        high_risk_issues = [
            "Password not required",
            "Account disabled"
        ]
        
        medium_risk_issues = [
            "Password never expires"
        ]
        
        # Check for high risk issues
        if any(issue in security_issues for issue in high_risk_issues):
            return "high"
        
        # Check for medium risk issues or long inactivity
        if (any(issue in security_issues for issue in medium_risk_issues) or
            (days_since_logon and days_since_logon > 180)):
            return "high"
        elif days_since_logon and days_since_logon > 90:
            return "medium"
        
        return "medium" if security_issues else "low"
    
    def _get_security_recommendation(self, risk_level: str, risk_factors: List[str]) -> str:
        """Get security recommendation based on risk assessment."""
        if risk_level == "high":
            return "Immediate action required: Review and remediate high-risk security issues"
        elif risk_level == "medium":
            return "Review account permissions and consider implementing additional security controls"
        else:
            return "Monitor account activity and maintain current security posture"
    
    def _convert_filetime_to_datetime(self, filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime."""
        return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
    
    def _convert_datetime_to_filetime(self, dt: datetime) -> int:
        """Convert datetime to Windows FILETIME."""
        epoch = datetime(1601, 1, 1)
        delta = dt - epoch
        return int(delta.total_seconds() * 10000000)
    
    def _get_days_since_last_logon(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Get number of days since last logon."""
        last_logon = attributes.get('lastLogon', [0])[0]
        if last_logon == 0:
            return None
        
        try:
            last_logon_date = self._convert_filetime_to_datetime(last_logon)
            return (datetime.now() - last_logon_date).days
        except:
            return None
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for security operations."""
        return {
            "operations": [
                "get_domain_info", "get_privileged_groups", "get_user_permissions",
                "get_inactive_users", "get_password_policy_violations", "audit_admin_accounts"
            ],
            "security_attributes": [
                "userAccountControl", "memberOf", "lastLogon", "pwdLastSet",
                "accountExpires", "lockoutTime", "badPwdCount", "logonCount"
            ],
            "privileged_groups": [
                "Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Account Operators", "Backup Operators"
            ],
            "required_permissions": [
                "Read Domain Security Policy", "Read User Attributes",
                "Read Group Membership", "Audit User Activity"
            ]
        }
