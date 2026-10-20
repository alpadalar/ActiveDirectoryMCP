"""Security and audit tools for Active Directory."""

from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timedelta, timezone
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
                    'minPwdLength', 'pwdHistoryLength', 'forceLogoff'
                ],
                search_scope=ldap3.BASE
            )
            
            if not domain_results:
                raise Exception("Domain information not found")
            
            domain_entry = domain_results[0]
            # Handle bytes objects for JSON serialization
            object_sid = self._get_attr_value(domain_entry['attributes'], 'objectSid', b'')
            if isinstance(object_sid, bytes):
                object_sid = base64.b64encode(object_sid).decode('utf-8')

            domain_info = {
                'dn': domain_entry['dn'],
                'name': self._get_attr_value(domain_entry['attributes'], 'name', ''),
                'domain_component': self._get_attr_value(domain_entry['attributes'], 'dc', ''),
                'object_sid': object_sid,
                'when_created': self._get_attr_value(domain_entry['attributes'], 'whenCreated'),
                'when_changed': self._get_attr_value(domain_entry['attributes'], 'whenChanged')
            }

            # Password policy information
            password_policy = {
                'lockout_threshold': self._get_attr_value(domain_entry['attributes'], 'lockoutThreshold', 0),
                'lockout_duration': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'lockoutDuration', 0)),
                'max_password_age': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'maxPwdAge', 0)),
                'min_password_age': self._convert_time_interval(self._get_attr_value(domain_entry['attributes'], 'minPwdAge', 0)),
                'min_password_length': self._get_attr_value(domain_entry['attributes'], 'minPwdLength', 0),
                'password_history_length': self._get_attr_value(domain_entry['attributes'], 'pwdHistoryLength', 0)
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
                        search_filter=(
                            f"(&(objectClass={self.ldap.ad_config.group_object_class})"
                            f"(sAMAccountName={self._escape_ldap_filter(group_name)}))"
                        ),
                        attributes=['sAMAccountName', 'displayName', 'description', 'member', 'objectSid']
                    )
                    
                    if group_results:
                        group_entry = group_results[0]
                        members = self._get_attr_list(group_entry['attributes'], 'member')

                        # Handle bytes objects for JSON serialization
                        object_sid = self._get_attr_value(group_entry['attributes'], 'objectSid', b'')
                        if isinstance(object_sid, bytes):
                            object_sid = base64.b64encode(object_sid).decode('utf-8')

                        group_info = {
                            'dn': group_entry['dn'],
                            'sam_account_name': self._get_attr_value(group_entry['attributes'], 'sAMAccountName', ''),
                            'display_name': self._get_attr_value(group_entry['attributes'], 'displayName', ''),
                            'description': self._get_attr_value(group_entry['attributes'], 'description', ''),
                            'member_count': len(members),
                            'members': members[:10],  # First 10 members
                            'object_sid': object_sid
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
                "total_groups": len(groups_info)
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
                search_filter=(
                    f"(&(objectClass={self.ldap.ad_config.user_object_class})"
                    f"(sAMAccountName={self._escape_ldap_filter(username)}))"
                ),
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
                        search_filter=f"(objectClass={self.ldap.ad_config.group_object_class})",
                        attributes=['sAMAccountName', 'displayName', 'description', 'objectSid'],
                        search_scope=ldap3.BASE
                    )
                    
                    if group_info:
                        group_data = group_info[0]['attributes']
                        group_name = self._get_attr_value(group_data, 'sAMAccountName', '')

                        group_entry = {
                            'dn': group_dn,
                            'sam_account_name': group_name,
                            'display_name': self._get_attr_value(group_data, 'displayName', ''),
                            'description': self._get_attr_value(group_data, 'description', '')
                        }

                        # Check if it's a privileged group
                        if self._is_privileged_group(group_name):
                            group_entry['privileged'] = True
                            privileged_groups.append(group_entry)
                        else:
                            group_entry['privileged'] = False

                        group_analysis.append(group_entry)

                except Exception as group_exc:
                    # Skip groups that can't be analyzed, but leave a trace
                    self.logger.warning(
                        f"Skipping group {group_dn} while analyzing {username}: {group_exc}"
                    )
                    continue

            # Check account status
            uac = self._to_int(self._get_attr_value(user_entry['attributes'], 'userAccountControl'))
            if uac is None:
                raise ValueError(f"Cannot determine userAccountControl for user '{username}'")
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
                'display_name': self._get_attr_value(user_entry['attributes'], 'displayName', ''),
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
            # Calculate cutoff date (UTC, same basis as the AD time helpers)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Build search filter
            search_filter = f"(objectClass={self.ldap.ad_config.user_object_class})"
            if not include_disabled:
                search_filter = (
                    f"(&(objectClass={self.ldap.ad_config.user_object_class})"
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                )
            
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
                last_logon = self._get_attr_value(entry['attributes'], 'lastLogon', 0)
                last_logon_dt = self._ad_datetime(last_logon)

                # Check if user is inactive (unset/never counts as inactive)
                if last_logon_dt is None or last_logon_dt < cutoff_date:
                    uac = self._to_int(self._get_attr_value(entry['attributes'], 'userAccountControl'))
                    if uac is None:
                        self.logger.warning(f"Skipping {entry.get('dn')}: unreadable userAccountControl")
                        continue
                    member_of = self._get_attr_list(entry['attributes'], 'memberOf')

                    user_info = {
                        'dn': entry['dn'],
                        'sam_account_name': self._get_attr_value(entry['attributes'], 'sAMAccountName', ''),
                        'display_name': self._get_attr_value(entry['attributes'], 'displayName', ''),
                        'mail': self._get_attr_value(entry['attributes'], 'mail', ''),
                        'last_logon': last_logon_dt if last_logon_dt is not None else 'Never',
                        'days_inactive': self._get_days_since_last_logon({'lastLogon': last_logon}),
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

            max_pwd_age_raw = self._get_attr_value(domain_results[0]['attributes'], 'maxPwdAge', 0)

            # Normalise timedelta / int / numeric string to a magnitude in 100-ns ticks.
            # 0, -2**63, 2**63-1 and anything beyond the "never" threshold mean no max age.
            if isinstance(max_pwd_age_raw, timedelta):
                max_pwd_age = abs((max_pwd_age_raw // timedelta(microseconds=1)) * 10)
            else:
                max_pwd_age = abs(self._to_int(max_pwd_age_raw, 0))
            if max_pwd_age > 10 ** 7 * 864000000000:
                max_pwd_age = 0

            # Search for users
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(objectClass={self.ldap.ad_config.user_object_class})",
                attributes=[
                    'sAMAccountName', 'displayName', 'pwdLastSet',
                    'userAccountControl', 'accountExpires'
                ]
            )

            violations = []
            current_time = self._convert_datetime_to_filetime(datetime.now(timezone.utc))

            for entry in user_results:
                uac = self._to_int(self._get_attr_value(entry['attributes'], 'userAccountControl'))
                if uac is None:
                    self.logger.warning(f"Skipping {entry.get('dn')}: unreadable userAccountControl")
                    continue
                pwd_last_set_raw = self._get_attr_value(entry['attributes'], 'pwdLastSet', 0)
                account_expires_raw = self._get_attr_value(entry['attributes'], 'accountExpires', 0)

                # Normalise datetime / int / numeric-string values to FILETIME ints
                # (0 = unset or never)
                pwd_last_set_dt = self._ad_datetime(pwd_last_set_raw)
                pwd_last_set = self._convert_datetime_to_filetime(pwd_last_set_dt) if pwd_last_set_dt else 0
                account_expires_dt = self._ad_datetime(account_expires_raw)
                account_expires = (
                    self._convert_datetime_to_filetime(account_expires_dt) if account_expires_dt else 0
                )

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
                        'sam_account_name': self._get_attr_value(entry['attributes'], 'sAMAccountName', ''),
                        'display_name': self._get_attr_value(entry['attributes'], 'displayName', ''),
                        'violations': user_violations,
                        'enabled': not bool(uac & 0x0002),
                        'pwd_last_set': pwd_last_set_dt if pwd_last_set_dt is not None else 'Never'
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
                        search_filter=(
                            f"(&(objectClass={self.ldap.ad_config.group_object_class})"
                            f"(sAMAccountName={self._escape_ldap_filter(group_name)}))"
                        ),
                        attributes=['member']
                    )
                    
                    if group_results:
                        members = group_results[0]['attributes'].get('member', [])
                        
                        for member_dn in members:
                            # Get user details
                            user_results = self.ldap.search(
                                search_base=member_dn,
                                search_filter=f"(objectClass={self.ldap.ad_config.user_object_class})",
                                attributes=[
                                    'sAMAccountName', 'displayName', 'mail',
                                    'userAccountControl', 'lastLogon', 'pwdLastSet',
                                    'logonCount', 'badPwdCount'
                                ],
                                search_scope=ldap3.BASE
                            )
                            
                            if user_results:
                                user_entry = user_results[0]
                                uac = self._to_int(self._get_attr_value(user_entry['attributes'], 'userAccountControl'))
                                if uac is None:
                                    self.logger.warning(f"Skipping admin audit for {member_dn}: unreadable userAccountControl")
                                    continue

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
                                last_logon = self._get_attr_value(user_entry['attributes'], 'lastLogon', 0)
                                days_since_logon = self._get_days_since_last_logon({'lastLogon': last_logon})
                                if days_since_logon and days_since_logon > 90:
                                    security_issues.append(f"No logon for {days_since_logon} days")

                                admin_info = {
                                    'dn': user_entry['dn'],
                                    'sam_account_name': self._get_attr_value(user_entry['attributes'], 'sAMAccountName', ''),
                                    'display_name': self._get_attr_value(user_entry['attributes'], 'displayName', ''),
                                    'mail': self._get_attr_value(user_entry['attributes'], 'mail', ''),
                                    'privileged_group': group_name,
                                    'enabled': not bool(uac & 0x0002),
                                    'last_logon': self._ad_datetime(last_logon) or 'Never',
                                    'days_since_logon': days_since_logon,
                                    'logon_count': self._get_attr_value(user_entry['attributes'], 'logonCount', 0),
                                    'bad_pwd_count': self._get_attr_value(user_entry['attributes'], 'badPwdCount', 0),
                                    'security_issues': security_issues,
                                    'risk_level': self._calculate_admin_risk_level(security_issues, days_since_logon)
                                }

                                # Avoid duplicates
                                if not any(acc['sam_account_name'] == admin_info['sam_account_name'] for acc in admin_accounts):
                                    admin_accounts.append(admin_info)
                                
                except Exception as group_error:
                    self.logger.warning(f"Failed to audit group {group_name}: {group_error}")
                    continue
            
            # Sort by severity (HIGH first), then by name
            admin_accounts.sort(
                key=lambda x: (self._risk_rank(x['risk_level']), x['sam_account_name'])
            )
            
            log_ldap_operation("audit_admin_accounts", self.ldap.ad_config.base_dn, True, f"Audited {len(admin_accounts)} admin accounts")
            
            return self._format_response({
                "admin_accounts": admin_accounts,
                "total_admin_accounts": len(admin_accounts),
                "high_risk_count": len([acc for acc in admin_accounts if str(acc['risk_level']).lower() == 'high']),
                "medium_risk_count": len([acc for acc in admin_accounts if str(acc['risk_level']).lower() == 'medium']),
                "low_risk_count": len([acc for acc in admin_accounts if str(acc['risk_level']).lower() == 'low'])
            }, "audit_admin_accounts")
            
        except Exception as e:
            return self._handle_ldap_error(e, "audit_admin_accounts", self.ldap.ad_config.base_dn)
    
    def _convert_time_interval(self, value) -> Dict[str, Any]:
        """Convert an AD time interval to a human readable dict.

        Accepts a timedelta (what ldap3 returns for AD interval attributes), a signed
        100-ns tick count (int) or a numeric string (schema-less mode). `raw` is the
        interval magnitude in 100-ns ticks for every input type (0 for unset); the
        "never" sentinels (0, -2**63, 2**63-1, timedelta.max) report
        raw 0 / 2**63-1 and description "Never" without a `seconds` key.
        """
        never_ticks = 9223372036854775807
        # Anything longer than ~27,000 years is the AD "never" marker, not a real interval
        never_threshold = 10 ** 7 * 864000000000

        if value is None:
            return {"raw": 0, "description": "Never"}
        if isinstance(value, timedelta):
            ticks = abs((value // timedelta(microseconds=1)) * 10)
        else:
            number = self._to_int(value)
            if number is None:
                return {"raw": value, "description": "Unknown"}
            ticks = abs(number)

        if ticks == 0:
            return {"raw": 0, "description": "Never"}
        if ticks > never_threshold:
            return {"raw": never_ticks, "description": "Never"}

        seconds = ticks / 10000000
        if seconds < 60:
            description = f"{seconds:.0f} seconds"
        elif seconds < 3600:
            description = f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            description = f"{seconds / 3600:.0f} hours"
        else:
            description = f"{seconds / 86400:.0f} days"
        return {"raw": ticks, "seconds": seconds, "description": description}

    @staticmethod
    def _risk_rank(risk_level: Any) -> int:
        """Severity rank for sorting: HIGH=0, MEDIUM=1, LOW=2, anything else=3."""
        return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(str(risk_level).upper(), 3)

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
            return "LOW"
        
        high_risk_issues = [
            "Password not required",
            "Account disabled"
        ]
        
        medium_risk_issues = [
            "Password never expires"
        ]
        
        # Check for high risk issues
        if any(issue in security_issues for issue in high_risk_issues):
            return "HIGH"
        
        # Check for medium risk issues or long inactivity
        if (any(issue in security_issues for issue in medium_risk_issues) or
            (days_since_logon and days_since_logon > 180)):
            return "HIGH"
        elif days_since_logon and days_since_logon > 90:
            return "MEDIUM"
        
        return "MEDIUM" if security_issues else "LOW"
    
    def _get_security_recommendation(self, risk_level: str, risk_factors: List[str]) -> str:
        """Get security recommendation based on risk assessment."""
        level = str(risk_level).upper()
        if level == "HIGH":
            return "Immediate action required: Review and remediate high-risk security issues"
        elif level == "MEDIUM":
            return "Review account permissions and consider implementing additional security controls"
        else:
            return "Monitor account activity and maintain current security posture"
    
    def _get_days_since_last_logon(self, attributes: Dict[str, Any]) -> Optional[int]:
        """Whole days since last logon; None when unset/never. Accepts datetime, int, numeric str."""
        return self._days_since(self._get_attr_value(attributes, 'lastLogon', 0))

    # Additional policy checks
    def check_password_policy(self) -> List[Dict[str, Any]]:
        """Check password policy compliance."""
        try:
            domain_response = self.get_domain_info()
            if not domain_response:
                raise Exception("Domain info not found")

            policy_data = json.loads(domain_response[0].text)
            if not policy_data.get('success', True):
                # Pass the structured get_domain_info error through unchanged
                return domain_response

            pwd_policy = policy_data.get('password_policy', {})
            compliance = {
                'policy_compliant': True,
                'recommendations': [],
                'password_policy': pwd_policy,
            }

            min_length = self._to_int(pwd_policy.get('min_password_length'), 0)
            if min_length < 8:
                compliance['policy_compliant'] = False
                compliance['recommendations'].append('Increase minimum password length to at least 8 characters')

            history_length = self._to_int(pwd_policy.get('password_history_length'), 0)
            if history_length < 5:
                compliance['policy_compliant'] = False
                compliance['recommendations'].append('Increase password history to at least 5 passwords')

            return self._format_response(compliance, "check_password_policy")

        except Exception as e:
            return self._handle_ldap_error(e, 'check_password_policy', 'domain')

    def generate_security_report(self) -> List[Dict[str, Any]]:
        """Generate comprehensive security report."""
        try:
            report_timestamp = datetime.now().isoformat()
            
            # Collect data from various security methods
            domain_info_response = self.get_domain_info()
            admin_audit_response = self.audit_admin_accounts()
            privileged_groups_response = self.get_privileged_groups()
            password_policy_response = self.check_password_policy()
            
            # Parse responses (they are List[Content])
            domain_info = json.loads(domain_info_response[0].text) if domain_info_response else {}
            admin_audit = json.loads(admin_audit_response[0].text) if admin_audit_response else {}
            privileged_groups = json.loads(privileged_groups_response[0].text) if privileged_groups_response else {}
            password_policy = json.loads(password_policy_response[0].text) if password_policy_response else {}
            
            # Generate executive summary
            total_admins = admin_audit.get('total_admin_accounts', 0)
            high_risk_admins = admin_audit.get('high_risk_count', 0)
            total_privileged_groups = privileged_groups.get('total_groups', 0)
            policy_compliant = password_policy.get('policy_compliant', True)
            
            executive_summary = {
                'total_admin_accounts': total_admins,
                'high_risk_admin_accounts': high_risk_admins,
                'total_privileged_groups': total_privileged_groups,
                'password_policy_compliant': policy_compliant,
                'overall_security_score': max(0, 100 - (high_risk_admins * 10) - (0 if policy_compliant else 20))
            }
            
            # Detailed findings
            detailed_findings = {
                'domain_information': domain_info,
                'admin_account_audit': admin_audit,
                'privileged_groups_analysis': privileged_groups,
                'password_policy_assessment': password_policy
            }
            
            report = {
                'report_timestamp': report_timestamp,
                'executive_summary': executive_summary,
                'detailed_findings': detailed_findings,
                'recommendations': self._generate_security_recommendations(executive_summary)
            }
            
            return self._format_response(report, "generate_security_report")
            
        except Exception as e:
            return self._handle_ldap_error(e, "generate_security_report", "security_report")
    
    def _generate_security_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if summary.get('high_risk_admin_accounts', 0) > 0:
            recommendations.append("Review and remediate high-risk administrative accounts")
            
        if not summary.get('password_policy_compliant', True):
            recommendations.append("Update password policy to meet security standards")
            
        if summary.get('overall_security_score', 100) < 80:
            recommendations.append("Conduct comprehensive security hardening review")
            
        return recommendations or ["Security posture appears satisfactory - continue regular monitoring"]

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for security operations."""
        return {
            "operations": [
                "get_domain_info", "get_privileged_groups", "get_user_permissions",
                "get_inactive_users", "get_password_policy_violations", "audit_admin_accounts",
                "check_password_policy", "generate_security_report"
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
            ],
            "risk_levels": ["low", "medium", "high", "critical"]
        }
