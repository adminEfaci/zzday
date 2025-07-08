"""
MFA Policy

Business rules for multi-factor authentication requirements.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import MFAMethod, PolicyConfigManager, RiskLevel, UserRole

from .base import BusinessRule, PolicyViolation


class MFAPolicy(BusinessRule):
    """Multi-factor authentication policy validation."""
    
    def __init__(self, policy_config: dict[str, Any] | None = None):
        if policy_config:
            self.config = policy_config
        else:
            config_manager = PolicyConfigManager()
            mfa_config = config_manager.get_mfa_config()
            self.config = mfa_config.__dict__
    
    def validate(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate MFA requirements against policy."""
        violations = []
        
        # Validate role-based requirements
        violations.extend(self._validate_role_requirements(user_data))
        
        # Validate risk-based requirements
        violations.extend(self._validate_risk_requirements(user_data))
        
        # Validate privilege-based requirements
        violations.extend(self._validate_privilege_requirements(user_data))
        
        # Validate MFA device requirements
        violations.extend(self._validate_device_requirements(user_data))
        
        # Validate grace period
        violations.extend(self._validate_grace_period(user_data))
        
        return violations
    
    def is_compliant(self, user_data: dict[str, Any]) -> bool:
        """Check if user MFA setup is compliant with policy."""
        violations = self.validate(user_data)
        return not self.has_blocking_violations(violations)
    
    def is_mfa_required(self, user_data: dict[str, Any]) -> bool:
        """Determine if MFA is required for user."""
        # Check role requirements
        user_role = user_data.get("role", UserRole.USER)
        if self._is_role_required_mfa(user_role):
            return True
        
        # Check risk level
        risk_level = user_data.get("risk_level", RiskLevel.LOW)
        if self._is_risk_required_mfa(risk_level):
            return True
        
        # Check privilege level
        if self._has_elevated_privileges(user_data):
            return True
        
        # Check mandatory enforcement
        return bool(self.config.get("enforce_for_all", False))
    
    def _validate_role_requirements(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate role-based MFA requirements."""
        violations = []
        
        user_role = user_data.get("role", UserRole.USER)
        has_mfa = user_data.get("has_mfa", False)
        mfa_methods = user_data.get("mfa_methods", [])
        
        # Admin MFA requirement
        if self.config["require_for_admin"] and self._is_admin_role(user_role):
            if not has_mfa:
                violations.append(PolicyViolation(
                    rule_name="admin_mfa_required",
                    description="MFA is required for admin users",
                    severity="error",
                    current_value=has_mfa,
                    expected_value=True
                ))
            
            # Admin might require specific MFA methods
            required_methods = self.config.get("admin_required_methods", [])
            if required_methods:
                missing_methods = set(required_methods) - set(mfa_methods)
                if missing_methods:
                    violations.append(PolicyViolation(
                        rule_name="admin_mfa_method_required",
                        description=f"Admin users must have these MFA methods: {missing_methods}",
                        severity="error",
                        current_value=mfa_methods,
                        expected_value=required_methods
                    ))
        
        # Role-specific requirements
        role_requirements = self.config.get("role_requirements", {})
        if str(user_role) in role_requirements:
            role_config = role_requirements[str(user_role)]
            if role_config.get("required", False) and not has_mfa:
                violations.append(PolicyViolation(
                    rule_name="role_mfa_required",
                    description=f"MFA is required for {user_role} role",
                    severity="error",
                    current_value=has_mfa,
                    expected_value=True
                ))
        
        return violations
    
    def _validate_risk_requirements(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate risk-based MFA requirements."""
        violations = []
        
        risk_level = user_data.get("risk_level", RiskLevel.LOW)
        has_mfa = user_data.get("has_mfa", False)
        risk_score = user_data.get("risk_score", 0.0)
        
        # High risk MFA requirement
        if self.config["require_for_high_risk"] and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            if not has_mfa:
                violations.append(PolicyViolation(
                    rule_name="high_risk_mfa_required",
                    description=f"MFA is required for {risk_level.value} risk users",
                    severity="error",
                    current_value=has_mfa,
                    expected_value=True
                ))
        
        # Risk score threshold
        risk_threshold = self.config.get("risk_score_threshold", 0.7)
        if risk_score > risk_threshold and not has_mfa:
            violations.append(PolicyViolation(
                rule_name="risk_threshold_mfa_required",
                description="MFA required due to high risk score",
                severity="error",
                current_value=has_mfa,
                expected_value=True,
                context={"risk_score": risk_score}
            ))
        
        # Adaptive MFA requirements
        if self.config.get("adaptive_mfa_enabled", False):
            violations.extend(self._validate_adaptive_mfa(user_data))
        
        return violations
    
    def _validate_privilege_requirements(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate privilege-based MFA requirements."""
        violations = []
        
        has_mfa = user_data.get("has_mfa", False)
        permissions = user_data.get("permissions", [])
        
        # Check for sensitive permissions
        sensitive_permissions = self.config.get("sensitive_permissions", [])
        user_sensitive_perms = [p for p in permissions if p in sensitive_permissions]
        
        if user_sensitive_perms and not has_mfa:
            violations.append(PolicyViolation(
                rule_name="sensitive_permission_mfa_required",
                description="MFA required for users with sensitive permissions",
                severity="error",
                current_value=has_mfa,
                expected_value=True,
                context={"sensitive_permissions": user_sensitive_perms}
            ))
        
        # Check for data access levels
        data_access_level = user_data.get("data_access_level", "basic")
        if data_access_level in ["sensitive", "confidential", "restricted"] and not has_mfa:
            violations.append(PolicyViolation(
                rule_name="data_access_mfa_required",
                description=f"MFA required for {data_access_level} data access",
                severity="error",
                current_value=has_mfa,
                expected_value=True
            ))
        
        return violations
    
    def _validate_device_requirements(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate MFA device requirements."""
        violations = []
        
        has_mfa = user_data.get("has_mfa", False)
        mfa_devices = user_data.get("mfa_devices", [])
        active_devices = [d for d in mfa_devices if d.get("is_active", False)]
        
        if has_mfa:
            # Minimum active devices
            min_devices = self.config.get("min_active_devices", 1)
            if len(active_devices) < min_devices:
                violations.append(PolicyViolation(
                    rule_name="insufficient_mfa_devices",
                    description=f"Must have at least {min_devices} active MFA devices",
                    severity="error",
                    current_value=len(active_devices),
                    expected_value=min_devices
                ))
            
            # Backup method requirement
            if self.config.get("require_backup_method", True):
                has_backup = any(d.get("method") == MFAMethod.BACKUP_CODE for d in active_devices)
                if not has_backup:
                    violations.append(PolicyViolation(
                        rule_name="backup_method_required",
                        description="Must have backup codes as fallback MFA method",
                        severity="warning",
                        current_value=False,
                        expected_value=True
                    ))
            
            # Method diversity
            if self.config.get("require_method_diversity", False):
                unique_methods = len({d.get("method") for d in active_devices})
                min_methods = self.config.get("min_unique_methods", 2)
                
                if unique_methods < min_methods:
                    violations.append(PolicyViolation(
                        rule_name="insufficient_mfa_diversity",
                        description=f"Must have at least {min_methods} different MFA methods",
                        severity="warning",
                        current_value=unique_methods,
                        expected_value=min_methods
                    ))
        
        return violations
    
    def _validate_grace_period(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate MFA grace period requirements."""
        violations = []
        
        account_created = user_data.get("created_at")
        has_mfa = user_data.get("has_mfa", False)
        mfa_required = self.is_mfa_required(user_data)
        
        if not account_created or has_mfa or not mfa_required:
            return violations
        
        # Check grace period
        grace_days = self.config.get("grace_period_days", 30)
        account_age = datetime.now(UTC) - account_created
        grace_period = timedelta(days=grace_days)
        
        if account_age > grace_period:
            violations.append(PolicyViolation(
                rule_name="mfa_grace_period_expired",
                description="MFA setup grace period has expired",
                severity="error",
                current_value=f"{account_age.days} days",
                expected_value=f"<= {grace_days} days"
            ))
        elif account_age > grace_period * 0.8:  # 80% of grace period
            violations.append(PolicyViolation(
                rule_name="mfa_grace_period_ending",
                description="MFA setup grace period ending soon",
                severity="warning",
                current_value=f"{account_age.days} days",
                expected_value=f"< {int(grace_days * 0.8)} days"
            ))
        
        return violations
    
    def _validate_adaptive_mfa(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate adaptive MFA requirements."""
        violations = []
        
        # Context-based MFA requirements
        login_context = user_data.get("login_context", {})
        
        # New location
        if login_context.get("new_location", False):
            if not login_context.get("mfa_completed", False):
                violations.append(PolicyViolation(
                    rule_name="new_location_mfa_required",
                    description="MFA required for login from new location",
                    severity="error",
                    current_value=False,
                    expected_value=True
                ))
        
        # New device
        if login_context.get("new_device", False):
            if not login_context.get("mfa_completed", False):
                violations.append(PolicyViolation(
                    rule_name="new_device_mfa_required",
                    description="MFA required for login from new device",
                    severity="error",
                    current_value=False,
                    expected_value=True
                ))
        
        # Suspicious activity
        if login_context.get("suspicious_activity", False):
            if not login_context.get("mfa_completed", False):
                violations.append(PolicyViolation(
                    rule_name="suspicious_activity_mfa_required",
                    description="MFA required due to suspicious activity",
                    severity="error",
                    current_value=False,
                    expected_value=True
                ))
        
        return violations
    
    def _is_admin_role(self, role: UserRole) -> bool:
        """Check if role is admin level."""
        admin_roles = [UserRole.ADMIN, UserRole.SUPER_ADMIN]
        return role in admin_roles
    
    def _is_role_required_mfa(self, role: UserRole) -> bool:
        """Check if role requires MFA."""
        if self.config["require_for_admin"] and self._is_admin_role(role):
            return True
        
        role_requirements = self.config.get("role_requirements", {})
        role_config = role_requirements.get(str(role), {})
        return role_config.get("required", False)
    
    def _is_risk_required_mfa(self, risk_level: RiskLevel) -> bool:
        """Check if risk level requires MFA."""
        if self.config["require_for_high_risk"] and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        risk_requirements = self.config.get("risk_requirements", {})
        return risk_requirements.get(risk_level.value, False)
    
    def _has_elevated_privileges(self, user_data: dict[str, Any]) -> bool:
        """Check if user has elevated privileges requiring MFA."""
        # Check permissions
        permissions = user_data.get("permissions", [])
        sensitive_permissions = self.config.get("sensitive_permissions", [])
        if any(p in sensitive_permissions for p in permissions):
            return True
        
        # Check data access
        data_access = user_data.get("data_access_level", "basic")
        if data_access in ["sensitive", "confidential", "restricted"]:
            return True
        
        # Check special flags
        if user_data.get("is_service_account", False):
            return self.config.get("require_for_service_accounts", True)
        
        return False
    
    def get_allowed_methods(self, user_data: dict[str, Any]) -> list[MFAMethod]:
        """Get allowed MFA methods for user."""
        allowed = list(MFAMethod)  # Start with all methods
        
        # Remove disallowed methods globally
        disallowed = self.config.get("disallowed_methods", [])
        allowed = [m for m in allowed if m not in disallowed]
        
        # Role-based restrictions
        user_role = user_data.get("role", UserRole.USER)
        role_config = self.config.get("role_requirements", {}).get(str(user_role), {})
        if "allowed_methods" in role_config:
            allowed = [m for m in allowed if m in role_config["allowed_methods"]]
        
        # Remove SMS for high-risk users if configured
        if self.config.get("disable_sms_for_high_risk", False):
            risk_level = user_data.get("risk_level", RiskLevel.LOW)
            if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                allowed = [m for m in allowed if m != MFAMethod.SMS]
        
        return allowed
