"""
Policy Builders

Fluent builders for creating complex policy configurations and validation chains.
"""

from typing import Any

from app.core.config import PolicyConfigManager, PolicyEnvironment

from .base import BusinessRule, PolicyViolation, RemediationAction, ViolationSeverity


class PolicyBuilder:
    """Fluent builder for creating policy configurations."""
    
    def __init__(self):
        self._config_manager = PolicyConfigManager()
        self._policies: list[BusinessRule] = []
        self._custom_rules: dict[str, Any] = {}
        self._environment = PolicyEnvironment.PRODUCTION
    
    def for_environment(self, environment: PolicyEnvironment) -> 'PolicyBuilder':
        """Set the target environment."""
        self._environment = environment
        self._config_manager = PolicyConfigManager(environment)
        return self
    
    def with_password_policy(self, **overrides) -> 'PolicyBuilder':
        """Add password policy with optional overrides."""
        config = self._config_manager.get_password_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .password_policy import PasswordPolicy
        policy = PasswordPolicy(config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_session_policy(self, **overrides) -> 'PolicyBuilder':
        """Add session policy with optional overrides."""
        config = self._config_manager.get_session_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .session_policy import SessionPolicy
        policy = SessionPolicy(config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_mfa_policy(self, **overrides) -> 'PolicyBuilder':
        """Add MFA policy with optional overrides."""
        config = self._config_manager.get_mfa_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .mfa_policy import MFAPolicy
        policy = MFAPolicy(config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_lockout_policy(self, **overrides) -> 'PolicyBuilder':
        """Add lockout policy with optional overrides."""
        config = self._config_manager.get_lockout_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .lockout_policy import AccountLockoutPolicy
        policy = AccountLockoutPolicy(config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_risk_policy(self, **overrides) -> 'PolicyBuilder':
        """Add risk assessment policy with optional overrides."""
        config = self._config_manager.get_risk_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .risk_policy import RiskAssessmentPolicy
        policy = RiskAssessmentPolicy(config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_compliance_policy(self, **overrides) -> 'PolicyBuilder':
        """Add compliance policy with optional overrides."""
        config = self._config_manager.get_compliance_config()
        
        # Apply overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        from .compliance_policy import CompliancePolicy
        policy = CompliancePolicy(**config.__dict__)
        self._policies.append(policy)
        return self
    
    def with_custom_rule(self, name: str, rule: BusinessRule) -> 'PolicyBuilder':
        """Add a custom business rule."""
        self._custom_rules[name] = rule
        self._policies.append(rule)
        return self
    
    def build(self) -> 'PolicyChain':
        """Build the policy chain."""
        return PolicyChain(self._policies, self._environment)


class PolicyChain:
    """Chain of policies that can be validated together."""
    
    def __init__(self, policies: list[BusinessRule], environment: PolicyEnvironment):
        self.policies = policies
        self.environment = environment
        self._stop_on_critical = True
        self._parallel_validation = False
    
    def stop_on_critical(self, stop: bool = True) -> 'PolicyChain':
        """Configure whether to stop validation on critical violations."""
        self._stop_on_critical = stop
        return self
    
    def parallel_validation(self, parallel: bool = True) -> 'PolicyChain':
        """Configure whether to run validations in parallel."""
        self._parallel_validation = parallel
        return self
    
    def validate_all(self, data: dict[str, Any]) -> dict[str, list[PolicyViolation]]:
        """Validate data against all policies in the chain."""
        results = {}
        
        for policy in self.policies:
            policy_name = policy.rule_name
            
            try:
                # Extract relevant data for this policy
                policy_data = self._extract_policy_data(policy_name, data)
                violations = policy.validate(**policy_data)
                results[policy_name] = violations
                
                # Stop on critical violations if configured
                if self._stop_on_critical and any(v.severity == ViolationSeverity.CRITICAL for v in violations):
                    break
                    
            except Exception as e:
                # Create error violation for policy failure
                error_violation = PolicyViolation(
                    rule_name=f"{policy_name}.validation_error",
                    description=f"Policy validation failed: {e!s}",
                    severity=ViolationSeverity.ERROR,
                    current_value="exception",
                    expected_value="successful_validation",
                    context={"exception_type": type(e).__name__}
                )
                results[policy_name] = [error_violation]
        
        return results
    
    def _extract_policy_data(self, policy_name: str, data: dict[str, Any]) -> dict[str, Any]:
        """Extract relevant data for a specific policy."""
        # Map policy names to their expected data keys
        policy_data_mapping = {
            "PasswordPolicy": ["password", "user_context"],
            "SessionPolicy": ["session_data"],
            "MFAPolicy": ["user_data"],
            "AccountLockoutPolicy": ["login_attempts"],
            "RiskAssessmentPolicy": ["risk_score", "risk_factors", "user_data"],
            "CompliancePolicy": ["action", "user_data", "data_categories", "purpose", "region"]
        }
        
        expected_keys = policy_data_mapping.get(policy_name, [])
        return {key: data.get(key) for key in expected_keys if key in data}
    
    def is_compliant(self, data: dict[str, Any]) -> bool:
        """Check if data is compliant with all policies."""
        results = self.validate_all(data)
        return not any(
            any(v.is_blocking() for v in violations)
            for violations in results.values()
        )
    
    def get_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        """Get validation summary."""
        results = self.validate_all(data)
        
        total_violations = sum(len(violations) for violations in results.values())
        blocking_violations = sum(
            sum(1 for v in violations if v.is_blocking())
            for violations in results.values()
        )
        
        return {
            "environment": self.environment.value,
            "total_policies": len(self.policies),
            "total_violations": total_violations,
            "blocking_violations": blocking_violations,
            "is_compliant": blocking_violations == 0,
            "policy_results": {
                name: {
                    "violation_count": len(violations),
                    "blocking_count": sum(1 for v in violations if v.is_blocking()),
                    "compliant": not any(v.is_blocking() for v in violations)
                }
                for name, violations in results.items()
            }
        }


class ScenarioBuilder:
    """Builder for creating domain-specific policy scenarios."""
    
    @staticmethod
    def for_user_registration() -> PolicyBuilder:
        """Create policy chain for user registration."""
        return (PolicyBuilder()
                .with_password_policy()
                .with_compliance_policy()
                .with_risk_policy(require_mfa_above_score=0.3))
    
    @staticmethod
    def for_admin_login() -> PolicyBuilder:
        """Create policy chain for admin login."""
        return (PolicyBuilder()
                .with_mfa_policy(require_for_admin=True)
                .with_session_policy(absolute_timeout_minutes=240)  # 4 hours
                .with_lockout_policy(max_failed_attempts=3)
                .with_risk_policy(alert_security_team_above=0.5))
    
    @staticmethod
    def for_high_risk_user() -> PolicyBuilder:
        """Create policy chain for high-risk users."""
        return (PolicyBuilder()
                .with_password_policy(min_length=12, complexity_score_threshold=0.8)
                .with_mfa_policy(require_method_diversity=True, min_unique_methods=2)
                .with_session_policy(absolute_timeout_minutes=120)  # 2 hours
                .with_risk_policy(require_mfa_above_score=0.3))
    
    @staticmethod
    def for_service_account() -> PolicyBuilder:
        """Create policy chain for service accounts."""
        return (PolicyBuilder()
                .with_mfa_policy(require_for_service_accounts=True)
                .with_session_policy(absolute_timeout_minutes=43200)  # 30 days
                .with_risk_policy(block_above_score=0.7))
    
    @staticmethod
    def for_compliance_audit() -> PolicyBuilder:
        """Create policy chain for compliance auditing."""
        return (PolicyBuilder()
                .with_compliance_policy()
                .with_password_policy(history_limit=12)
                .with_mfa_policy(require_backup_method=True)
                .with_session_policy())
    
    @staticmethod
    def for_development_environment() -> PolicyBuilder:
        """Create relaxed policy chain for development."""
        return (PolicyBuilder()
                .for_environment(PolicyEnvironment.DEVELOPMENT)
                .with_password_policy(min_length=6, require_special_chars=False)
                .with_session_policy(absolute_timeout_minutes=480)
                .with_lockout_policy(max_failed_attempts=10))


class RemediationBuilder:
    """Builder for creating remediation actions."""
    
    @staticmethod
    def password_remediation() -> list[RemediationAction]:
        """Create password-related remediation actions."""
        return [
            RemediationAction(
                action_type="password_change",
                description="Change your password to meet security requirements",
                user_action_required=True,
                estimated_time_minutes=5,
                help_url="/help/password-requirements"
            ),
            RemediationAction(
                action_type="password_generator",
                description="Use the password generator to create a secure password",
                automated=True,
                user_action_required=False,
                estimated_time_minutes=1,
                help_url="/help/password-generator"
            )
        ]
    
    @staticmethod
    def mfa_remediation() -> list[RemediationAction]:
        """Create MFA-related remediation actions."""
        return [
            RemediationAction(
                action_type="mfa_setup",
                description="Set up multi-factor authentication",
                user_action_required=True,
                estimated_time_minutes=10,
                help_url="/help/mfa-setup"
            ),
            RemediationAction(
                action_type="backup_codes",
                description="Generate backup codes for account recovery",
                user_action_required=True,
                estimated_time_minutes=2,
                help_url="/help/backup-codes"
            )
        ]
    
    @staticmethod
    def session_remediation() -> list[RemediationAction]:
        """Create session-related remediation actions."""
        return [
            RemediationAction(
                action_type="session_refresh",
                description="Refresh your session to continue",
                automated=True,
                user_action_required=False,
                estimated_time_minutes=1
            ),
            RemediationAction(
                action_type="re_authentication",
                description="Please log in again to verify your identity",
                user_action_required=True,
                estimated_time_minutes=2
            )
        ]
