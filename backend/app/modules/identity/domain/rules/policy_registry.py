"""
Policy Registry

Central registry for all business rule policies.
"""

from typing import Any

from app.core.config import PolicyConfigManager, PolicyEnvironment

from .base import BusinessRule, PolicyViolation
from .builders import PolicyBuilder, ScenarioBuilder
from .compliance_policy import CompliancePolicy
from .device_trust_policy import DeviceTrustPolicy
from .lockout_policy import AccountLockoutPolicy
from .mfa_policy import MFAPolicy
from .password_policy import PasswordPolicy
from .risk_policy import RiskAssessmentPolicy
from .session_limit_policy import SessionLimitPolicy
from .session_policy import SessionPolicy
from .user_status_policy import UserStatusPolicy

# Enhanced policy registry mapping
POLICY_REGISTRY: dict[str, type[BusinessRule]] = {
    "password": PasswordPolicy,
    "session": SessionPolicy,
    "lockout": AccountLockoutPolicy,
    "mfa": MFAPolicy,
    "risk": RiskAssessmentPolicy,
    "compliance": CompliancePolicy,
    "device_trust": DeviceTrustPolicy,
    "user_status": UserStatusPolicy,
    "session_limit": SessionLimitPolicy,
}

# Scenario registry for common use cases
SCENARIO_REGISTRY: dict[str, callable] = {
    "user_registration": ScenarioBuilder.for_user_registration,
    "admin_login": ScenarioBuilder.for_admin_login,
    "high_risk_user": ScenarioBuilder.for_high_risk_user,
    "service_account": ScenarioBuilder.for_service_account,
    "compliance_audit": ScenarioBuilder.for_compliance_audit,
    "development": ScenarioBuilder.for_development_environment,
}


def get_policy(policy_name: str, config: dict[str, Any] | None = None, 
               environment: PolicyEnvironment | None = None) -> BusinessRule:
    """
    Get policy instance by name with enhanced configuration support.
    
    Args:
        policy_name: Name of the policy to retrieve
        config: Optional configuration to override defaults
        environment: Optional environment for configuration
        
    Returns:
        BusinessRule: Instance of the requested policy
        
    Raises:
        ValueError: If policy name is not found
    """
    policy_class = POLICY_REGISTRY.get(policy_name)
    if not policy_class:
        available = ", ".join(POLICY_REGISTRY.keys())
        raise ValueError(
            f"Unknown policy: {policy_name}. Available policies: {available}"
        )
    
    # Get configuration from manager if not provided
    if config is None and environment:
        config_manager = PolicyConfigManager(environment)
        
        # Get appropriate config based on policy type
        config_getters = {
            "password": config_manager.get_password_config,
            "session": config_manager.get_session_config,
            "mfa": config_manager.get_mfa_config,
            "lockout": config_manager.get_lockout_config,
            "risk": config_manager.get_risk_config,
            "compliance": config_manager.get_compliance_config,
        }
        
        if policy_name in config_getters:
            policy_config = config_getters[policy_name]()
            config = policy_config.__dict__
    
    # Create policy instance
    if config:
        return policy_class(config)
    return policy_class()


def get_scenario(scenario_name: str, environment: PolicyEnvironment | None = None) -> PolicyBuilder:
    """
    Get a pre-configured policy scenario.
    
    Args:
        scenario_name: Name of the scenario
        environment: Optional environment override
        
    Returns:
        PolicyBuilder: Configured policy builder
        
    Raises:
        ValueError: If scenario name is not found
    """
    scenario_builder = SCENARIO_REGISTRY.get(scenario_name)
    if not scenario_builder:
        available = ", ".join(SCENARIO_REGISTRY.keys())
        raise ValueError(
            f"Unknown scenario: {scenario_name}. Available scenarios: {available}"
        )
    
    builder = scenario_builder()
    if environment:
        builder = builder.for_environment(environment)
    
    return builder


def validate_all_policies(
    policy_data: dict[str, dict[str, Any]],
    policy_configs: dict[str, dict[str, Any]] | None = None
) -> dict[str, list[PolicyViolation]]:
    """
    Validate data against multiple policies.
    
    Args:
        policy_data: Dictionary mapping policy names to their validation data
        policy_configs: Optional dictionary of policy configurations
        
    Returns:
        Dictionary mapping policy names to their violations
    """
    results = {}
    configs = policy_configs or {}
    
    for policy_name, data in policy_data.items():
        try:
            config = configs.get(policy_name)
            policy = get_policy(policy_name, config)
            violations = policy.validate(data)
            results[policy_name] = violations
        except ValueError as e:
            # Invalid policy name
            results[policy_name] = [PolicyViolation(
                rule_name="invalid_policy",
                description=str(e),
                severity="error",
                current_value=policy_name,
                expected_value="Valid policy name"
            )]
        except Exception as e:
            # Other validation errors
            results[policy_name] = [PolicyViolation(
                rule_name="policy_error",
                description=f"Error validating policy {policy_name}: {e!s}",
                severity="error",
                current_value=None,
                expected_value=None
            )]
    
    return results


def get_all_violations_by_severity(
    validation_results: dict[str, list[PolicyViolation]]
) -> dict[str, list[PolicyViolation]]:
    """
    Group all violations by severity level.
    
    Args:
        validation_results: Results from validate_all_policies
        
    Returns:
        Dictionary mapping severity levels to violations
    """
    by_severity = {
        "critical": [],
        "error": [],
        "warning": [],
        "info": []
    }
    
    for policy_name, violations in validation_results.items():
        for violation in violations:
            if violation.severity in by_severity:
                # Add policy context to violation
                existing_context = violation.context or {}
                new_context = {**existing_context, "policy": policy_name}

                violation_with_context = PolicyViolation(
                    rule_name=f"{policy_name}.{violation.rule_name}",
                    description=violation.description,
                    severity=violation.severity,
                    current_value=violation.current_value,
                    expected_value=violation.expected_value,
                    context=new_context
                )
                by_severity[violation.severity].append(violation_with_context)
    
    return by_severity


def has_blocking_violations(
    validation_results: dict[str, list[PolicyViolation]]
) -> bool:
    """
    Check if there are any blocking violations (critical or error).
    
    Args:
        validation_results: Results from validate_all_policies
        
    Returns:
        True if there are blocking violations
    """
    for violations in validation_results.values():
        if any(v.severity in ["critical", "error"] for v in violations):
            return True
    return False


def get_policy_summary(
    validation_results: dict[str, list[PolicyViolation]]
) -> dict[str, Any]:
    """
    Get summary statistics of policy validation.
    
    Args:
        validation_results: Results from validate_all_policies
        
    Returns:
        Summary with counts and compliance status
    """
    total_violations = sum(len(v) for v in validation_results.values())
    by_severity = get_all_violations_by_severity(validation_results)
    
    return {
        "total_policies_checked": len(validation_results),
        "total_violations": total_violations,
        "critical_count": len(by_severity["critical"]),
        "error_count": len(by_severity["error"]),
        "warning_count": len(by_severity["warning"]),
        "info_count": len(by_severity["info"]),
        "is_compliant": not has_blocking_violations(validation_results),
        "policies_with_violations": [
            policy for policy, violations in validation_results.items()
            if violations
        ],
        "policies_compliant": [
            policy for policy, violations in validation_results.items()
            if not violations
        ]
    }


def create_policy_chain(*policies: str) -> list[BusinessRule]:
    """
    Create a chain of policies to validate in sequence.
    
    Args:
        *policies: Policy names to chain
        
    Returns:
        List of policy instances
    """
    return [get_policy(policy_name) for policy_name in policies]


def validate_policy_chain(
    policy_chain: list[BusinessRule],
    data: dict[str, Any]
) -> dict[str, list[PolicyViolation]]:
    """
    Validate data through a chain of policies.
    
    Args:
        policy_chain: List of policy instances
        data: Data to validate
        
    Returns:
        Dictionary mapping policy class names to violations
    """
    results = {}
    
    for policy in policy_chain:
        policy_name = policy.__class__.__name__
        violations = policy.validate(data)
        results[policy_name] = violations
        
        # Stop chain if critical violations found
        if any(v.severity == "critical" for v in violations):
            break
    
    return results
