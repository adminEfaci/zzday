"""
Identity Domain Error Hierarchy

Domain-specific exceptions that represent business rule violations
and domain constraint failures.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.errors import DomainError


class IdentityDomainError(DomainError):
    """Base error for identity domain."""

    def __init__(
        self,
        message: str,
        code: str | None = None,
        user_message: str | None = None,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
        severity: str = "error",
        category: str = "general"
    ):
        super().__init__(message, code, details, cause)
        if user_message:
            self.details["user_message"] = user_message
        
        # Add domain context
        self.details["domain"] = "identity"
        self.details["timestamp"] = datetime.now(UTC).isoformat()
        self.details["severity"] = severity
        self.details["category"] = category

    def get_user_friendly_message(self) -> str:
        """Get user-friendly error message."""
        return self.details.get("user_message", "An error occurred. Please try again.")

    def get_error_context(self) -> dict[str, Any]:
        """Get error context for logging and monitoring."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.code,
            "domain": self.details.get("domain"),
            "timestamp": self.details.get("timestamp"),
            "severity": self.details.get("severity"),
            "category": self.details.get("category"),
            "user_message": self.details.get("user_message"),
            "technical_message": str(self),
        }

    def is_retryable(self) -> bool:
        """Check if this error is retryable."""
        retryable_errors = {
            "RATE_LIMIT_EXCEEDED", "SERVICE_UNAVAILABLE", 
            "TEMPORARY_FAILURE", "NETWORK_ERROR", "TIMEOUT_ERROR"
        }
        return self.code in retryable_errors

    def is_security_related(self) -> bool:
        """Check if this is a security-related error."""
        security_errors = {
            "AUTHENTICATION_ERROR", "AUTHORIZATION_ERROR",
            "SECURITY_POLICY_ERROR", "SUSPICIOUS_ACTIVITY",
            "ACCOUNT_LOCKED", "INVALID_CREDENTIALS", "MFA_REQUIRED",
            "IP_BLOCKED", "SECURITY_POLICY_VIOLATION"
        }
        return self.code in security_errors

    def is_user_actionable(self) -> bool:
        """Check if user can take action to resolve this error."""
        user_actionable_errors = {
            "INVALID_CREDENTIALS", "PASSWORD_EXPIRED", "MFA_REQUIRED",
            "EMAIL_NOT_VERIFIED", "ACCOUNT_LOCKED", "VALIDATION_ERROR"
        }
        return self.code in user_actionable_errors

    def get_severity_level(self) -> int:
        """Get numeric severity level for comparison."""
        severity_levels = {
            "info": 1,
            "warning": 2,
            "error": 3,
            "critical": 4
        }
        return severity_levels.get(self.details.get("severity", "error"), 3)

    def should_alert_security_team(self) -> bool:
        """Check if this error should trigger security team alerts."""
        alert_worthy_errors = {
            "SUSPICIOUS_ACTIVITY", "BRUTE_FORCE_ATTACK", 
            "PRIVILEGE_ESCALATION", "DATA_BREACH", "ACCOUNT_COMPROMISE"
        }
        return self.code in alert_worthy_errors or self.get_severity_level() >= 4


# =============================================================================
# Base Error Categories
# =============================================================================

class AuthenticationError(IdentityDomainError):
    """Base authentication error."""
    default_code = "AUTHENTICATION_ERROR"
    status_code = 401


class AuthorizationError(IdentityDomainError):
    """Base authorization error."""
    default_code = "AUTHORIZATION_ERROR"
    status_code = 403


class VerificationError(IdentityDomainError):
    """Base verification error."""
    default_code = "VERIFICATION_ERROR"


class SecurityPolicyError(IdentityDomainError):
    """Base security policy error."""
    default_code = "SECURITY_POLICY_ERROR"


class ComplianceError(IdentityDomainError):
    """Base compliance error."""
    default_code = "COMPLIANCE_ERROR"


class BusinessRuleError(IdentityDomainError):
    """Base business rule error."""
    default_code = "BUSINESS_RULE_ERROR"


class ValidationError(IdentityDomainError):
    """Base validation error."""
    default_code = "VALIDATION_ERROR"
    status_code = 400


# =============================================================================
# Rate Limiting Errors
# =============================================================================

class IdentityRateLimitError(IdentityDomainError):
    """Identity-specific rate limit errors."""
    default_code = "IDENTITY_RATE_LIMIT"
    status_code = 429


class VerificationAttemptsExceededError(IdentityRateLimitError):
    """Too many verification attempts."""

    def __init__(self, retry_after: datetime):
        retry_in = int((retry_after - datetime.now(UTC)).total_seconds())
        super().__init__(
            "Too many verification attempts",
            code="VERIFICATION_ATTEMPTS_EXCEEDED",
            user_message=f"Too many verification attempts. Please try again in {retry_in} seconds."
        )
        self.details["retry_after"] = retry_after.isoformat()
        self.details["retry_in_seconds"] = retry_in


# =============================================================================
# Permission Lifecycle Errors
# =============================================================================

class PermissionNotFoundError(AuthorizationError):
    """Permission does not exist."""
    
    def __init__(self, identifier: str):
        super().__init__(
            f"Permission not found: {identifier}",
            code="PERMISSION_NOT_FOUND"
        )
        self.details["permission"] = identifier


class PermissionAlreadyExistsError(BusinessRuleError):
    """Permission with code already exists."""
    
    def __init__(self, code: str):
        super().__init__(
            f"Permission with code '{code}' already exists",
            code="PERMISSION_ALREADY_EXISTS",
            user_message="A permission with this code already exists.",
            details={"permission_code": code}
        )


class SystemPermissionModificationError(AuthorizationError):
    """Cannot modify system permission."""
    
    def __init__(self, permission_code: str):
        super().__init__(
            f"Cannot modify system permission: {permission_code}",
            code="SYSTEM_PERMISSION_MODIFICATION",
            user_message="System permissions cannot be modified.",
            details={"permission_code": permission_code}
        )


class DeletedPermissionOperationError(BusinessRuleError):
    """Cannot operate on deleted permission."""
    
    def __init__(self, permission_id: UUID, operation: str):
        super().__init__(
            f"Cannot perform '{operation}' on deleted permission: {permission_id}",
            code="DELETED_PERMISSION_OPERATION",
            user_message="Cannot modify deleted permissions.",
            details={"permission_id": str(permission_id), "operation": operation}
        )


# =============================================================================
# Permission Validation Errors
# =============================================================================

class InvalidPermissionCodeError(ValidationError):
    """Permission code format is invalid."""
    
    def __init__(self, code: str, reason: str = ""):
        message = f"Invalid permission code format: {code}"
        if reason:
            message += f" - {reason}"
        
        super().__init__(
            message,
            code="INVALID_PERMISSION_CODE",
            user_message="Permission code format is invalid.",
            details={"permission_code": code, "reason": reason}
        )


class PermissionCodeTooLongError(ValidationError):
    """Permission code exceeds maximum length."""
    
    def __init__(self, code: str, max_length: int = 100):
        super().__init__(
            f"Permission code too long: {len(code)} chars (max {max_length})",
            code="PERMISSION_CODE_TOO_LONG",
            user_message=f"Permission code must be {max_length} characters or less.",
            details={"permission_code": code, "length": len(code), "max_length": max_length}
        )


# =============================================================================
# Permission Hierarchy Errors
# =============================================================================

class CircularPermissionHierarchyError(BusinessRuleError):
    """Permission hierarchy would create circular reference."""
    
    def __init__(self, permission_id: UUID, parent_id: UUID):
        super().__init__(
            f"Moving permission {permission_id} under {parent_id} would create circular reference",
            code="CIRCULAR_PERMISSION_HIERARCHY",
            user_message="This change would create a circular hierarchy.",
            details={"permission_id": str(permission_id), "parent_id": str(parent_id)}
        )


class PermissionHierarchyTooDeepError(BusinessRuleError):
    """Permission hierarchy exceeds maximum depth."""
    
    def __init__(self, current_depth: int, max_depth: int = 10):
        super().__init__(
            f"Permission hierarchy too deep: {current_depth} levels (max {max_depth})",
            code="PERMISSION_HIERARCHY_TOO_DEEP",
            user_message=f"Permission hierarchy cannot exceed {max_depth} levels.",
            details={"current_depth": current_depth, "max_depth": max_depth}
        )


class SelfParentPermissionError(BusinessRuleError):
    """Permission cannot be its own parent."""
    
    def __init__(self, permission_id: UUID):
        super().__init__(
            f"Permission {permission_id} cannot be its own parent",
            code="SELF_PARENT_PERMISSION",
            user_message="A permission cannot be its own parent.",
            details={"permission_id": str(permission_id)}
        )


class InactiveParentPermissionError(BusinessRuleError):
    """Cannot create permission under inactive parent."""
    
    def __init__(self, parent_id: UUID):
        super().__init__(
            f"Cannot create permission under inactive parent: {parent_id}",
            code="INACTIVE_PARENT_PERMISSION", 
            user_message="Cannot create permissions under inactive parent.",
            details={"parent_id": str(parent_id)}
        )


# =============================================================================
# Permission Assignment Errors
# =============================================================================

class DangerousPermissionError(AuthorizationError):
    """Dangerous permission requires explicit confirmation."""
    
    def __init__(self, permission_code: str):
        super().__init__(
            f"Dangerous permission '{permission_code}' requires explicit confirmation",
            code="DANGEROUS_PERMISSION_CONFIRMATION",
            user_message="This is a dangerous permission that requires explicit confirmation.",
            details={"permission_code": permission_code}
        )


class MfaRequiredError(AuthorizationError):
    """Permission requires MFA verification."""
    
    def __init__(self, permission_code: str):
        super().__init__(
            f"Permission '{permission_code}' requires MFA verification",
            code="MFA_REQUIRED",
            user_message="This permission requires multi-factor authentication.",
            details={"permission_code": permission_code}
        )


class InactivePermissionAssignmentError(BusinessRuleError):
    """Cannot assign inactive permission."""
    
    def __init__(self, permission_code: str):
        super().__init__(
            f"Cannot assign inactive permission: {permission_code}",
            code="INACTIVE_PERMISSION_ASSIGNMENT",
            user_message="Cannot assign inactive permissions.",
            details={"permission_code": permission_code}
        )


# =============================================================================
# Permission Evaluation Errors
# =============================================================================

class PermissionEvaluationError(AuthorizationError):
    """Error during permission evaluation."""
    
    def __init__(self, permission_code: str, context: str = ""):
        message = f"Permission evaluation failed for: {permission_code}"
        if context:
            message += f" in context: {context}"
        
        super().__init__(
            message,
            code="PERMISSION_EVALUATION_ERROR",
            user_message="Permission evaluation failed.",
            details={"permission_code": permission_code, "context": context}
        )


class ConstraintViolationError(AuthorizationError):
    """Permission constraint not satisfied."""
    
    def __init__(self, permission_code: str, failed_constraints: list[str]):
        super().__init__(
            f"Constraint violation for permission '{permission_code}': {', '.join(failed_constraints)}",
            code="CONSTRAINT_VIOLATION",
            user_message="Permission constraints not satisfied.",
            details={"permission_code": permission_code, "failed_constraints": failed_constraints}
        )


class ConflictingPermissionsError(BusinessRuleError):
    """Conflicting permissions detected."""
    
    def __init__(self, permission1_code: str, permission2_code: str, conflict_reason: str):
        super().__init__(
            f"Conflicting permissions: {permission1_code} and {permission2_code} - {conflict_reason}",
            code="CONFLICTING_PERMISSIONS",
            user_message="Conflicting permissions detected.",
            details={
                "permission1": permission1_code,
                "permission2": permission2_code,
                "reason": conflict_reason
            }
        )


# =============================================================================
# Permission Constraint Errors
# =============================================================================

class InvalidConstraintError(ValidationError):
    """Permission constraint is invalid."""
    
    def __init__(self, constraint_key: str, constraint_value: str, reason: str):
        super().__init__(
            f"Invalid constraint '{constraint_key}': {constraint_value} - {reason}",
            code="INVALID_CONSTRAINT",
            user_message="Permission constraint is invalid.",
            details={
                "constraint_key": constraint_key,
                "constraint_value": constraint_value,
                "reason": reason
            }
        )


class ConstraintNotFoundError(ValidationError):
    """Constraint does not exist on permission."""
    
    def __init__(self, permission_code: str, constraint_key: str):
        super().__init__(
            f"Constraint '{constraint_key}' not found on permission '{permission_code}'",
            code="CONSTRAINT_NOT_FOUND",
            user_message="The specified constraint was not found.",
            details={"permission_code": permission_code, "constraint_key": constraint_key}
        )


# =============================================================================
# Permission Operation Errors
# =============================================================================

class PermissionMergeError(BusinessRuleError):
    """Cannot merge permissions."""
    
    def __init__(self, permission1_code: str, permission2_code: str, reason: str):
        super().__init__(
            f"Cannot merge permissions {permission1_code} and {permission2_code}: {reason}",
            code="PERMISSION_MERGE_ERROR",
            user_message="Cannot merge the specified permissions.",
            details={
                "permission1": permission1_code,
                "permission2": permission2_code,
                "reason": reason
            }
        )


class PermissionCloneError(BusinessRuleError):
    """Cannot clone permission."""
    
    def __init__(self, permission_code: str, reason: str):
        super().__init__(
            f"Cannot clone permission {permission_code}: {reason}",
            code="PERMISSION_CLONE_ERROR",
            user_message="Cannot clone the specified permission.",
            details={"permission_code": permission_code, "reason": reason}
        )


# =============================================================================
# Role Errors
# =============================================================================

class RoleNotFoundError(AuthorizationError):
    """Role does not exist."""
    
    def __init__(self, role_name: str):
        super().__init__(
            f"Role not found: {role_name}",
            code="ROLE_NOT_FOUND"
        )
        self.details["role"] = role_name


class InsufficientPermissionsError(AuthorizationError):
    """User lacks required permissions."""
    
    def __init__(self, required_permissions: list[str], user_permissions: list[str] | None = None):
        super().__init__(
            f"Insufficient permissions. Required: {', '.join(required_permissions)}",
            code="INSUFFICIENT_PERMISSIONS",
            user_message="You don't have permission to perform this action."
        )
        self.details["required_permissions"] = required_permissions
        if user_permissions:
            self.details["user_permissions"] = user_permissions


class InvalidRoleHierarchyError(BusinessRuleError):
    """Raised when role hierarchy would create circular reference."""
    
    def __init__(self, role_id: UUID, parent_role_id: UUID):
        super().__init__(
            f"Invalid role hierarchy: {role_id} -> {parent_role_id} would create circular reference",
            code="INVALID_ROLE_HIERARCHY",
            user_message="Invalid role hierarchy configuration.",
            details={"role_id": str(role_id), "parent_role_id": str(parent_role_id)}
        )


class CircularRoleInheritanceError(BusinessRuleError):
    """Raised when role inheritance would create circular dependency."""
    
    def __init__(self, role_path: list[str]):
        super().__init__(
            f"Circular role inheritance detected: {' -> '.join(role_path)}",
            code="CIRCULAR_ROLE_INHERITANCE",
            user_message="Role inheritance configuration would create a circular dependency.",
            details={"role_path": role_path}
        )


class SystemRoleModificationError(AuthorizationError):
    """Raised when attempting to modify a system role."""
    
    def __init__(self, role_name: str):
        super().__init__(
            f"Cannot modify system role: {role_name}",
            code="SYSTEM_ROLE_MODIFICATION",
            user_message="System roles cannot be modified.",
            details={"role_name": role_name}
        )


class RoleAssignmentError(AuthorizationError):
    """Raised when role assignment fails."""
    
    def __init__(self, user_id: UUID, role_name: str, reason: str):
        super().__init__(
            f"Failed to assign role {role_name} to user {user_id}: {reason}",
            code="ROLE_ASSIGNMENT_ERROR",
            user_message=f"Role assignment failed: {reason}",
            details={"user_id": str(user_id), "role_name": role_name, "reason": reason}
        )


class PermissionDeniedError(AuthorizationError):
    """Raised when permission is explicitly denied."""
    
    def __init__(self, resource: str, action: str):
        super().__init__(
            f"Permission denied for action '{action}' on resource '{resource}'",
            code="PERMISSION_DENIED",
            user_message="Permission denied for this action.",
            details={"resource": resource, "action": action}
        )


class InvalidPermissionScopeError(AuthorizationError):
    """Raised when permission scope is invalid."""
    
    def __init__(self, permission: str, scope: str):
        super().__init__(
            f"Invalid scope '{scope}' for permission '{permission}'",
            code="INVALID_PERMISSION_SCOPE",
            user_message="Invalid permission scope.",
            details={"permission": permission, "scope": scope}
        )


# =============================================================================
# Security Errors
# =============================================================================

class SuspiciousActivityError(SecurityPolicyError):
    """Raised when suspicious activity is detected."""
    
    def __init__(self, user_id: UUID | None, activity_type: str, risk_score: float):
        message = f"Suspicious activity detected: {activity_type}"
        if user_id:
            message += f" for user {user_id}"
        message += f" (risk score: {risk_score})"
        
        super().__init__(
            message,
            code="SUSPICIOUS_ACTIVITY",
            user_message="Suspicious activity detected. Additional verification may be required.",
            details={
                "user_id": str(user_id) if user_id else None,
                "activity_type": activity_type,
                "risk_score": risk_score
            }
        )


class IPBlockedError(SecurityPolicyError):
    """Raised when IP address is blocked."""
    
    def __init__(self, ip_address: str, reason: str):
        super().__init__(
            f"IP address blocked: {ip_address} ({reason})",
            code="IP_BLOCKED",
            user_message="Access from this IP address is not allowed.",
            details={"ip_address": ip_address, "reason": reason}
        )


class SecurityPolicyViolationError(SecurityPolicyError):
    """Raised when security policy is violated."""
    
    def __init__(self, policy: str, violation: str):
        super().__init__(
            f"Security policy violation: {policy} - {violation}",
            code="SECURITY_POLICY_VIOLATION",
            user_message="Action violates security policy.",
            details={"policy": policy, "violation": violation}
        )


# =============================================================================
# Compliance Errors
# =============================================================================

class GDPRViolationError(ComplianceError):
    """Raised when GDPR compliance is violated."""
    
    def __init__(self, violation_type: str, details: dict[str, Any]):
        super().__init__(
            f"GDPR violation: {violation_type}",
            code="GDPR_VIOLATION",
            user_message="This action would violate data protection regulations.",
            details={"violation_type": violation_type, **details}
        )


class DataRetentionViolationError(ComplianceError):
    """Raised when data retention policy is violated."""
    
    def __init__(self, data_type: str, retention_period: str):
        super().__init__(
            f"Data retention violation: {data_type} exceeds {retention_period}",
            code="DATA_RETENTION_VIOLATION",
            user_message="Data retention policy violation detected.",
            details={"data_type": data_type, "retention_period": retention_period}
        )


class ConsentRequiredError(ComplianceError):
    """Raised when user consent is required but not provided."""
    
    def __init__(self, user_id: UUID, consent_type: str):
        super().__init__(
            f"Consent required for user {user_id}: {consent_type}",
            code="CONSENT_REQUIRED",
            user_message="Your consent is required for this operation.",
            details={"user_id": str(user_id), "consent_type": consent_type}
        )


# =============================================================================
# Audit Log Errors
# =============================================================================

class AuditLogError(IdentityDomainError):
    """Base audit log error."""
    default_code = "AUDIT_LOG_ERROR"


class AuditLogTamperingDetectedError(AuditLogError):
    """Raised when audit log tampering is detected."""
    
    def __init__(self, log_id: str, details: dict[str, Any]):
        super().__init__(
            f"Audit log tampering detected for log {log_id}",
            code="AUDIT_LOG_TAMPERING",
            user_message="Security breach: Audit log integrity violation detected.",
            details={"log_id": log_id, **details}
        )


class InsufficientAuditDataError(AuditLogError):
    """Raised when insufficient audit data for compliance."""
    
    def __init__(self, required_fields: list[str]):
        super().__init__(
            f"Insufficient audit data. Missing fields: {', '.join(required_fields)}",
            code="INSUFFICIENT_AUDIT_DATA",
            user_message="Unable to complete audit due to missing data.",
            details={"missing_fields": required_fields}
        )


# =============================================================================
# Operational Errors
# =============================================================================

class BulkOperationLimitError(IdentityDomainError):
    """Raised when bulk operation exceeds allowed limit."""
    
    def __init__(self, operation: str, requested: int, limit: int):
        super().__init__(
            f"Bulk operation '{operation}' exceeds limit: {requested} > {limit}",
            code="BULK_OPERATION_LIMIT",
            user_message=f"Operation exceeds allowed limit. Maximum: {limit}",
            details={"operation": operation, "requested": requested, "limit": limit}
        )


class MaintenanceModeError(IdentityDomainError):
    """Raised when system is in maintenance mode."""
    
    def __init__(self, estimated_completion: datetime | None = None):
        message = "System is in maintenance mode"
        user_message = "System is currently under maintenance."
        
        if estimated_completion:
            completion_str = estimated_completion.strftime("%Y-%m-%d %H:%M UTC")
            user_message += f" Expected completion: {completion_str}"
            
        super().__init__(
            message,
            code="MAINTENANCE_MODE",
            user_message=user_message
        )
        
        if estimated_completion:
            self.details["estimated_completion"] = estimated_completion.isoformat()


# =============================================================================
# Business Rule Errors
# =============================================================================

class InvalidOperationError(BusinessRuleError):
    """Raised when an operation cannot be performed due to business rules."""
    
    def __init__(self, message: str, operation: str | None = None):
        super().__init__(
            message,
            code="INVALID_OPERATION",
            user_message="This operation cannot be performed at this time."
        )
        if operation:
            self.details["operation"] = operation


# Export all errors (alphabetically sorted)
__all__ = [
    # Base classes
    'AuthenticationError',
    'AuthorizationError',
    'BusinessRuleError',
    'ComplianceError',
    'IdentityDomainError',
    'IdentityRateLimitError',
    'SecurityPolicyError',
    'ValidationError',
    'VerificationError',
    
    # Audit log errors
    'AuditLogError',
    'AuditLogTamperingDetectedError',
    'InsufficientAuditDataError',
    
    # Operational errors
    'BulkOperationLimitError',
    'MaintenanceModeError',
    
    # Business rule errors
    'InvalidOperationError',
    
    # Compliance errors
    'ConsentRequiredError',
    'DataRetentionViolationError',
    'GDPRViolationError',
    
    # Permission errors
    'CircularPermissionHierarchyError',
    'ConflictingPermissionsError',
    'ConstraintNotFoundError',
    'ConstraintViolationError',
    'DangerousPermissionError',
    'DeletedPermissionOperationError',
    'InactiveParentPermissionError',
    'InactivePermissionAssignmentError',
    'InvalidConstraintError',
    'InvalidPermissionCodeError',
    'MfaRequiredError',
    'PermissionAlreadyExistsError',
    'PermissionCloneError',
    'PermissionCodeTooLongError',
    'PermissionEvaluationError',
    'PermissionHierarchyTooDeepError',
    'PermissionMergeError',
    'PermissionNotFoundError',
    'SelfParentPermissionError',
    'SystemPermissionModificationError',
    
    # Role errors
    'CircularRoleInheritanceError',
    'InsufficientPermissionsError',
    'InvalidPermissionScopeError',
    'InvalidRoleHierarchyError',
    'PermissionDeniedError',
    'RoleAssignmentError',
    'RoleNotFoundError',
    'SystemRoleModificationError',
    
    # Security errors
    'IPBlockedError',
    'SecurityPolicyViolationError',
    'SuspiciousActivityError',
    
    # Rate limiting errors
    'VerificationAttemptsExceededError',
]