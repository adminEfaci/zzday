"""
Identity Domain Events

Base events and aggregate-level events for the identity domain.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.core.events.types import DomainEvent


class IdentityDomainEvent(DomainEvent):
    """Base class for all identity domain events."""

    # Domain identifier for all identity events
    domain: str = Field(default="identity", frozen=True)

    def get_aggregate_id(self) -> str:
        """Get the aggregate ID for this event."""
        raise NotImplementedError("Subclasses must implement get_aggregate_id")

    def get_event_metadata(self) -> dict[str, Any]:
        """Get event metadata for audit and monitoring."""
        return {
            "domain": self.domain,
            "event_type": self.__class__.__name__,
            "aggregate_id": self.get_aggregate_id(),
            "timestamp": self.occurred_at.isoformat(),
            "event_id": str(self.event_id),
            "correlation_id": getattr(self, 'correlation_id', None),
            "causation_id": getattr(self, 'causation_id', None),
            "event_version": getattr(self, 'event_version', '1.0'),
            "source": getattr(self, 'source', 'identity-service'),
            "risk_level": self.get_risk_level(),
            "is_security_event": self.is_security_event(),
            "is_compliance_event": self.is_compliance_event(),
            "requires_audit": self.requires_audit(),
        }

    def is_security_event(self) -> bool:
        """Check if this is a security-related event."""
        security_events = {
            'AccessTokenRevoked', 'ComplianceViolationDetected', 'DeviceRegistered',
            'DeviceTrusted', 'DeviceUntrusted', 'IPAllowlisted', 'IPBlocklisted',
            'MFACodeVerificationFailed', 'MFADeviceCreated', 'MFADeviceDisabled',
            'MFADeviceVerified', 'SecurityAlertRaised', 'SessionCreated',
            'SessionTerminated', 'SuspiciousActivityDetected', 'TokenFamilyRevoked',
            'TokenIssued', 'TokenRefreshed', 'TokenRevoked'
        }
        return self.__class__.__name__ in security_events

    def is_compliance_event(self) -> bool:
        """Check if this is a compliance-related event."""
        compliance_events = {
            'AuditLogCreated', 'ComplianceViolationDetected', 'TokenIssued',
            'TokenRevoked', 'AccessTokenRevoked'
        }
        return self.__class__.__name__ in compliance_events

    def requires_audit(self) -> bool:
        """Check if this event requires detailed audit logging."""
        audit_required_events = {
            'AccessTokenRevoked', 'AuditLogCreated', 'ComplianceViolationDetected',
            'DeviceRegistered', 'DeviceTrusted', 'DeviceUntrusted', 'IPAllowlisted',
            'IPBlocklisted', 'MFADeviceCreated', 'MFADeviceDisabled', 'MFADeviceVerified',
            'SecurityAlertRaised', 'SuspiciousActivityDetected', 'TokenFamilyRevoked',
            'TokenIssued', 'TokenRefreshed', 'TokenRevoked'
        }
        return (self.__class__.__name__ in audit_required_events or 
                self.is_security_event() or 
                self.is_compliance_event())

    def get_risk_level(self) -> str:
        """Get risk level for this event."""
        critical_risk_events = {
            'ComplianceViolationDetected', 'SecurityAlertRaised', 'TokenFamilyRevoked'
        }
        high_risk_events = {
            'AccessTokenRevoked', 'IPBlocklisted', 'MFADeviceDisabled',
            'SuspiciousActivityDetected', 'TokenRevoked'
        }
        medium_risk_events = {
            'DeviceUntrusted', 'MFACodeVerificationFailed', 'SessionTerminated'
        }
        
        event_name = self.__class__.__name__
        if event_name in critical_risk_events:
            return "critical"
        if event_name in high_risk_events:
            return "high"
        if event_name in medium_risk_events:
            return "medium"
        return "low"

    def get_event_category(self) -> str:
        """Get event category for classification."""
        if self.is_security_event():
            return "security"
        if self.is_compliance_event():
            return "compliance"
        if "Token" in self.__class__.__name__:
            return "token_management"
        if "Session" in self.__class__.__name__:
            return "session_management"
        if "Device" in self.__class__.__name__:
            return "device_management"
        if "MFA" in self.__class__.__name__:
            return "authentication"
        if "Permission" in self.__class__.__name__:
            return "permission_management"
        if "Role" in self.__class__.__name__:
            return "role_management"
        return "general"

    def should_trigger_notification(self) -> bool:
        """Check if this event should trigger user notifications."""
        notification_events = {
            'DeviceRegistered', 'DeviceTrusted', 'MFADeviceCreated', 'MFADeviceDisabled',
            'SecurityAlertRaised', 'SuspiciousActivityDetected'
        }
        return self.__class__.__name__ in notification_events

    def get_retention_period_days(self) -> int:
        """Get retention period for this event type in days."""
        if self.is_security_event() or self.is_compliance_event():
            return 2555  # 7 years for security and compliance events
        if self.requires_audit():
            return 1095  # 3 years for audit events
        return 365   # 1 year for general events


# =============================================================================
# Session Events
# =============================================================================

class SessionCreated(IdentityDomainEvent):
    """Event when a new session is created."""
    session_id: UUID
    user_id: UUID
    session_type: str
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.session_id)


class SessionTerminated(IdentityDomainEvent):
    """Event when a session is terminated."""
    session_id: UUID
    user_id: UUID
    reason: str
    terminated_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.session_id)


# =============================================================================
# Access Token Events
# =============================================================================

class TokenIssued(IdentityDomainEvent):
    """Event raised when an access token is issued."""
    token_id: UUID
    user_id: UUID
    token_type: str
    scopes: list[str]
    client_id: str | None = None
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenRefreshed(IdentityDomainEvent):
    """Event raised when a token is refreshed."""
    token_id: UUID
    user_id: UUID
    old_token_id: UUID
    refresh_strategy: str
    generation: int

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenRevoked(IdentityDomainEvent):
    """Event raised when a token is revoked."""
    user_id: UUID
    token_id: UUID
    token_type: str
    revoked_by: UUID | None = None
    revocation_reason: str = "user_revoked"

    def get_aggregate_id(self) -> str:
        return str(self.token_id)


class TokenFamilyRevoked(IdentityDomainEvent):
    """Event raised when an entire token family is revoked."""
    family_id: UUID
    user_id: UUID
    revocation_reason: str
    member_count: int

    def get_aggregate_id(self) -> str:
        return str(self.family_id)


# =============================================================================
# MFA Device Events
# =============================================================================

class MFADeviceCreated(IdentityDomainEvent):
    """Event raised when an MFA device is created."""
    device_id: UUID
    user_id: UUID
    method: str
    device_name: str
    verified: bool

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFADeviceVerified(IdentityDomainEvent):
    """Event raised when an MFA device is verified."""
    device_id: UUID
    user_id: UUID
    method: str
    verified_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFADeviceDisabled(IdentityDomainEvent):
    """Event raised when an MFA device is disabled."""
    device_id: UUID
    user_id: UUID
    method: str
    disabled_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class MFACodeVerificationFailed(IdentityDomainEvent):
    """Event raised when MFA code verification fails."""
    device_id: UUID
    user_id: UUID
    failed_attempts: int
    timestamp: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


# =============================================================================
# Device Registration Events
# =============================================================================

class DeviceRegistered(IdentityDomainEvent):
    """Event raised when a device is registered."""
    device_id: UUID
    user_id: UUID
    device_name: str
    device_type: str
    fingerprint: str
    trusted: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class DeviceTrusted(IdentityDomainEvent):
    """Event raised when a device is marked as trusted."""
    device_id: UUID
    user_id: UUID
    trusted_by: UUID | None = None
    trust_method: str = Field(default="user_confirmation")

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


class DeviceUntrusted(IdentityDomainEvent):
    """Event raised when a device is untrusted."""
    user_id: UUID
    device_id: UUID
    untrusted_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.device_id)


# =============================================================================
# Permission Lifecycle Events
# =============================================================================

class PermissionCreated(IdentityDomainEvent):
    """Event raised when a new permission is created."""
    permission_id: UUID
    name: str
    code: str
    permission_type: str
    resource_type: str
    parent_id: UUID | None = None
    created_by: UUID | None = None
    is_system: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionUpdated(IdentityDomainEvent):
    """Event raised when permission details are updated."""
    permission_id: UUID
    updated_by: UUID | None = None
    old_name: str
    new_name: str
    old_description: str
    new_description: str

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionDeleted(IdentityDomainEvent):
    """Event raised when a permission is deleted."""
    permission_id: UUID
    deleted_by: UUID
    permission_code: str
    had_children: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionActivated(IdentityDomainEvent):
    """Event raised when a permission is activated."""
    permission_id: UUID
    activated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionDeactivated(IdentityDomainEvent):
    """Event raised when a permission is deactivated."""
    permission_id: UUID
    deactivated_by: UUID
    reason: str = ""

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


# =============================================================================
# Permission Hierarchy Events
# =============================================================================

class PermissionHierarchyChanged(IdentityDomainEvent):
    """Event raised when permission hierarchy changes."""
    permission_id: UUID
    old_parent_id: UUID | None = None
    new_parent_id: UUID | None = None
    old_path: str
    new_path: str
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


# =============================================================================
# Permission Constraint Events
# =============================================================================

class PermissionConstraintAdded(IdentityDomainEvent):
    """Event raised when a constraint is added to permission."""
    permission_id: UUID
    constraint_key: str
    constraint_value: Any
    old_value: Any = None
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


class PermissionConstraintRemoved(IdentityDomainEvent):
    """Event raised when a constraint is removed from permission."""
    permission_id: UUID
    constraint_key: str
    old_value: Any
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.permission_id)


# =============================================================================
# Permission Operations Events
# =============================================================================

class PermissionCloned(IdentityDomainEvent):
    """Event raised when a permission is cloned."""
    original_permission_id: UUID
    cloned_permission_id: UUID
    cloned_by: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.cloned_permission_id)


class PermissionMerged(IdentityDomainEvent):
    """Event raised when permissions are merged."""
    permission1_id: UUID
    permission2_id: UUID
    merged_permission_id: UUID
    merged_by: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.merged_permission_id)


# =============================================================================
# Role Lifecycle Events
# =============================================================================

class RoleCreated(IdentityDomainEvent):
    """Event raised when a new role is created."""
    role_id: UUID
    name: str
    display_name: str
    role_type: str
    created_by: UUID
    is_system_role: bool = False

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleUpdated(IdentityDomainEvent):
    """Event raised when role details are updated."""
    role_id: UUID
    updated_by: UUID | None
    old_display_name: str
    new_display_name: str
    old_description: str
    new_description: str

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleDeleted(IdentityDomainEvent):
    """Event raised when a role is deleted."""
    role_id: UUID
    deleted_by: UUID
    role_name: str
    had_permissions: bool

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleActivated(IdentityDomainEvent):
    """Event raised when a role is activated."""
    role_id: UUID
    activated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RoleDeactivated(IdentityDomainEvent):
    """Event raised when a role is deactivated."""
    role_id: UUID
    deactivated_by: UUID
    reason: str = ""

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


# =============================================================================
# Role Permission Events
# =============================================================================

class RolePermissionGranted(IdentityDomainEvent):
    """Event raised when permission is granted to role."""
    role_id: UUID
    permission_id: UUID
    permission_name: str
    granted_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class RolePermissionRevoked(IdentityDomainEvent):
    """Event raised when permission is revoked from role."""
    role_id: UUID
    permission_id: UUID
    permission_name: str
    revoked_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


# =============================================================================
# Role Hierarchy Events
# =============================================================================

class RoleHierarchyChanged(IdentityDomainEvent):
    """Event raised when role hierarchy changes."""
    role_id: UUID
    parent_role_id: UUID
    action: str  # parent_added, parent_removed
    updated_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


# =============================================================================
# User Role Assignment Events
# =============================================================================

class RoleAssigned(IdentityDomainEvent):
    """Event raised when a role is assigned to a user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    assigned_by: UUID
    effective_from: datetime
    expires_at: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleUnassigned(IdentityDomainEvent):
    """Event raised when a role is removed from a user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    unassigned_by: UUID
    reason: str = Field(default="manual_removal")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleAssignmentExpired(IdentityDomainEvent):
    """Event raised when role assignment expires."""
    user_id: UUID
    role_id: UUID
    role_name: str
    expired_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class RoleAssignmentSuspended(IdentityDomainEvent):
    """Event raised when role assignment is suspended."""
    user_id: UUID
    role_id: UUID
    suspended_by: UUID
    reason: str
    suspended_until: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# User Permission Events
# =============================================================================

class PermissionGranted(IdentityDomainEvent):
    """Event raised when a permission is granted to a user."""
    user_id: UUID
    permission_id: UUID
    permission_name: str
    granted_by: UUID
    scope: str | None = None
    expires_at: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PermissionRevoked(IdentityDomainEvent):
    """Event raised when a permission is revoked from a user."""
    user_id: UUID
    permission_id: UUID
    permission_name: str
    revoked_by: UUID
    reason: str = Field(default="manual_revocation")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Legacy Role Permission Events
# =============================================================================

class PermissionAddedToRole(IdentityDomainEvent):
    """Event raised when a permission is added to a role."""
    role_id: UUID
    role_name: str
    permission: str

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


class PermissionRemovedFromRole(IdentityDomainEvent):
    """Event raised when a permission is removed from a role."""
    role_id: UUID
    role_name: str
    permission: str

    def get_aggregate_id(self) -> str:
        return str(self.role_id)


# =============================================================================
# Security Events
# =============================================================================

class SecurityAlertRaised(IdentityDomainEvent):
    """Event raised when a security alert is triggered."""
    alert_type: str
    risk_level: str
    description: str
    source_ip: str
    user_agent: str
    evidence: dict[str, Any]
    user_id: UUID | None = None
    automatic_response: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.source_ip


class SuspiciousActivityDetected(IdentityDomainEvent):
    """Event raised when suspicious activity is detected."""
    activity_type: str
    risk_score: float
    ip_address: str
    user_agent: str
    patterns_detected: list[str]
    confidence_score: float
    user_id: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.ip_address


# =============================================================================
# IP Management Events
# =============================================================================

class IPAllowlisted(IdentityDomainEvent):
    """Event raised when IP is added to allowlist."""
    ip_address: str
    allowlisted_by: UUID
    reason: str
    expires_at: datetime | None = None
    user_id: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.ip_address


class IPBlocklisted(IdentityDomainEvent):
    """Event raised when IP is blocklisted."""
    ip_address: str
    blocklisted_by: UUID
    reason: str
    threat_level: str
    expires_at: datetime | None = None
    user_id: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.ip_address


# =============================================================================
# Audit Events
# =============================================================================

class AuditLogCreated(IdentityDomainEvent):
    """Event raised when an audit log entry is created."""
    audit_id: UUID
    action: str
    resource_type: str
    user_id: UUID | None = None
    actor_id: UUID | None = None
    resource_id: str | None = None
    changes: dict[str, Any] | None = None

    def get_aggregate_id(self) -> str:
        if self.user_id:
            return str(self.user_id)
        if self.actor_id:
            return str(self.actor_id)
        return "system"


# =============================================================================
# Compliance Events
# =============================================================================

class ComplianceViolationDetected(IdentityDomainEvent):
    """Event raised when a compliance violation is detected."""
    violation_type: str
    severity: str
    description: str
    regulation: str  # GDPR, SOX, HIPAA, etc.
    user_id: UUID | None = None
    remediation_required: bool = Field(default=True)
    auto_remediation_possible: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else "system"


# Export all events (organized by category)
__all__ = [
    # Base Events
    'IdentityDomainEvent',
    
    # Session Events
    'SessionCreated',
    'SessionTerminated',
    
    # Access Token Events
    'TokenFamilyRevoked',
    'TokenIssued',
    'TokenRefreshed',
    'TokenRevoked',
    
    # MFA Device Events
    'MFACodeVerificationFailed',
    'MFADeviceCreated',
    'MFADeviceDisabled',
    'MFADeviceVerified',
    
    # Device Registration Events
    'DeviceRegistered',
    'DeviceTrusted',
    'DeviceUntrusted',
    
    # Permission Events
    'PermissionActivated',
    'PermissionCloned',
    'PermissionConstraintAdded',
    'PermissionConstraintRemoved',
    'PermissionCreated',
    'PermissionDeactivated',
    'PermissionDeleted',
    'PermissionGranted',
    'PermissionHierarchyChanged',
    'PermissionMerged',
    'PermissionRevoked',
    'PermissionUpdated',
    
    # Role Events
    'RoleActivated',
    'RoleAssigned',
    'RoleAssignmentExpired',
    'RoleAssignmentSuspended',
    'RoleCreated',
    'RoleDeactivated',
    'RoleDeleted',
    'RoleHierarchyChanged',
    'RolePermissionGranted',
    'RolePermissionRevoked',
    'RoleUnassigned',
    'RoleUpdated',
    
    # Legacy Role Permission Events
    'PermissionAddedToRole',
    'PermissionRemovedFromRole',
    
    # Security Events
    'SecurityAlertRaised',
    'SuspiciousActivityDetected',
    
    # IP Management Events
    'IPAllowlisted',
    'IPBlocklisted',
    
    # Audit Events
    'AuditLogCreated',
    
    # Compliance Events
    'ComplianceViolationDetected'
]