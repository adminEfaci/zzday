"""Base classes for identity domain events."""

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
        authentication_events = {
            'LoginSuccessful', 'LoginFailed', 'AccountLockedOut', 'AccountUnlocked',
            'MFAEnabled', 'MFADisabled', 'MFADeviceCreated', 'MFADeviceVerified',
            'MFACodeVerificationFailed', 'SessionCreated', 'SessionTerminated'
        }
        
        authorization_events = {
            'PermissionGranted', 'PermissionRevoked', 'RoleAssigned', 'RoleUnassigned',
            'PermissionCreated', 'PermissionUpdated', 'PermissionDeleted',
            'RoleCreated', 'RoleUpdated', 'RoleDeleted'
        }
        
        security_events = {
            'SecurityAlertRaised', 'SuspiciousActivityDetected', 'DeviceRegistered',
            'DeviceTrusted', 'DeviceUntrusted', 'IPAllowlisted', 'IPBlocklisted'
        }
        
        token_events = {
            'TokenIssued', 'TokenRefreshed', 'TokenRevoked', 'TokenFamilyRevoked'
        }
        
        event_name = self.__class__.__name__
        if event_name in authentication_events:
            return "authentication"
        if event_name in authorization_events:
            return "authorization"
        if event_name in security_events:
            return "security"
        if event_name in token_events:
            return "token"
        return "general"