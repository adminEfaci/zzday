"""
User Lifecycle Event Handlers

Handles user lifecycle events (created/deleted/suspended) from the Identity module 
and creates corresponding audit trails with compliance tracking.
"""

import logging
from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from app.modules.identity.domain.entities.user.user_events import (
    UserCreated, UserDeleted, UserSuspended, UserActivated, UserDeactivated
)
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.domain.enums import AuditAction, AuditOutcome, AuditSeverity, AuditCategory
from app.core.events.handlers import EventHandler
from app.core.logging import get_logger


logger = get_logger(__name__)


class UserCreatedEventHandler(EventHandler[UserCreated]):
    """Event handler for user creation events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: UserCreated) -> None:
        """Handle user created event.
        
        Args:
            event: User created event
        """
        try:
            logger.info(
                "Processing user created event",
                user_id=str(event.user_id),
                email=event.email,
                event_id=str(event.event_id)
            )
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.USER_CREATED,
                operation="user.account_created",
                description=f"New user account created with role '{event.role}'",
                resource_type="user_account",
                resource_id=str(event.user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.INFO,
                category=AuditCategory.USER_MANAGEMENT,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                ip_address=getattr(event, 'ip_address', None),
                user_agent=getattr(event, 'user_agent', None),
                tags=["user-creation", "account-provisioning", event.registration_method],
                compliance_tags=["user-lifecycle", "access-provisioning", "identity-management"],
                custom_fields={
                    "email": event.email,
                    "name": event.name,
                    "role": event.role,
                    "created_by": str(event.created_by) if event.created_by else "self_registration",
                    "registration_method": event.registration_method,
                    "verification_required": event.registration_method == "email",
                    "initial_permissions": self._get_role_permissions(event.role)
                }
            )
            
            # Create compliance audit for data processing
            await self._create_data_processing_audit(event)
            
            # Create admin action audit if created by another user
            if event.created_by:
                await self._create_admin_action_audit(event)
            
            logger.info(
                "Successfully processed user created event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process user created event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_data_processing_audit(self, event: UserCreated) -> None:
        """Create GDPR compliance audit trail.
        
        Args:
            event: User created event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.DATA_PROCESSING,
            operation="compliance.personal_data_collected",
            description="Personal data collected for new user account",
            resource_type="personal_data",
            resource_id=str(event.user_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.INFO,
            category=AuditCategory.COMPLIANCE,
            event_id=str(event.event_id),
            tags=["gdpr", "data-collection", "privacy"],
            compliance_tags=["GDPR-Article-6", "lawful-basis", "data-minimization"],
            custom_fields={
                "data_categories": ["identity", "contact", "authentication"],
                "lawful_basis": "consent",
                "retention_period": "active_account_plus_7_years",
                "data_subject_rights": ["access", "rectification", "erasure", "portability"],
                "consent_timestamp": datetime.now(UTC).isoformat()
            }
        )
    
    async def _create_admin_action_audit(self, event: UserCreated) -> None:
        """Create admin action audit trail.
        
        Args:
            event: User created event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.created_by,
            action_type=AuditAction.ADMIN_ACTION,
            operation="admin.user_provisioned",
            description=f"Administrator created new user account",
            resource_type="admin_action",
            resource_id=str(event.user_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.LOW,
            category=AuditCategory.ADMINISTRATIVE,
            event_id=str(event.event_id),
            tags=["admin-action", "user-provisioning", "privileged-operation"],
            compliance_tags=["privileged-access", "administrative-audit"],
            custom_fields={
                "admin_id": str(event.created_by),
                "target_user_id": str(event.user_id),
                "action_type": "user_creation",
                "justification": "administrative_provisioning"
            }
        )
    
    def _get_role_permissions(self, role: str) -> list[str]:
        """Get default permissions for role.
        
        Args:
            role: User role
            
        Returns:
            List of permissions
        """
        # Simplified permission mapping
        role_permissions = {
            "admin": ["all"],
            "user": ["read:own_profile", "write:own_profile"],
            "viewer": ["read:own_profile"]
        }
        return role_permissions.get(role.lower(), ["read:own_profile"])


class UserDeletedEventHandler(EventHandler[UserDeleted]):
    """Event handler for user deletion events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: UserDeleted) -> None:
        """Handle user deleted event.
        
        Args:
            event: User deleted event
        """
        try:
            logger.info(
                "Processing user deleted event",
                user_id=str(event.user_id),
                deleted_by=str(event.deleted_by),
                event_id=str(event.event_id)
            )
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.USER_DELETED,
                operation="user.account_deleted",
                description=f"User account permanently deleted: {event.deletion_reason}",
                resource_type="user_account",
                resource_id=str(event.user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=AuditSeverity.HIGH,
                category=AuditCategory.USER_MANAGEMENT,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                tags=["user-deletion", "account-termination", "data-removal"],
                compliance_tags=["user-lifecycle", "data-retention", "right-to-erasure"],
                custom_fields={
                    "deleted_by": str(event.deleted_by),
                    "deletion_reason": event.deletion_reason,
                    "data_retained": event.data_retained,
                    "retained_data_types": event.retained_data_types,
                    "gdpr_compliant": event.gdpr_compliant,
                    "deletion_method": "permanent",
                    "recovery_possible": False
                }
            )
            
            # Create GDPR compliance audit
            await self._create_gdpr_deletion_audit(event)
            
            # Create data retention audit if data was retained
            if event.data_retained:
                await self._create_data_retention_audit(event)
            
            logger.info(
                "Successfully processed user deleted event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process user deleted event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_gdpr_deletion_audit(self, event: UserDeleted) -> None:
        """Create GDPR deletion compliance audit.
        
        Args:
            event: User deleted event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.DATA_DELETION,
            operation="compliance.right_to_erasure_executed",
            description="GDPR right to erasure request fulfilled",
            resource_type="gdpr_request",
            resource_id=str(event.user_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.HIGH,
            category=AuditCategory.COMPLIANCE,
            event_id=str(event.event_id),
            tags=["gdpr", "right-to-erasure", "data-deletion"],
            compliance_tags=["GDPR-Article-17", "data-subject-rights", "privacy-compliance"],
            custom_fields={
                "request_type": "erasure",
                "legal_basis": event.deletion_reason,
                "data_categories_deleted": ["personal", "behavioral", "preferences"],
                "deletion_verification": "cryptographic_proof_available",
                "compliance_timestamp": datetime.now(UTC).isoformat()
            }
        )
    
    async def _create_data_retention_audit(self, event: UserDeleted) -> None:
        """Create data retention audit trail.
        
        Args:
            event: User deleted event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.DATA_RETENTION,
            operation="compliance.data_retained_for_legal_requirements",
            description="Some data retained for legal/compliance requirements",
            resource_type="retained_data",
            resource_id=str(event.user_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.MEDIUM,
            category=AuditCategory.COMPLIANCE,
            event_id=str(event.event_id),
            tags=["data-retention", "legal-requirement", "compliance"],
            compliance_tags=["data-retention-policy", "legal-hold"],
            custom_fields={
                "retained_data_types": event.retained_data_types,
                "retention_reason": "legal_compliance",
                "retention_period": "7_years",
                "review_date": "annual",
                "data_minimization_applied": True
            }
        )


class UserSuspendedEventHandler(EventHandler[UserSuspended]):
    """Event handler for user suspension events."""
    
    def __init__(self, audit_service: AuditService):
        """Initialize handler with audit service.
        
        Args:
            audit_service: Service for creating audit trails
        """
        self._audit_service = audit_service
        super().__init__()
    
    async def handle(self, event: UserSuspended) -> None:
        """Handle user suspended event.
        
        Args:
            event: User suspended event
        """
        try:
            logger.info(
                "Processing user suspended event",
                user_id=str(event.user_id),
                reason=event.reason,
                event_id=str(event.event_id)
            )
            
            # Determine severity based on reason
            severity = self._determine_suspension_severity(event)
            
            # Create primary audit trail
            await self._audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type=AuditAction.USER_SUSPENDED,
                operation="user.account_suspended",
                description=f"User account suspended: {event.reason}",
                resource_type="user_account",
                resource_id=str(event.user_id),
                outcome=AuditOutcome.SUCCESS,
                severity=severity,
                category=AuditCategory.USER_MANAGEMENT,
                event_id=str(event.event_id),
                correlation_id=getattr(event, 'correlation_id', None),
                tags=["user-suspension", "account-restriction", "security-action"],
                compliance_tags=["access-control", "security-enforcement"],
                custom_fields={
                    "suspended_by": str(event.suspended_by),
                    "suspension_reason": event.reason,
                    "automatic_suspension": event.automatic_suspension,
                    "suspension_expires_at": event.suspension_expires_at.isoformat() if event.suspension_expires_at else None,
                    "access_revoked": True,
                    "sessions_terminated": True,
                    "investigation_required": self._requires_investigation(event.reason)
                }
            )
            
            # Create security audit if suspension is security-related
            if self._is_security_suspension(event.reason):
                await self._create_security_suspension_audit(event)
            
            logger.info(
                "Successfully processed user suspended event",
                user_id=str(event.user_id),
                event_id=str(event.event_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to process user suspended event",
                user_id=str(event.user_id),
                event_id=str(event.event_id),
                error=str(e)
            )
    
    async def _create_security_suspension_audit(self, event: UserSuspended) -> None:
        """Create security-related suspension audit.
        
        Args:
            event: User suspended event
        """
        await self._audit_service.create_audit_trail(
            user_id=event.user_id,
            action_type=AuditAction.SECURITY_ACTION,
            operation="security.account_suspended_for_violation",
            description="Account suspended due to security violation",
            resource_type="security_response",
            resource_id=str(event.user_id),
            outcome=AuditOutcome.SUCCESS,
            severity=AuditSeverity.HIGH,
            category=AuditCategory.SECURITY,
            event_id=str(event.event_id),
            tags=["security-response", "violation-response", "account-protection"],
            compliance_tags=["incident-response", "security-enforcement"],
            custom_fields={
                "violation_type": self._get_violation_type(event.reason),
                "response_type": "account_suspension",
                "automated_response": event.automatic_suspension,
                "threat_mitigation": "access_revoked",
                "follow_up_required": True
            }
        )
    
    def _determine_suspension_severity(self, event: UserSuspended) -> AuditSeverity:
        """Determine severity based on suspension reason.
        
        Args:
            event: User suspended event
            
        Returns:
            Appropriate severity level
        """
        high_severity_reasons = ["security_breach", "fraud", "abuse", "violation"]
        medium_severity_reasons = ["suspicious_activity", "policy_violation", "payment_issue"]
        
        reason_lower = event.reason.lower()
        if any(reason in reason_lower for reason in high_severity_reasons):
            return AuditSeverity.HIGH
        elif any(reason in reason_lower for reason in medium_severity_reasons):
            return AuditSeverity.MEDIUM
        else:
            return AuditSeverity.LOW
    
    def _is_security_suspension(self, reason: str) -> bool:
        """Check if suspension is security-related.
        
        Args:
            reason: Suspension reason
            
        Returns:
            True if security-related
        """
        security_keywords = ["security", "breach", "attack", "fraud", "abuse", "suspicious"]
        return any(keyword in reason.lower() for keyword in security_keywords)
    
    def _requires_investigation(self, reason: str) -> bool:
        """Check if suspension requires investigation.
        
        Args:
            reason: Suspension reason
            
        Returns:
            True if investigation needed
        """
        investigation_keywords = ["breach", "attack", "fraud", "suspicious", "violation"]
        return any(keyword in reason.lower() for keyword in investigation_keywords)
    
    def _get_violation_type(self, reason: str) -> str:
        """Get violation type from reason.
        
        Args:
            reason: Suspension reason
            
        Returns:
            Violation type
        """
        reason_lower = reason.lower()
        if "breach" in reason_lower:
            return "security_breach"
        elif "fraud" in reason_lower:
            return "fraud_attempt"
        elif "abuse" in reason_lower:
            return "service_abuse"
        elif "suspicious" in reason_lower:
            return "suspicious_activity"
        else:
            return "policy_violation"