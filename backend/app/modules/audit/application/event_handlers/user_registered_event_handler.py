"""User registered event handler.

This module handles UserRegisteredEvent to create audit trails
for new user registrations and compliance tracking.
"""

from typing import Any

from ddd_implementation.shared_contracts import UserRegisteredEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class UserRegisteredEventHandler:
    """
    Event handler for user registration events.

    Creates audit trails when new users register in the system,
    supporting compliance and security monitoring requirements.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: UserRegisteredEvent) -> None:
        """
        Handle user registered event.

        Args:
            event: UserRegisteredEvent instance
        """
        logger.info(
            "Handling user registered event",
            user_id=event.user_id,
            email=event.email,
            event_id=event.metadata.event_id,
        )

        try:
            # Create audit trail for user registration
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action for registration
                action_type="user_registration",
                operation="create",
                description=f"User {event.email} registered successfully",
                resource_type="user",
                resource_id=str(event.user_id),
                resource_name=event.full_name or event.username,
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "tenant_id": str(event.tenant_id) if event.tenant_id else None,
                },
                outcome="success",
                severity="medium",
                category="authentication",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["user_lifecycle", "registration"],
                custom_fields={
                    "email": event.email,
                    "username": event.username,
                    "full_name": event.full_name,
                    "registration_method": "standard",
                    "tenant_id": str(event.tenant_id) if event.tenant_id else None,
                },
                compliance_tags=["user_management", "data_creation"],
            )

            # Create compliance audit trail if in regulated environment
            if event.tenant_id:
                await self._create_compliance_audit_trail(event)

            logger.info(
                "User registration audit trail created successfully",
                user_id=event.user_id,
                email=event.email,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for user registration",
                user_id=event.user_id,
                email=event.email,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting the registration process

    async def _create_compliance_audit_trail(self, event: Any) -> None:
        """
        Create additional compliance audit trail for regulated environments.

        Args:
            event: UserRegisteredEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="compliance_user_creation",
                operation="create",
                description=f"New user account created for compliance tracking: {event.email}",
                resource_type="user_account",
                resource_id=str(event.user_id),
                resource_name=f"Account for {event.email}",
                outcome="success",
                severity="medium",
                category="compliance",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["compliance", "user_creation", "gdpr", "data_subject"],
                custom_fields={
                    "compliance_event_type": "data_subject_creation",
                    "personal_data_collected": True,
                    "consent_required": True,
                    "data_protection_impact": "new_data_subject",
                },
                compliance_tags=[
                    "GDPR_Article_30",
                    "data_processing_record",
                    "personal_data",
                ],
            )

            logger.debug(
                "Compliance audit trail created for user registration",
                user_id=event.user_id,
            )

        except Exception as e:
            logger.warning(
                "Failed to create compliance audit trail",
                user_id=event.user_id,
                error=str(e),
            )


__all__ = ["UserRegisteredEventHandler"]
