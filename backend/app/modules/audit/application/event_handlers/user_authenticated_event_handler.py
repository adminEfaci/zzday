"""User authenticated event handler.

This module handles UserAuthenticatedEvent to create audit trails
for user authentication events and security monitoring.
"""

from ddd_implementation.shared_contracts import UserAuthenticatedEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class UserAuthenticatedEventHandler:
    """
    Event handler for user authentication events.

    Creates audit trails when users successfully authenticate,
    supporting security monitoring and compliance requirements.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: UserAuthenticatedEvent) -> None:
        """
        Handle user authenticated event.

        Args:
            event: UserAuthenticatedEvent instance
        """
        logger.info(
            "Handling user authenticated event",
            user_id=event.user_id,
            session_id=event.session_id,
            ip_address=event.ip_address,
            mfa_used=event.mfa_used,
            event_id=event.metadata.event_id,
        )

        try:
            # Create audit trail for user authentication
            await self.audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type="user_authentication",
                operation="authenticate",
                description=f"User successfully authenticated with session {event.session_id}",
                resource_type="user_session",
                resource_id=str(event.session_id),
                resource_name=f"Session for user {event.user_id}",
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "mfa_used": event.mfa_used,
                    "session_id": str(event.session_id),
                },
                outcome="success",
                severity="low" if event.mfa_used else "medium",
                category="authentication",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["user_authentication", "session_creation", "login"],
                custom_fields={
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "mfa_used": event.mfa_used,
                    "session_id": str(event.session_id),
                    "authentication_method": "mfa" if event.mfa_used else "password",
                    "risk_level": "low" if event.mfa_used else "medium",
                },
                compliance_tags=["access_control", "authentication_logging"],
            )

            # Create additional security audit trail for MFA authentication
            if event.mfa_used:
                await self._create_mfa_audit_trail(event)

            # Create risk assessment audit trail for non-MFA authentication
            if not event.mfa_used:
                await self._create_risk_assessment_audit_trail(event)

            logger.info(
                "User authentication audit trail created successfully",
                user_id=event.user_id,
                session_id=event.session_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for user authentication",
                user_id=event.user_id,
                session_id=event.session_id,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting the authentication process

    async def _create_mfa_audit_trail(self, event: UserAuthenticatedEvent) -> None:
        """
        Create additional audit trail for MFA authentication.

        Args:
            event: UserAuthenticatedEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type="mfa_authentication",
                operation="authenticate",
                description="User completed multi-factor authentication successfully",
                resource_type="security_factor",
                resource_id=str(event.user_id),
                resource_name=f"MFA for user {event.user_id}",
                outcome="success",
                severity="low",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["mfa", "security", "strong_authentication"],
                custom_fields={
                    "authentication_strength": "strong",
                    "security_enhancement": "mfa_enabled",
                    "compliance_level": "enhanced",
                },
                compliance_tags=[
                    "strong_authentication",
                    "security_controls",
                    "access_security",
                ],
            )

            logger.debug(
                "MFA audit trail created for user authentication", user_id=event.user_id
            )

        except Exception as e:
            logger.warning(
                "Failed to create MFA audit trail", user_id=event.user_id, error=str(e)
            )

    async def _create_risk_assessment_audit_trail(
        self, event: UserAuthenticatedEvent
    ) -> None:
        """
        Create risk assessment audit trail for non-MFA authentication.

        Args:
            event: UserAuthenticatedEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=event.user_id,
                action_type="authentication_risk_assessment",
                operation="assess",
                description="Authentication without MFA detected - medium risk login",
                resource_type="security_assessment",
                resource_id=str(event.user_id),
                resource_name=f"Risk assessment for user {event.user_id}",
                outcome="success",
                severity="medium",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=[
                    "risk_assessment",
                    "security_monitoring",
                    "authentication_weakness",
                ],
                custom_fields={
                    "risk_factor": "no_mfa",
                    "authentication_strength": "basic",
                    "security_recommendation": "enable_mfa",
                    "risk_level": "medium",
                },
                compliance_tags=[
                    "security_monitoring",
                    "risk_management",
                    "authentication_controls",
                ],
            )

            logger.debug(
                "Risk assessment audit trail created for non-MFA authentication",
                user_id=event.user_id,
            )

        except Exception as e:
            logger.warning(
                "Failed to create risk assessment audit trail",
                user_id=event.user_id,
                error=str(e),
            )


__all__ = ["UserAuthenticatedEventHandler"]
