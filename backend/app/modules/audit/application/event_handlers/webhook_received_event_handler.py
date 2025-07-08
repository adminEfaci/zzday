"""Webhook received event handler.

This module handles WebhookReceivedEvent to create audit trails
for external webhook processing and security monitoring.
"""

from typing import Any

from ddd_implementation.shared_contracts import WebhookReceivedEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class WebhookReceivedEventHandler:
    """
    Event handler for webhook received events.

    Creates audit trails when webhooks are received from external systems,
    supporting integration security and compliance monitoring.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: WebhookReceivedEvent) -> None:
        """
        Handle webhook received event.

        Args:
            event: WebhookReceivedEvent instance
        """
        logger.info(
            "Handling webhook received event",
            webhook_id=event.webhook_id,
            source=event.source,
            endpoint=event.endpoint,
            method=event.method,
            signature_valid=event.signature_valid,
            event_id=event.metadata.event_id,
        )

        try:
            # Create audit trail for webhook reception
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action for webhook
                action_type="webhook_received",
                operation="receive",
                description=f"Webhook received from integration {event.integration_id}: {event.event_type}",
                resource_type="webhook",
                resource_id=str(event.webhook_id),
                resource_name=f"Webhook {event.webhook_id}",
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "integration_id": str(event.integration_id),
                    "webhook_event_type": event.event_type,
                    "signature_valid": event.signature_valid,
                    "payload_size": len(str(event.payload)) if event.payload else 0,
                },
                outcome="success" if event.signature_valid else "failure",
                severity=self._calculate_severity(
                    event.signature_valid, event.event_type
                ),
                category="integration",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["webhook", "external_integration", "api_endpoint"],
                custom_fields={
                    "webhook_id": str(event.webhook_id),
                    "integration_id": str(event.integration_id),
                    "event_type": event.event_type,
                    "signature_valid": event.signature_valid,
                    "payload_present": event.payload is not None,
                    "payload_size_bytes": len(str(event.payload))
                    if event.payload
                    else 0,
                    "webhook_source": self._determine_webhook_source(
                        event.integration_id
                    ),
                    "processing_status": "received",
                },
                compliance_tags=["external_data_processing", "integration_audit"],
            )

            # Create security audit trail for invalid signatures
            if not event.signature_valid:
                await self._create_security_audit_trail(event)

            # Create data processing audit trail for webhook payload
            if event.payload:
                await self._create_data_processing_audit_trail(event)

            # Create integration compliance audit trail
            await self._create_integration_compliance_audit_trail(event)

            logger.info(
                "Webhook received audit trail created successfully",
                webhook_id=event.webhook_id,
                integration_id=event.integration_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for webhook received",
                webhook_id=event.webhook_id,
                integration_id=event.integration_id,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting webhook processing

    def _calculate_severity(self, signature_valid: bool, event_type: str) -> str:
        """
        Calculate severity based on signature validity and event type.

        Args:
            signature_valid: Whether webhook signature is valid
            event_type: Type of webhook event

        Returns:
            Severity level
        """
        if not signature_valid:
            return "high"  # Security issue
        if self._is_sensitive_event_type(event_type):
            return "medium"
        return "low"

    def _is_sensitive_event_type(self, event_type: str) -> bool:
        """
        Check if webhook event type is sensitive.

        Args:
            event_type: Webhook event type

        Returns:
            True if sensitive event type
        """
        sensitive_types = [
            "user_data",
            "payment",
            "security",
            "auth",
            "admin",
            "delete",
            "modify",
            "access",
            "permission",
            "role",
        ]
        event_type_lower = event_type.lower()
        return any(sensitive in event_type_lower for sensitive in sensitive_types)

    def _determine_webhook_source(self, integration_id: str) -> str:
        """
        Determine webhook source from integration ID.

        Args:
            integration_id: Integration identifier

        Returns:
            Webhook source type
        """
        # This would typically look up the integration in a registry
        # For now, we'll make educated guesses based on common patterns
        integration_str = str(integration_id).lower()

        if "github" in integration_str:
            return "github"
        if "slack" in integration_str:
            return "slack"
        if "stripe" in integration_str:
            return "stripe"
        if "paypal" in integration_str:
            return "paypal"
        if "oauth" in integration_str:
            return "oauth_provider"
        return "external_system"

    async def _create_security_audit_trail(self, event: Any) -> None:
        """
        Create security audit trail for invalid webhook signatures.

        Args:
            event: WebhookReceivedEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="webhook_security_violation",
                operation="validate",
                description=f"Webhook with invalid signature received from integration {event.integration_id}",
                resource_type="security_event",
                resource_id=str(event.webhook_id),
                resource_name=f"Security violation for webhook {event.webhook_id}",
                outcome="failure",
                severity="high",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["security_violation", "invalid_signature", "webhook_security"],
                custom_fields={
                    "violation_type": "invalid_webhook_signature",
                    "source_integration": str(event.integration_id),
                    "webhook_event_type": event.event_type,
                    "potential_threat": "unauthorized_webhook",
                    "security_action_required": True,
                    "risk_level": "high",
                },
                compliance_tags=[
                    "security_monitoring",
                    "threat_detection",
                    "integration_security",
                ],
            )

            logger.warning(
                "Security audit trail created for invalid webhook signature",
                webhook_id=event.webhook_id,
                integration_id=event.integration_id,
            )

        except Exception as e:
            logger.exception(
                "Failed to create security audit trail for webhook",
                webhook_id=event.webhook_id,
                error=str(e),
            )

    async def _create_data_processing_audit_trail(self, event: Any) -> None:
        """
        Create data processing audit trail for webhook payload.

        Args:
            event: WebhookReceivedEvent instance
        """
        try:
            # Analyze payload for sensitive data indicators
            payload_str = str(event.payload)
            contains_personal_data = self._contains_personal_data(payload_str)

            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="external_data_processing",
                operation="process",
                description=f"External data received via webhook from {event.integration_id}",
                resource_type="external_data",
                resource_id=str(event.webhook_id),
                resource_name=f"Webhook data {event.webhook_id}",
                outcome="success",
                severity="medium" if contains_personal_data else "low",
                category="data_processing",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["external_data", "webhook_processing", "data_ingestion"],
                custom_fields={
                    "data_source": "external_webhook",
                    "integration_source": str(event.integration_id),
                    "data_size_bytes": len(payload_str),
                    "contains_personal_data": contains_personal_data,
                    "processing_purpose": "webhook_handling",
                    "data_retention_applied": True,
                },
                compliance_tags=[
                    "external_data_processing",
                    "data_ingestion",
                    "privacy_protection",
                ],
            )

            logger.debug(
                "Data processing audit trail created for webhook",
                webhook_id=event.webhook_id,
                contains_personal_data=contains_personal_data,
            )

        except Exception as e:
            logger.warning(
                "Failed to create data processing audit trail",
                webhook_id=event.webhook_id,
                error=str(e),
            )

    async def _create_integration_compliance_audit_trail(self, event: Any) -> None:
        """
        Create integration compliance audit trail.

        Args:
            event: WebhookReceivedEvent instance
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=None,  # System action
                action_type="integration_compliance_check",
                operation="validate",
                description=f"Integration compliance check for webhook from {event.integration_id}",
                resource_type="integration_compliance",
                resource_id=str(event.integration_id),
                resource_name=f"Compliance check for integration {event.integration_id}",
                outcome="success" if event.signature_valid else "warning",
                severity="low",
                category="compliance",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=[
                    "integration_compliance",
                    "webhook_validation",
                    "external_system_audit",
                ],
                custom_fields={
                    "compliance_check_type": "webhook_validation",
                    "integration_authorized": event.signature_valid,
                    "data_transfer_method": "webhook",
                    "security_controls_applied": event.signature_valid,
                    "compliance_status": "compliant"
                    if event.signature_valid
                    else "non_compliant",
                },
                compliance_tags=[
                    "integration_governance",
                    "external_system_compliance",
                    "data_transfer_audit",
                ],
            )

            logger.debug(
                "Integration compliance audit trail created",
                webhook_id=event.webhook_id,
                integration_id=event.integration_id,
            )

        except Exception as e:
            logger.warning(
                "Failed to create integration compliance audit trail",
                webhook_id=event.webhook_id,
                error=str(e),
            )

    def _contains_personal_data(self, payload_str: str) -> bool:
        """
        Check if payload contains personal data indicators.

        Args:
            payload_str: Payload as string

        Returns:
            True if likely contains personal data
        """
        personal_data_indicators = [
            "email",
            "phone",
            "address",
            "name",
            "ssn",
            "dob",
            "birthday",
            "user_id",
            "customer_id",
            "account",
        ]
        payload_lower = payload_str.lower()
        return any(indicator in payload_lower for indicator in personal_data_indicators)


__all__ = ["WebhookReceivedEventHandler"]
