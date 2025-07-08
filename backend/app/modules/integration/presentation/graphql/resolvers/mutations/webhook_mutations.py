"""
Webhook Management Mutations for GraphQL API

This module provides comprehensive webhook management mutations including
webhook CRUD operations, testing, debugging, and configuration management.
"""

from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import DomainError, ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.webhook_inputs import (
    CreateWebhookEndpointInput,
    ResendWebhookInput,
    UpdateWebhookEndpointInput,
    WebhookRetryPolicyInput,
    WebhookSecurityConfigInput,
    WebhookTestInput,
)
from ...schemas.types.webhook_type import (
    WebhookDelivery,
    WebhookEndpoint,
    WebhookRetryPolicy,
    WebhookSecurityInfo,
)

logger = get_logger(__name__)


@strawberry.type
class WebhookMutations:
    """Webhook management GraphQL mutations."""

    @strawberry.field(description="Create a new webhook endpoint")
    @require_auth()
    @require_permission("webhook.endpoint.create")
    @audit_operation("webhook.create_endpoint")
    @rate_limit(requests=10, window=60)
    @track_metrics("create_webhook_endpoint")
    async def create_webhook_endpoint(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        input: CreateWebhookEndpointInput,
    ) -> WebhookEndpoint:
        """
        Create a new webhook endpoint for an integration.

        Args:
            integration_id: UUID of the integration
            input: Webhook endpoint creation parameters

        Returns:
            Created webhook endpoint details
        """
        try:
            # Validate URL
            if not input.url or not input.url.strip():
                raise ValidationError("Webhook URL is required")

            url = input.url.strip()
            if not url.startswith(("http://", "https://")):
                raise ValidationError("Webhook URL must start with http:// or https://")

            # Validate event types
            if not input.event_types or len(input.event_types) == 0:
                raise ValidationError("At least one event type must be specified")

            info.context["container"].resolve("WebhookService")
            command = info.context["container"].resolve("CreateWebhookEndpointCommand")

            # Execute creation
            result = await command.execute(
                integration_id=integration_id,
                url=url,
                event_types=input.event_types,
                description=input.description,
                secret=input.secret,
                headers=input.headers or {},
                is_active=input.is_active,
                created_by=info.context["user_id"],
            )

            logger.info(
                "Webhook endpoint created successfully",
                endpoint_id=str(result.endpoint_id),
                integration_id=str(integration_id),
                url=url,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.endpoint_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error creating webhook endpoint",
                integration_id=str(integration_id),
                url=input.url,
                error=str(e),
            )
            raise DomainError("Failed to create webhook endpoint")

    @strawberry.field(description="Update an existing webhook endpoint")
    @require_auth()
    @require_permission("webhook.endpoint.update")
    @audit_operation("webhook.update_endpoint")
    @rate_limit(requests=20, window=60)
    @track_metrics("update_webhook_endpoint")
    async def update_webhook_endpoint(
        self,
        info: strawberry.Info,
        endpoint_id: UUID,
        input: UpdateWebhookEndpointInput,
    ) -> WebhookEndpoint:
        """
        Update an existing webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint
            input: Webhook endpoint update parameters

        Returns:
            Updated webhook endpoint details
        """
        try:
            service = info.context["container"].resolve("WebhookService")
            command = info.context["container"].resolve("UpdateWebhookEndpointCommand")

            # Check if endpoint exists
            existing = await service.get_webhook_endpoint(endpoint_id)
            if not existing:
                raise ValidationError("Webhook endpoint not found")

            # Validate URL if provided
            if input.url:
                url = input.url.strip()
                if not url.startswith(("http://", "https://")):
                    raise ValidationError(
                        "Webhook URL must start with http:// or https://"
                    )

            # Execute update
            result = await command.execute(
                endpoint_id=endpoint_id,
                url=input.url,
                event_types=input.event_types,
                description=input.description,
                secret=input.secret,
                headers=input.headers,
                is_active=input.is_active,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Webhook endpoint updated successfully",
                endpoint_id=str(endpoint_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.endpoint_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error updating webhook endpoint",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to update webhook endpoint")

    @strawberry.field(description="Delete a webhook endpoint")
    @require_auth()
    @require_permission("webhook.endpoint.delete")
    @audit_operation("webhook.delete_endpoint")
    @rate_limit(requests=10, window=60)
    @track_metrics("delete_webhook_endpoint")
    async def delete_webhook_endpoint(
        self, info: strawberry.Info, endpoint_id: UUID, force: bool = False
    ) -> bool:
        """
        Delete a webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint
            force: Whether to force deletion even with pending deliveries

        Returns:
            True if deletion was successful
        """
        try:
            service = info.context["container"].resolve("WebhookService")
            command = info.context["container"].resolve("DeleteWebhookEndpointCommand")

            # Check if endpoint exists
            existing = await service.get_webhook_endpoint(endpoint_id)
            if not existing:
                raise ValidationError("Webhook endpoint not found")

            # Execute deletion
            await command.execute(
                endpoint_id=endpoint_id, force=force, deleted_by=info.context["user_id"]
            )

            logger.info(
                "Webhook endpoint deleted successfully",
                endpoint_id=str(endpoint_id),
                force=force,
                user_id=str(info.context["user_id"]),
            )

            return True

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error deleting webhook endpoint",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to delete webhook endpoint")

    @strawberry.field(description="Test webhook endpoint connectivity")
    @require_auth()
    @require_permission("webhook.test")
    @audit_operation("webhook.test_endpoint")
    @rate_limit(requests=10, window=60)
    @track_metrics("test_webhook_endpoint")
    async def test_webhook_endpoint(
        self,
        info: strawberry.Info,
        endpoint_id: UUID,
        input: WebhookTestInput | None = None,
    ) -> dict[str, Any]:
        """
        Test webhook endpoint with a sample payload.

        Args:
            endpoint_id: UUID of the webhook endpoint
            input: Optional test configuration

        Returns:
            Test results and diagnostics
        """
        try:
            service = info.context["container"].resolve("WebhookTestService")

            # Execute test
            result = await service.test_webhook_endpoint(
                endpoint_id=endpoint_id,
                test_config=input,
                tested_by=info.context["user_id"],
            )

            logger.info(
                "Webhook endpoint test completed",
                endpoint_id=str(endpoint_id),
                success=result.success,
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": result.success,
                "status_code": result.status_code,
                "response_time_ms": result.response_time_ms,
                "response_headers": result.response_headers,
                "response_body": result.response_body,
                "error_message": result.error_message,
                "validation_errors": result.validation_errors,
                "test_payload": result.test_payload,
                "tested_at": result.tested_at,
                "test_id": str(result.test_id),
            }

        except Exception as e:
            logger.exception(
                "Error testing webhook endpoint",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to test webhook endpoint")

    @strawberry.field(description="Resend a failed webhook delivery")
    @require_auth()
    @require_permission("webhook.delivery.resend")
    @audit_operation("webhook.resend_delivery")
    @rate_limit(requests=20, window=60)
    @track_metrics("resend_webhook_delivery")
    async def resend_webhook_delivery(
        self,
        info: strawberry.Info,
        delivery_id: UUID,
        input: ResendWebhookInput | None = None,
    ) -> WebhookDelivery:
        """
        Resend a failed webhook delivery.

        Args:
            delivery_id: UUID of the webhook delivery to resend
            input: Optional resend configuration

        Returns:
            New delivery attempt details
        """
        try:
            service = info.context["container"].resolve("WebhookDeliveryService")
            command = info.context["container"].resolve("ResendWebhookCommand")

            # Check if delivery exists
            existing = await service.get_webhook_delivery(delivery_id)
            if not existing:
                raise ValidationError("Webhook delivery not found")

            # Execute resend
            result = await command.execute(
                delivery_id=delivery_id,
                resend_config=input,
                resent_by=info.context["user_id"],
            )

            logger.info(
                "Webhook delivery resent successfully",
                original_delivery_id=str(delivery_id),
                new_delivery_id=str(result.delivery_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.delivery_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error resending webhook delivery",
                delivery_id=str(delivery_id),
                error=str(e),
            )
            raise DomainError("Failed to resend webhook delivery")

    @strawberry.field(description="Update webhook retry policy")
    @require_auth()
    @require_permission("webhook.retry.update")
    @audit_operation("webhook.update_retry_policy")
    @rate_limit(requests=15, window=60)
    @track_metrics("update_webhook_retry_policy")
    async def update_webhook_retry_policy(
        self, info: strawberry.Info, endpoint_id: UUID, policy: WebhookRetryPolicyInput
    ) -> WebhookRetryPolicy:
        """
        Update retry policy for a webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint
            policy: New retry policy configuration

        Returns:
            Updated retry policy details
        """
        try:
            # Validate policy parameters
            if policy.max_attempts and (
                policy.max_attempts < 1 or policy.max_attempts > 10
            ):
                raise ValidationError("Max attempts must be between 1 and 10")

            if policy.initial_delay_seconds and policy.initial_delay_seconds < 1:
                raise ValidationError("Initial delay must be at least 1 second")

            info.context["container"].resolve("WebhookRetryService")
            command = info.context["container"].resolve("UpdateRetryPolicyCommand")

            # Execute update
            result = await command.execute(
                endpoint_id=endpoint_id,
                policy=policy,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Webhook retry policy updated",
                endpoint_id=str(endpoint_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.retry_policy_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error updating retry policy",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to update retry policy")

    @strawberry.field(description="Update webhook security configuration")
    @require_auth()
    @require_permission("webhook.security.update")
    @audit_operation("webhook.update_security")
    @rate_limit(requests=10, window=60)
    @track_metrics("update_webhook_security")
    async def update_webhook_security(
        self,
        info: strawberry.Info,
        endpoint_id: UUID,
        security_config: WebhookSecurityConfigInput,
    ) -> WebhookSecurityInfo:
        """
        Update security configuration for a webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint
            security_config: New security configuration

        Returns:
            Updated security information
        """
        try:
            info.context["container"].resolve("WebhookSecurityService")
            command = info.context["container"].resolve("UpdateSecurityConfigCommand")

            # Execute update
            result = await command.execute(
                endpoint_id=endpoint_id,
                security_config=security_config,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Webhook security configuration updated",
                endpoint_id=str(endpoint_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.security_info_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error updating security configuration",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to update security configuration")

    @strawberry.field(description="Pause webhook deliveries")
    @require_auth()
    @require_permission("webhook.endpoint.pause")
    @audit_operation("webhook.pause_deliveries")
    @rate_limit(requests=20, window=60)
    @track_metrics("pause_webhook_deliveries")
    async def pause_webhook_deliveries(
        self,
        info: strawberry.Info,
        endpoint_id: UUID,
        pause_duration_minutes: int | None = None,
    ) -> WebhookEndpoint:
        """
        Pause webhook deliveries for an endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint
            pause_duration_minutes: Optional duration to pause (indefinite if not specified)

        Returns:
            Updated webhook endpoint details
        """
        try:
            if pause_duration_minutes and pause_duration_minutes < 1:
                raise ValidationError("Pause duration must be at least 1 minute")

            info.context["container"].resolve("WebhookService")
            command = info.context["container"].resolve("PauseWebhookCommand")

            # Execute pause
            result = await command.execute(
                endpoint_id=endpoint_id,
                pause_duration_minutes=pause_duration_minutes,
                paused_by=info.context["user_id"],
            )

            logger.info(
                "Webhook deliveries paused",
                endpoint_id=str(endpoint_id),
                duration_minutes=pause_duration_minutes,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.endpoint_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error pausing webhook deliveries",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to pause webhook deliveries")

    @strawberry.field(description="Resume webhook deliveries")
    @require_auth()
    @require_permission("webhook.endpoint.resume")
    @audit_operation("webhook.resume_deliveries")
    @rate_limit(requests=20, window=60)
    @track_metrics("resume_webhook_deliveries")
    async def resume_webhook_deliveries(
        self, info: strawberry.Info, endpoint_id: UUID
    ) -> WebhookEndpoint:
        """
        Resume webhook deliveries for a paused endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint

        Returns:
            Updated webhook endpoint details
        """
        try:
            info.context["container"].resolve("WebhookService")
            command = info.context["container"].resolve("ResumeWebhookCommand")

            # Execute resume
            result = await command.execute(
                endpoint_id=endpoint_id, resumed_by=info.context["user_id"]
            )

            logger.info(
                "Webhook deliveries resumed",
                endpoint_id=str(endpoint_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.endpoint_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error resuming webhook deliveries",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to resume webhook deliveries")

    @strawberry.field(description="Regenerate webhook secret")
    @require_auth()
    @require_permission("webhook.secret.regenerate")
    @audit_operation("webhook.regenerate_secret")
    @rate_limit(requests=5, window=60)
    @track_metrics("regenerate_webhook_secret")
    async def regenerate_webhook_secret(
        self, info: strawberry.Info, endpoint_id: UUID
    ) -> dict[str, Any]:
        """
        Regenerate the webhook secret for an endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint

        Returns:
            New secret information (partially redacted)
        """
        try:
            info.context["container"].resolve("WebhookSecurityService")
            command = info.context["container"].resolve("RegenerateSecretCommand")

            # Execute regeneration
            result = await command.execute(
                endpoint_id=endpoint_id, regenerated_by=info.context["user_id"]
            )

            logger.info(
                "Webhook secret regenerated",
                endpoint_id=str(endpoint_id),
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": True,
                "secret_preview": result.secret_preview,  # First few characters
                "secret_hint": result.secret_hint,
                "regenerated_at": result.regenerated_at,
                "previous_secret_expires_at": result.previous_secret_expires_at,
            }

        except Exception as e:
            logger.exception(
                "Error regenerating webhook secret",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to regenerate webhook secret")

    @strawberry.field(description="Bulk resend failed webhook deliveries")
    @require_auth()
    @require_permission("webhook.delivery.bulk_resend")
    @audit_operation("webhook.bulk_resend_deliveries")
    @rate_limit(requests=5, window=60)
    @track_metrics("bulk_resend_webhook_deliveries")
    async def bulk_resend_webhook_deliveries(
        self,
        info: strawberry.Info,
        endpoint_id: UUID,
        delivery_ids: list[UUID] | None = None,
        hours_back: int | None = None,
    ) -> dict[str, Any]:
        """
        Bulk resend failed webhook deliveries.

        Args:
            endpoint_id: UUID of the webhook endpoint
            delivery_ids: Optional specific delivery IDs to resend
            hours_back: Optional hours back to find failed deliveries

        Returns:
            Bulk resend results
        """
        try:
            if delivery_ids and len(delivery_ids) > 100:
                raise ValidationError("Maximum 100 deliveries can be resent at once")

            if hours_back and hours_back > 168:  # 1 week
                raise ValidationError("Cannot resend deliveries older than 1 week")

            info.context["container"].resolve("WebhookBulkService")
            command = info.context["container"].resolve("BulkResendCommand")

            # Execute bulk resend
            result = await command.execute(
                endpoint_id=endpoint_id,
                delivery_ids=delivery_ids,
                hours_back=hours_back or 24,
                resent_by=info.context["user_id"],
            )

            logger.info(
                "Bulk webhook deliveries resent",
                endpoint_id=str(endpoint_id),
                total_resent=result.total_resent,
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": True,
                "total_found": result.total_found,
                "total_resent": result.total_resent,
                "total_failed": result.total_failed,
                "resent_delivery_ids": [str(id) for id in result.resent_delivery_ids],
                "failed_delivery_ids": [str(id) for id in result.failed_delivery_ids],
                "errors": result.errors,
                "resent_at": result.resent_at,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error bulk resending webhook deliveries",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise DomainError("Failed to bulk resend webhook deliveries")


__all__ = ["WebhookMutations"]
