"""
Webhook Management Queries for GraphQL API

This module provides comprehensive webhook management queries including
webhook debugging, logs, event tracking, and configuration management.
"""

from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.webhook_inputs import (
    PaginationInput,
    WebhookEventFilterInput,
    WebhookFilterInput,
    WebhookLogFilterInput,
    WebhookTestInput,
)
from ...schemas.types.webhook_type import (
    WebhookDelivery,
    WebhookEndpoint,
    WebhookEvent,
    WebhookLog,
    WebhookRetryPolicy,
    WebhookSecurityInfo,
    WebhookStatistics,
    WebhookValidationResult,
)

logger = get_logger(__name__)


@strawberry.type
class WebhookQueries:
    """Webhook management GraphQL queries."""

    @strawberry.field(description="Get webhook endpoint by ID")
    @require_auth()
    @require_permission("webhook.endpoint.read")
    @audit_operation("webhook.get_endpoint")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_webhook_endpoint")
    async def get_webhook_endpoint(
        self, info: strawberry.Info, endpoint_id: UUID
    ) -> WebhookEndpoint | None:
        """
        Get webhook endpoint details by ID.

        Args:
            endpoint_id: UUID of the webhook endpoint

        Returns:
            Webhook endpoint details or None if not found
        """
        try:
            service = info.context["container"].resolve("WebhookService")
            result = await service.get_webhook_endpoint(endpoint_id)

            if not result:
                logger.warning(
                    "Webhook endpoint not found", endpoint_id=str(endpoint_id)
                )
                return None

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.endpoint_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving webhook endpoint",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="List webhook endpoints for integration")
    @require_auth()
    @require_permission("webhook.endpoint.list")
    @audit_operation("webhook.list_endpoints")
    @rate_limit(requests=50, window=60)
    @track_metrics("list_webhook_endpoints")
    async def list_webhook_endpoints(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: WebhookFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[WebhookEndpoint]:
        """
        List webhook endpoints for an integration.

        Args:
            integration_id: UUID of the integration
            filters: Optional filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of webhook endpoints
        """
        try:
            service = info.context["container"].resolve("WebhookService")
            result = await service.list_webhook_endpoints(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=20),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return [
                mapper.endpoint_dto_to_graphql_type(endpoint) for endpoint in result
            ]

        except Exception as e:
            logger.exception(
                "Error listing webhook endpoints",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get webhook events history")
    @require_auth()
    @require_permission("webhook.events.read")
    @audit_operation("webhook.get_events")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_webhook_events")
    async def get_webhook_events(
        self,
        info: strawberry.Info,
        endpoint_id: UUID | None = None,
        integration_id: UUID | None = None,
        filters: WebhookEventFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[WebhookEvent]:
        """
        Get webhook events history with filtering.

        Args:
            endpoint_id: Optional specific webhook endpoint ID
            integration_id: Optional integration ID to filter by
            filters: Optional event filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of webhook events
        """
        try:
            if not endpoint_id and not integration_id:
                raise ValidationError(
                    "Either endpoint_id or integration_id must be provided"
                )

            service = info.context["container"].resolve("WebhookEventService")
            result = await service.get_webhook_events(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return [mapper.event_dto_to_graphql_type(event) for event in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving webhook events", error=str(e))
            raise

    @strawberry.field(description="Get webhook delivery details")
    @require_auth()
    @require_permission("webhook.delivery.read")
    @audit_operation("webhook.get_delivery")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_webhook_delivery")
    async def get_webhook_delivery(
        self, info: strawberry.Info, delivery_id: UUID
    ) -> WebhookDelivery | None:
        """
        Get detailed webhook delivery information.

        Args:
            delivery_id: UUID of the webhook delivery

        Returns:
            Webhook delivery details or None if not found
        """
        try:
            service = info.context["container"].resolve("WebhookDeliveryService")
            result = await service.get_webhook_delivery(delivery_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.delivery_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving webhook delivery",
                delivery_id=str(delivery_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get webhook delivery attempts")
    @require_auth()
    @require_permission("webhook.delivery.attempts")
    @audit_operation("webhook.get_delivery_attempts")
    @rate_limit(requests=60, window=60)
    @track_metrics("get_webhook_delivery_attempts")
    async def get_webhook_delivery_attempts(
        self, info: strawberry.Info, event_id: UUID, include_successful: bool = True
    ) -> list[WebhookDelivery]:
        """
        Get all delivery attempts for a webhook event.

        Args:
            event_id: UUID of the webhook event
            include_successful: Whether to include successful deliveries

        Returns:
            List of delivery attempts
        """
        try:
            service = info.context["container"].resolve("WebhookDeliveryService")
            result = await service.get_delivery_attempts(
                event_id=event_id, include_successful=include_successful
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return [
                mapper.delivery_dto_to_graphql_type(delivery) for delivery in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving delivery attempts",
                event_id=str(event_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get webhook logs")
    @require_auth()
    @require_permission("webhook.logs.read")
    @audit_operation("webhook.get_logs")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_webhook_logs")
    async def get_webhook_logs(
        self,
        info: strawberry.Info,
        endpoint_id: UUID | None = None,
        integration_id: UUID | None = None,
        filters: WebhookLogFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[WebhookLog]:
        """
        Get webhook logs with filtering and pagination.

        Args:
            endpoint_id: Optional webhook endpoint ID
            integration_id: Optional integration ID
            filters: Optional log filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of webhook logs
        """
        try:
            service = info.context["container"].resolve("WebhookLogService")
            result = await service.get_webhook_logs(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=100),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return [mapper.log_dto_to_graphql_type(log) for log in result]

        except Exception as e:
            logger.exception("Error retrieving webhook logs", error=str(e))
            raise

    @strawberry.field(description="Get webhook statistics")
    @require_auth()
    @require_permission("webhook.statistics.read")
    @audit_operation("webhook.get_statistics")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_webhook_statistics")
    async def get_webhook_statistics(
        self,
        info: strawberry.Info,
        endpoint_id: UUID | None = None,
        integration_id: UUID | None = None,
        time_range_hours: int = 24,
    ) -> WebhookStatistics:
        """
        Get webhook statistics for analysis.

        Args:
            endpoint_id: Optional specific webhook endpoint
            integration_id: Optional integration ID
            time_range_hours: Time range in hours for statistics

        Returns:
            Webhook statistics data
        """
        try:
            if time_range_hours > 168:  # 1 week
                raise ValidationError("Maximum time range is 168 hours (1 week)")

            if not endpoint_id and not integration_id:
                raise ValidationError(
                    "Either endpoint_id or integration_id must be provided"
                )

            service = info.context["container"].resolve("WebhookStatisticsService")
            result = await service.get_webhook_statistics(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                time_range_hours=time_range_hours,
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.statistics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving webhook statistics", error=str(e))
            raise

    @strawberry.field(description="Validate webhook endpoint configuration")
    @require_auth()
    @require_permission("webhook.validate")
    @audit_operation("webhook.validate_endpoint")
    @rate_limit(requests=20, window=60)
    @track_metrics("validate_webhook_endpoint")
    async def validate_webhook_endpoint(
        self,
        info: strawberry.Info,
        url: str,
        secret: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> WebhookValidationResult:
        """
        Validate webhook endpoint configuration.

        Args:
            url: Webhook endpoint URL
            secret: Optional webhook secret for validation
            headers: Optional custom headers

        Returns:
            Validation results
        """
        try:
            if not url or not url.strip():
                raise ValidationError("Webhook URL is required")

            # Basic URL validation
            if not url.startswith(("http://", "https://")):
                raise ValidationError("Webhook URL must start with http:// or https://")

            service = info.context["container"].resolve("WebhookValidationService")
            result = await service.validate_webhook_endpoint(
                url=url.strip(), secret=secret, headers=headers or {}
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.validation_result_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error validating webhook endpoint", url=url, error=str(e))
            raise

    @strawberry.field(description="Test webhook endpoint connectivity")
    @require_auth()
    @require_permission("webhook.test")
    @audit_operation("webhook.test_endpoint")
    @rate_limit(requests=10, window=60)
    @track_metrics("test_webhook_endpoint")
    async def test_webhook_endpoint(
        self, info: strawberry.Info, input: WebhookTestInput
    ) -> dict[str, Any]:
        """
        Test webhook endpoint with a sample payload.

        Args:
            input: Webhook test configuration

        Returns:
            Test results
        """
        try:
            service = info.context["container"].resolve("WebhookTestService")
            result = await service.test_webhook_endpoint(input)

            return {
                "success": result.success,
                "status_code": result.status_code,
                "response_time_ms": result.response_time_ms,
                "response_headers": result.response_headers,
                "response_body": result.response_body,
                "error_message": result.error_message,
                "validation_errors": result.validation_errors,
                "tested_at": result.tested_at,
            }

        except Exception as e:
            logger.exception("Error testing webhook endpoint", error=str(e))
            raise

    @strawberry.field(description="Get webhook retry policy")
    @require_auth()
    @require_permission("webhook.retry.read")
    @audit_operation("webhook.get_retry_policy")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_webhook_retry_policy")
    async def get_webhook_retry_policy(
        self, info: strawberry.Info, endpoint_id: UUID
    ) -> WebhookRetryPolicy | None:
        """
        Get retry policy for a webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint

        Returns:
            Retry policy details or None if not found
        """
        try:
            service = info.context["container"].resolve("WebhookRetryService")
            result = await service.get_retry_policy(endpoint_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.retry_policy_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving retry policy",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get webhook security information")
    @require_auth()
    @require_permission("webhook.security.read")
    @audit_operation("webhook.get_security_info")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_webhook_security_info")
    async def get_webhook_security_info(
        self, info: strawberry.Info, endpoint_id: UUID
    ) -> WebhookSecurityInfo | None:
        """
        Get security information for a webhook endpoint.

        Args:
            endpoint_id: UUID of the webhook endpoint

        Returns:
            Security information or None if not found
        """
        try:
            service = info.context["container"].resolve("WebhookSecurityService")
            result = await service.get_security_info(endpoint_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("WebhookMapper")
            return mapper.security_info_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving webhook security info",
                endpoint_id=str(endpoint_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get failed webhook deliveries")
    @require_auth()
    @require_permission("webhook.failures.read")
    @audit_operation("webhook.get_failed_deliveries")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_failed_webhook_deliveries")
    async def get_failed_webhook_deliveries(
        self,
        info: strawberry.Info,
        endpoint_id: UUID | None = None,
        integration_id: UUID | None = None,
        hours: int = 24,
        pagination: PaginationInput | None = None,
    ) -> list[WebhookDelivery]:
        """
        Get failed webhook deliveries for debugging.

        Args:
            endpoint_id: Optional webhook endpoint ID
            integration_id: Optional integration ID
            hours: Time range in hours to search
            pagination: Optional pagination parameters

        Returns:
            List of failed deliveries
        """
        try:
            if hours > 168:  # 1 week
                raise ValidationError("Maximum time range is 168 hours")

            service = info.context["container"].resolve("WebhookDeliveryService")
            result = await service.get_failed_deliveries(
                endpoint_id=endpoint_id,
                integration_id=integration_id,
                hours=hours,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("WebhookMapper")
            return [
                mapper.delivery_dto_to_graphql_type(delivery) for delivery in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving failed deliveries", error=str(e))
            raise

    @strawberry.field(description="Get webhook event types")
    @require_auth()
    @require_permission("webhook.event_types.read")
    @audit_operation("webhook.get_event_types")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_webhook_event_types")
    async def get_webhook_event_types(
        self, info: strawberry.Info, integration_id: UUID
    ) -> list[dict[str, Any]]:
        """
        Get available webhook event types for an integration.

        Args:
            integration_id: UUID of the integration

        Returns:
            List of available event types
        """
        try:
            service = info.context["container"].resolve("WebhookEventTypeService")
            result = await service.get_event_types(integration_id)

            return [
                {
                    "event_type": event_type.name,
                    "description": event_type.description,
                    "schema": event_type.schema,
                    "example_payload": event_type.example_payload,
                    "is_supported": event_type.is_supported,
                    "frequency": event_type.expected_frequency,
                    "categories": event_type.categories,
                }
                for event_type in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving event types",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise


__all__ = ["WebhookQueries"]
