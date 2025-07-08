"""
Email Service Queries for GraphQL API

This module provides comprehensive email service management queries including
email analytics, delivery tracking, template management, and bounce handling.
"""

from datetime import datetime, timedelta
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

from ...schemas.inputs.email_inputs import (
    DateRangeInput,
    EmailAnalyticsInput,
    EmailCampaignFilterInput,
    EmailFilterInput,
    EmailTemplateFilterInput,
    PaginationInput,
)
from ...schemas.types.email_service_type import (
    EmailAnalytics,
    EmailBounce,
    EmailCampaign,
    EmailComplaint,
    EmailDelivery,
    EmailProvider,
    EmailSendQuota,
    EmailStatistics,
    EmailSuppressionList,
    EmailTemplate,
)

logger = get_logger(__name__)


@strawberry.type
class EmailQueries:
    """Email service management GraphQL queries."""

    @strawberry.field(description="Get available email providers")
    @require_auth()
    @require_permission("email.providers.read")
    @audit_operation("email.get_providers")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_email_providers")
    async def get_email_providers(
        self, info: strawberry.Info, include_inactive: bool = False
    ) -> list[EmailProvider]:
        """
        Get list of available email service providers.

        Args:
            include_inactive: Whether to include inactive providers

        Returns:
            List of email providers with capabilities
        """
        try:
            service = info.context["container"].resolve("EmailProviderService")
            result = await service.get_providers(include_inactive=include_inactive)

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.provider_dto_to_graphql_type(provider) for provider in result
            ]

        except Exception as e:
            logger.exception("Error retrieving email providers", error=str(e))
            raise

    @strawberry.field(description="Get email delivery statistics")
    @require_auth()
    @require_permission("email.statistics.read")
    @audit_operation("email.get_statistics")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_email_statistics")
    async def get_email_statistics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        date_range: DateRangeInput | None = None,
    ) -> EmailStatistics:
        """
        Get comprehensive email delivery statistics.

        Args:
            integration_id: UUID of the email integration
            date_range: Optional date range for statistics

        Returns:
            Email statistics data
        """
        try:
            # Default to last 30 days if no range provided
            if not date_range:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=30)
                date_range = DateRangeInput(start_date=start_date, end_date=end_date)

            # Validate date range
            if date_range.end_date <= date_range.start_date:
                raise ValidationError("End date must be after start date")

            days_diff = (date_range.end_date - date_range.start_date).days
            if days_diff > 90:
                raise ValidationError("Date range cannot exceed 90 days")

            service = info.context["container"].resolve("EmailStatisticsService")
            result = await service.get_email_statistics(
                integration_id=integration_id, date_range=date_range
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return mapper.statistics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving email statistics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email delivery details")
    @require_auth()
    @require_permission("email.delivery.read")
    @audit_operation("email.get_delivery")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_email_delivery")
    async def get_email_delivery(
        self, info: strawberry.Info, delivery_id: UUID
    ) -> EmailDelivery | None:
        """
        Get detailed email delivery information.

        Args:
            delivery_id: UUID of the email delivery

        Returns:
            Email delivery details or None if not found
        """
        try:
            service = info.context["container"].resolve("EmailDeliveryService")
            result = await service.get_email_delivery(delivery_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("EmailMapper")
            return mapper.delivery_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving email delivery",
                delivery_id=str(delivery_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email deliveries with filtering")
    @require_auth()
    @require_permission("email.deliveries.read")
    @audit_operation("email.get_deliveries")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_email_deliveries")
    async def get_email_deliveries(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: EmailFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailDelivery]:
        """
        Get email deliveries with filtering and pagination.

        Args:
            integration_id: UUID of the email integration
            filters: Optional filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of email deliveries
        """
        try:
            service = info.context["container"].resolve("EmailDeliveryService")
            result = await service.get_email_deliveries(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.delivery_dto_to_graphql_type(delivery) for delivery in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving email deliveries",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email templates")
    @require_auth()
    @require_permission("email.templates.read")
    @audit_operation("email.get_templates")
    @rate_limit(requests=60, window=60)
    @track_metrics("get_email_templates")
    async def get_email_templates(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: EmailTemplateFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailTemplate]:
        """
        Get email templates from provider.

        Args:
            integration_id: UUID of the email integration
            filters: Optional template filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of email templates
        """
        try:
            service = info.context["container"].resolve("EmailTemplateService")
            result = await service.get_email_templates(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.template_dto_to_graphql_type(template) for template in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving email templates",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email template by ID")
    @require_auth()
    @require_permission("email.template.read")
    @audit_operation("email.get_template")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_email_template")
    async def get_email_template(
        self, info: strawberry.Info, integration_id: UUID, template_id: str
    ) -> EmailTemplate | None:
        """
        Get specific email template by ID.

        Args:
            integration_id: UUID of the email integration
            template_id: External template identifier

        Returns:
            Email template details or None if not found
        """
        try:
            service = info.context["container"].resolve("EmailTemplateService")
            result = await service.get_email_template(
                integration_id=integration_id, template_id=template_id
            )

            if not result:
                return None

            mapper = info.context["container"].resolve("EmailMapper")
            return mapper.template_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving email template",
                integration_id=str(integration_id),
                template_id=template_id,
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email campaigns")
    @require_auth()
    @require_permission("email.campaigns.read")
    @audit_operation("email.get_campaigns")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_email_campaigns")
    async def get_email_campaigns(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: EmailCampaignFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailCampaign]:
        """
        Get email campaigns from provider.

        Args:
            integration_id: UUID of the email integration
            filters: Optional campaign filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of email campaigns
        """
        try:
            service = info.context["container"].resolve("EmailCampaignService")
            result = await service.get_email_campaigns(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=30),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.campaign_dto_to_graphql_type(campaign) for campaign in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving email campaigns",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email analytics")
    @require_auth()
    @require_permission("email.analytics.read")
    @audit_operation("email.get_analytics")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_email_analytics")
    async def get_email_analytics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        analytics_input: EmailAnalyticsInput,
    ) -> EmailAnalytics:
        """
        Get detailed email analytics and metrics.

        Args:
            integration_id: UUID of the email integration
            analytics_input: Analytics query parameters

        Returns:
            Email analytics data
        """
        try:
            # Validate date range
            if analytics_input.end_date <= analytics_input.start_date:
                raise ValidationError("End date must be after start date")

            days_diff = (analytics_input.end_date - analytics_input.start_date).days
            if days_diff > 365:
                raise ValidationError("Date range cannot exceed 365 days")

            service = info.context["container"].resolve("EmailAnalyticsService")
            result = await service.get_email_analytics(
                integration_id=integration_id, analytics_input=analytics_input
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return mapper.analytics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving email analytics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email bounces")
    @require_auth()
    @require_permission("email.bounces.read")
    @audit_operation("email.get_bounces")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_email_bounces")
    async def get_email_bounces(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        date_range: DateRangeInput | None = None,
        bounce_types: list[str] | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailBounce]:
        """
        Get email bounce records.

        Args:
            integration_id: UUID of the email integration
            date_range: Optional date range filter
            bounce_types: Optional bounce type filters
            pagination: Optional pagination parameters

        Returns:
            List of email bounces
        """
        try:
            service = info.context["container"].resolve("EmailBounceService")
            result = await service.get_email_bounces(
                integration_id=integration_id,
                date_range=date_range,
                bounce_types=bounce_types,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [mapper.bounce_dto_to_graphql_type(bounce) for bounce in result]

        except Exception as e:
            logger.exception(
                "Error retrieving email bounces",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email complaints")
    @require_auth()
    @require_permission("email.complaints.read")
    @audit_operation("email.get_complaints")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_email_complaints")
    async def get_email_complaints(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        date_range: DateRangeInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailComplaint]:
        """
        Get email complaint records.

        Args:
            integration_id: UUID of the email integration
            date_range: Optional date range filter
            pagination: Optional pagination parameters

        Returns:
            List of email complaints
        """
        try:
            service = info.context["container"].resolve("EmailComplaintService")
            result = await service.get_email_complaints(
                integration_id=integration_id,
                date_range=date_range,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.complaint_dto_to_graphql_type(complaint) for complaint in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving email complaints",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email send quota information")
    @require_auth()
    @require_permission("email.quota.read")
    @audit_operation("email.get_send_quota")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_email_send_quota")
    async def get_email_send_quota(
        self, info: strawberry.Info, integration_id: UUID
    ) -> EmailSendQuota | None:
        """
        Get email sending quota and limits.

        Args:
            integration_id: UUID of the email integration

        Returns:
            Email send quota information or None if not available
        """
        try:
            service = info.context["container"].resolve("EmailQuotaService")
            result = await service.get_send_quota(integration_id)

            if not result:
                return None

            mapper = info.context["container"].resolve("EmailMapper")
            return mapper.send_quota_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving email send quota",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email suppression list")
    @require_auth()
    @require_permission("email.suppression.read")
    @audit_operation("email.get_suppression_list")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_email_suppression_list")
    async def get_email_suppression_list(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        suppression_types: list[str] | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailSuppressionList]:
        """
        Get email suppression list entries.

        Args:
            integration_id: UUID of the email integration
            suppression_types: Optional suppression type filters
            pagination: Optional pagination parameters

        Returns:
            List of suppression list entries
        """
        try:
            service = info.context["container"].resolve("EmailSuppressionService")
            result = await service.get_suppression_list(
                integration_id=integration_id,
                suppression_types=suppression_types,
                pagination=pagination or PaginationInput(page=1, page_size=100),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.suppression_list_dto_to_graphql_type(entry) for entry in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving email suppression list",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Search email deliveries")
    @require_auth()
    @require_permission("email.search")
    @audit_operation("email.search_deliveries")
    @rate_limit(requests=20, window=60)
    @track_metrics("search_email_deliveries")
    async def search_email_deliveries(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        query: str,
        filters: EmailFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[EmailDelivery]:
        """
        Search email deliveries by recipient, subject, or message ID.

        Args:
            integration_id: UUID of the email integration
            query: Search query string
            filters: Optional additional filters
            pagination: Optional pagination parameters

        Returns:
            List of matching email deliveries
        """
        try:
            if not query or len(query.strip()) < 3:
                raise ValidationError("Search query must be at least 3 characters")

            service = info.context["container"].resolve("EmailSearchService")
            result = await service.search_email_deliveries(
                integration_id=integration_id,
                query=query.strip(),
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("EmailMapper")
            return [
                mapper.delivery_dto_to_graphql_type(delivery) for delivery in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error searching email deliveries",
                integration_id=str(integration_id),
                query=query,
                error=str(e),
            )
            raise

    @strawberry.field(description="Get email reputation metrics")
    @require_auth()
    @require_permission("email.reputation.read")
    @audit_operation("email.get_reputation")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_email_reputation")
    async def get_email_reputation(
        self, info: strawberry.Info, integration_id: UUID
    ) -> dict[str, Any]:
        """
        Get email sender reputation metrics.

        Args:
            integration_id: UUID of the email integration

        Returns:
            Email reputation data
        """
        try:
            service = info.context["container"].resolve("EmailReputationService")
            result = await service.get_email_reputation(integration_id)

            return {
                "integration_id": str(integration_id),
                "reputation_score": result.reputation_score,
                "deliverability_rate": result.deliverability_rate,
                "bounce_rate": result.bounce_rate,
                "complaint_rate": result.complaint_rate,
                "spam_rate": result.spam_rate,
                "domain_reputation": {
                    "domain": result.domain_reputation.domain,
                    "status": result.domain_reputation.status,
                    "reputation_score": result.domain_reputation.reputation_score,
                    "verification_status": result.domain_reputation.verification_status,
                },
                "ip_reputation": [
                    {
                        "ip_address": ip.ip_address,
                        "reputation_score": ip.reputation_score,
                        "status": ip.status,
                        "blocklist_status": ip.blocklist_status,
                    }
                    for ip in result.ip_reputation
                ],
                "recommendations": result.recommendations,
                "last_updated": result.last_updated,
            }

        except Exception as e:
            logger.exception(
                "Error retrieving email reputation",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise


__all__ = ["EmailQueries"]
