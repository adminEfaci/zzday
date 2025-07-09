"""Email adapter implementations."""

from .resend_adapter import ResendEmailAdapter
from .resend_client import ResendApiClient, ResendAPIError, ResendRateLimitError
from .resend_types import (
    BulkDeliveryResult,
    ResendAnalyticsResponse,
    ResendAttachment,
    ResendBatchRequest,
    ResendBatchResponse,
    ResendConfiguration,
    ResendDomainVerification,
    ResendEmailAddress,
    ResendEmailRequest,
    ResendEmailResponse,
    ResendEventTypes,
    ResendScheduleRequest,
    ResendScheduleResponse,
    ResendStatus,
    ResendSuppressionEntry,
    ResendTemplateRequest,
    ResendWebhookConfig,
    ResendWebhookEvent,
    ScheduleResult,
    SuppressionList,
    WebhookResult,
)
from .resend_webhooks import (
    ResendWebhookFilters,
    ResendWebhookManager,
    ResendWebhookProcessor,
    ResendWebhookValidator,
)

__all__ = [
    "BulkDeliveryResult",
    "ResendAPIError",
    "ResendAnalyticsResponse",
    # API client
    "ResendApiClient",
    "ResendAttachment",
    # Extended types
    "ResendBatchRequest",
    "ResendBatchResponse",
    # Configuration and results
    "ResendConfiguration",
    "ResendDomainVerification",
    # Main adapter
    "ResendEmailAdapter",
    "ResendEmailAddress",
    # Core types
    "ResendEmailRequest",
    "ResendEmailResponse",
    "ResendEventTypes",
    "ResendRateLimitError",
    "ResendScheduleRequest",
    "ResendScheduleResponse",
    "ResendStatus",
    "ResendSuppressionEntry",
    "ResendTemplateRequest",
    "ResendWebhookConfig",
    "ResendWebhookEvent",
    "ResendWebhookFilters",
    # Webhook handling
    "ResendWebhookManager",
    "ResendWebhookProcessor",
    "ResendWebhookValidator",
    "ScheduleResult",
    "SuppressionList",
    "WebhookResult",
]
