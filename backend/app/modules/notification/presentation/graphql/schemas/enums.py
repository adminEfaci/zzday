"""Notification GraphQL enums.

This module contains GraphQL enum definitions for the notification system,
providing type-safe enum values for various notification properties.
"""

import strawberry

from app.modules.notification.domain.enums import (
    BatchStatus,
    ChannelStatus,
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    RecipientStatus,
    ScheduleStatus,
    TemplateType,
    VariableType,
)


@strawberry.enum
class NotificationChannelEnum(NotificationChannel):
    """GraphQL enum for notification channels."""

    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"
    WEBHOOK = "webhook"


@strawberry.enum
class NotificationPriorityEnum(NotificationPriority):
    """GraphQL enum for notification priorities."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@strawberry.enum
class DeliveryStatusEnum(DeliveryStatus):
    """GraphQL enum for delivery status."""

    PENDING = "pending"
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"
    READ = "read"
    CANCELLED = "cancelled"


@strawberry.enum
class TemplateTypeEnum(TemplateType):
    """GraphQL enum for template types."""

    TRANSACTIONAL = "transactional"
    MARKETING = "marketing"
    SYSTEM = "system"
    ALERT = "alert"


@strawberry.enum
class BatchStatusEnum(BatchStatus):
    """GraphQL enum for batch status."""

    CREATED = "created"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


@strawberry.enum
class ChannelStatusEnum(ChannelStatus):
    """GraphQL enum for channel status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    CONFIGURING = "configuring"
    ERROR = "error"


@strawberry.enum
class RecipientStatusEnum(RecipientStatus):
    """GraphQL enum for recipient status."""

    ACTIVE = "active"
    UNSUBSCRIBED = "unsubscribed"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    SUPPRESSED = "suppressed"


@strawberry.enum
class ScheduleStatusEnum(ScheduleStatus):
    """GraphQL enum for schedule status."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


@strawberry.enum
class VariableTypeEnum(VariableType):
    """GraphQL enum for variable types."""

    STRING = "string"
    NUMBER = "number"
    DATE = "date"
    DATETIME = "datetime"
    BOOLEAN = "boolean"
    URL = "url"
    EMAIL = "email"
    CURRENCY = "currency"


@strawberry.enum
class CampaignStatusEnum:
    """GraphQL enum for campaign status."""

    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@strawberry.enum
class AnalyticsTimeframeEnum:
    """GraphQL enum for analytics timeframes."""

    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


@strawberry.enum
class SortDirectionEnum:
    """GraphQL enum for sort directions."""

    ASC = "asc"
    DESC = "desc"


@strawberry.enum
class NotificationSortFieldEnum:
    """GraphQL enum for notification sort fields."""

    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    SENT_AT = "sent_at"
    DELIVERED_AT = "delivered_at"
    PRIORITY = "priority"
    STATUS = "status"
    CHANNEL = "channel"


@strawberry.enum
class TemplateSortFieldEnum:
    """GraphQL enum for template sort fields."""

    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    NAME = "name"
    TYPE = "type"
    CHANNEL = "channel"
    USAGE_COUNT = "usage_count"


@strawberry.enum
class CampaignSortFieldEnum:
    """GraphQL enum for campaign sort fields."""

    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    SCHEDULED_AT = "scheduled_at"
    STARTED_AT = "started_at"
    COMPLETED_AT = "completed_at"
    NAME = "name"
    STATUS = "status"
    RECIPIENT_COUNT = "recipient_count"
