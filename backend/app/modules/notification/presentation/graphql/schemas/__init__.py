"""Notification GraphQL schemas.

This module contains GraphQL type definitions, input types, enums, and unions
for the notification system.
"""

from .enums import (
    BatchStatusEnum,
    ChannelStatusEnum,
    DeliveryStatusEnum,
    NotificationChannelEnum,
    NotificationPriorityEnum,
    RecipientStatusEnum,
    ScheduleStatusEnum,
    TemplateTypeEnum,
    VariableTypeEnum,
)
from .inputs import (
    BulkSendInput,
    CampaignInput,
    ChannelConfigInput,
    DeliveryFilterInput,
    NotificationCreateInput,
    TemplateInput,
)
from .types import (
    AnalyticsType,
    CampaignType,
    ChannelType,
    DeliveryType,
    NotificationType,
    RecipientType,
    TemplateType,
)
from .unions import ChannelConfig, DeliveryResult, NotificationContent, TemplateContent

__all__ = [
    "AnalyticsType",
    "BatchStatusEnum",
    "BulkSendInput",
    "CampaignInput",
    "CampaignType",
    "ChannelConfig",
    "ChannelConfigInput",
    "ChannelStatusEnum",
    "ChannelType",
    "DeliveryFilterInput",
    "DeliveryResult",
    "DeliveryStatusEnum",
    "DeliveryType",
    # Enums
    "NotificationChannelEnum",
    # Unions
    "NotificationContent",
    # Inputs
    "NotificationCreateInput",
    "NotificationPriorityEnum",
    # Types
    "NotificationType",
    "RecipientStatusEnum",
    "RecipientType",
    "ScheduleStatusEnum",
    "TemplateContent",
    "TemplateInput",
    "TemplateType",
    "TemplateTypeEnum",
    "VariableTypeEnum",
]
