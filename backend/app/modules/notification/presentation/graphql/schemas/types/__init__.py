"""Notification GraphQL types.

This module contains GraphQL object type definitions for the notification system.
"""

from .analytics_type import (
    AnalyticsType,
    CampaignMetrics,
    ChannelMetrics,
    DeliveryMetrics,
    MetricsSummary,
    TemplateMetrics,
    TimeSeriesData,
)
from .campaign_type import CampaignConnection, CampaignEdge, CampaignStats, CampaignType
from .channel_type import ChannelHealth, ChannelSettings, ChannelType
from .delivery_type import BatchDelivery, DeliveryHistory, DeliveryReport, DeliveryType
from .notification_type import (
    NotificationConnection,
    NotificationEdge,
    NotificationType,
)
from .recipient_type import (
    RecipientConnection,
    RecipientEdge,
    RecipientPreferences,
    RecipientType,
)
from .template_type import (
    TemplateConnection,
    TemplateEdge,
    TemplateType,
    TemplateVariable,
)

__all__ = [
    # Analytics types
    "AnalyticsType",
    "BatchDelivery",
    "CampaignConnection",
    "CampaignEdge",
    "CampaignMetrics",
    "CampaignStats",
    # Campaign types
    "CampaignType",
    "ChannelHealth",
    "ChannelMetrics",
    "ChannelSettings",
    # Channel types
    "ChannelType",
    "DeliveryHistory",
    "DeliveryMetrics",
    "DeliveryReport",
    # Delivery types
    "DeliveryType",
    "MetricsSummary",
    "NotificationConnection",
    "NotificationEdge",
    # Notification types
    "NotificationType",
    "RecipientConnection",
    "RecipientEdge",
    "RecipientPreferences",
    # Recipient types
    "RecipientType",
    "TemplateConnection",
    "TemplateEdge",
    "TemplateMetrics",
    # Template types
    "TemplateType",
    "TemplateVariable",
    "TimeSeriesData",
]
