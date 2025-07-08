"""Notification GraphQL input types.

This module contains GraphQL input type definitions for the notification system.
"""

from .bulk_send_input import BulkRecipientInput, BulkSendInput, BulkTemplateInput
from .campaign_input import (
    CampaignABTestInput,
    CampaignCreateInput,
    CampaignScheduleInput,
    CampaignSegmentInput,
    CampaignUpdateInput,
)
from .channel_config_input import (
    ChannelConfigInput,
    ChannelSettingsInput,
    ChannelTestInput,
)
from .delivery_filter_input import (
    AnalyticsFilterInput,
    CampaignFilterInput,
    DeliveryFilterInput,
    NotificationFilterInput,
    RecipientFilterInput,
    TemplateFilterInput,
)
from .notification_create_input import (
    NotificationBatchInput,
    NotificationCreateInput,
    NotificationScheduleInput,
    NotificationUpdateInput,
)
from .template_input import (
    TemplateCreateInput,
    TemplateImportInput,
    TemplateTestInput,
    TemplateUpdateInput,
    TemplateVariableInput,
)

__all__ = [
    "AnalyticsFilterInput",
    "BulkRecipientInput",
    # Bulk operations
    "BulkSendInput",
    "BulkTemplateInput",
    "CampaignABTestInput",
    # Campaign inputs
    "CampaignCreateInput",
    "CampaignFilterInput",
    "CampaignScheduleInput",
    "CampaignSegmentInput",
    "CampaignUpdateInput",
    # Channel inputs
    "ChannelConfigInput",
    "ChannelSettingsInput",
    "ChannelTestInput",
    # Filters
    "DeliveryFilterInput",
    "NotificationBatchInput",
    # Notification inputs
    "NotificationCreateInput",
    "NotificationFilterInput",
    "NotificationScheduleInput",
    "NotificationUpdateInput",
    "RecipientFilterInput",
    # Template inputs
    "TemplateCreateInput",
    "TemplateFilterInput",
    "TemplateImportInput",
    "TemplateTestInput",
    "TemplateUpdateInput",
    "TemplateVariableInput",
]
