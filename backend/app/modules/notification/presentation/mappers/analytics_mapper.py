"""
Analytics Mapper

Maps between analytics DTOs and GraphQL types for notification analytics.
"""

import json
from typing import Any

from ..schemas.types.notification_type import NotificationAnalyticsType


class AnalyticsMapper:
    """Mapper for analytics-related data transformations."""

    @staticmethod
    def notification_analytics_to_graphql(
        dto: dict[str, Any]
    ) -> NotificationAnalyticsType:
        """Convert notification analytics DTO to GraphQL type."""
        return NotificationAnalyticsType(
            total_sent=dto.get("total_sent", 0),
            total_delivered=dto.get("total_delivered", 0),
            total_failed=dto.get("total_failed", 0),
            total_bounced=dto.get("total_bounced", 0),
            total_clicked=dto.get("total_clicked", 0),
            total_opened=dto.get("total_opened", 0),
            delivery_rate=dto.get("delivery_rate", 0.0),
            open_rate=dto.get("open_rate", 0.0),
            click_rate=dto.get("click_rate", 0.0),
            bounce_rate=dto.get("bounce_rate", 0.0),
            avg_delivery_time=dto.get("avg_delivery_time"),
            channel_breakdown=json.dumps(dto.get("channel_breakdown", {})),
        )
