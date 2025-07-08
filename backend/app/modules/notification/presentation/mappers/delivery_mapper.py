"""
Delivery Mapper

Maps between delivery DTOs and GraphQL types for notification delivery tracking.
"""

from typing import Any
from uuid import UUID

from ..schemas.types.delivery_type import DeliveryLogType


class DeliveryMapper:
    """Mapper for delivery-related data transformations."""

    @staticmethod
    def event_to_delivery_log(event: dict[str, Any]) -> DeliveryLogType:
        """Convert delivery event to GraphQL delivery log type."""
        # This is a simplified mapper - in practice you'd have more complex mapping
        return DeliveryLogType(
            id=UUID(event.get("delivery_id")),
            notification_id=UUID(event.get("notification_id")),
            recipient_id=UUID(event.get("recipient_id")),
            channel_id=UUID(event.get("channel_id")),
            channel_type=event.get("channel_type"),
            status=event.get("status"),
            final_status=event.get("final_status", False),
            recipient_address=event.get("recipient_address", ""),
            content_hash=event.get("content_hash"),
            queued_at=event.get("queued_at"),
            sent_at=event.get("sent_at"),
            delivered_at=event.get("delivered_at"),
            opened_at=event.get("opened_at"),
            clicked_at=event.get("clicked_at"),
            failed_at=event.get("failed_at"),
            delivery_duration=event.get("delivery_duration"),
            total_attempts=event.get("total_attempts", 1),
            provider_name=event.get("provider_name", ""),
            provider_message_id=event.get("provider_message_id"),
            provider_response=event.get("provider_response"),
            failure_reason=event.get("failure_reason"),
            error_message=event.get("error_message"),
            retry_count=event.get("retry_count", 0),
            next_retry_at=event.get("next_retry_at"),
            delivery_attempts=[],  # Would be mapped separately
            events=[],  # Would be mapped separately
            open_count=event.get("open_count", 0),
            click_count=event.get("click_count", 0),
            last_opened=event.get("last_opened"),
            last_clicked=event.get("last_clicked"),
            delivery_cost=event.get("delivery_cost"),
            cost_currency=event.get("cost_currency"),
            tags=event.get("tags", []),
            metadata=event.get("metadata"),
        )
