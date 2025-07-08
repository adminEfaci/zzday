"""
Notification Subscription Resolvers

GraphQL subscription resolvers for real-time notification delivery status,
analytics updates, and system events.
"""

from collections.abc import AsyncGenerator
from uuid import UUID

import strawberry

from app.core.logging import get_logger
from app.modules.identity.presentation.graphql.decorators import (
    require_auth,
    subscription_auth,
)

logger = get_logger(__name__)

from ...schemas.types.delivery_type import DeliveryLogType
from ...schemas.types.notification_type import NotificationType


@strawberry.type
class NotificationSubscriptions:
    """Real-time notification subscriptions."""

    @strawberry.subscription(
        description="Subscribe to notification delivery status updates"
    )
    @require_auth()
    @subscription_auth("notifications:subscribe")
    async def notification_delivery_status(
        self, info: strawberry.Info, notification_id: UUID
    ) -> AsyncGenerator[DeliveryLogType, None]:
        """Subscribe to delivery status updates for a specific notification."""
        try:
            # Get the event bus from context
            event_bus = info.context.get("event_bus")
            if not event_bus:
                logger.error("Event bus not available in context")
                return

            # Subscribe to delivery events for this notification
            async for event in event_bus.subscribe(
                f"notification.delivery.{notification_id}"
            ):
                if event.get("type") == "delivery_status_changed":
                    # Convert event data to GraphQL type
                    from ...mappers.delivery_mapper import DeliveryMapper

                    delivery_log = DeliveryMapper.event_to_delivery_log(event)
                    yield delivery_log

        except Exception as e:
            logger.exception(f"Error in notification delivery subscription: {e}")

    @strawberry.subscription(description="Subscribe to notification status changes")
    @require_auth()
    @subscription_auth("notifications:subscribe")
    async def notification_status_updates(
        self, info: strawberry.Info, notification_id: UUID | None = None
    ) -> AsyncGenerator[NotificationType, None]:
        """Subscribe to notification status changes."""
        try:
            event_bus = info.context.get("event_bus")
            if not event_bus:
                logger.error("Event bus not available in context")
                return

            # Subscribe to notification events
            topic = (
                f"notification.status.{notification_id}"
                if notification_id
                else "notification.status.*"
            )

            async for event in event_bus.subscribe(topic):
                if event.get("type") == "notification_status_changed":
                    # Convert event data to GraphQL type
                    from ...mappers.notification_mapper import NotificationMapper

                    notification = NotificationMapper.event_to_notification(event)
                    yield notification

        except Exception as e:
            logger.exception(f"Error in notification status subscription: {e}")

    @strawberry.subscription(description="Subscribe to campaign progress updates")
    @require_auth()
    @subscription_auth("campaigns:subscribe")
    async def campaign_progress_updates(
        self, info: strawberry.Info, campaign_id: UUID
    ) -> AsyncGenerator[str, None]:  # JSON string with progress data
        """Subscribe to campaign progress updates."""
        try:
            event_bus = info.context.get("event_bus")
            if not event_bus:
                logger.error("Event bus not available in context")
                return

            async for event in event_bus.subscribe(f"campaign.progress.{campaign_id}"):
                if event.get("type") == "campaign_progress_updated":
                    # Return progress data as JSON string
                    import json

                    progress_data = {
                        "campaign_id": str(campaign_id),
                        "progress_percentage": event.get("progress_percentage", 0.0),
                        "notifications_sent": event.get("notifications_sent", 0),
                        "notifications_delivered": event.get(
                            "notifications_delivered", 0
                        ),
                        "notifications_failed": event.get("notifications_failed", 0),
                        "updated_at": event.get("updated_at").isoformat()
                        if event.get("updated_at")
                        else None,
                    }
                    yield json.dumps(progress_data)

        except Exception as e:
            logger.exception(f"Error in campaign progress subscription: {e}")

    @strawberry.subscription(description="Subscribe to channel health updates")
    @require_auth()
    @subscription_auth("channels:subscribe")
    async def channel_health_updates(
        self, info: strawberry.Info, channel_id: UUID | None = None
    ) -> AsyncGenerator[str, None]:  # JSON string with health data
        """Subscribe to notification channel health updates."""
        try:
            event_bus = info.context.get("event_bus")
            if not event_bus:
                logger.error("Event bus not available in context")
                return

            topic = f"channel.health.{channel_id}" if channel_id else "channel.health.*"

            async for event in event_bus.subscribe(topic):
                if event.get("type") == "channel_health_changed":
                    # Return health data as JSON string
                    import json

                    health_data = {
                        "channel_id": event.get("channel_id"),
                        "status": event.get("status"),
                        "success_rate": event.get("success_rate", 0.0),
                        "error_count": event.get("error_count", 0),
                        "last_error": event.get("last_error"),
                        "updated_at": event.get("updated_at").isoformat()
                        if event.get("updated_at")
                        else None,
                    }
                    yield json.dumps(health_data)

        except Exception as e:
            logger.exception(f"Error in channel health subscription: {e}")

    @strawberry.subscription(description="Subscribe to system notification events")
    @require_auth()
    @subscription_auth("system:subscribe")
    async def system_notification_events(
        self, info: strawberry.Info
    ) -> AsyncGenerator[str, None]:  # JSON string with event data
        """Subscribe to system-wide notification events for monitoring."""
        try:
            auth_context = info.context.get("auth_context")

            # Only admins can subscribe to system events
            if not auth_context or not getattr(auth_context, "is_admin", False):
                logger.warning("Non-admin user attempted to subscribe to system events")
                return

            event_bus = info.context.get("event_bus")
            if not event_bus:
                logger.error("Event bus not available in context")
                return

            async for event in event_bus.subscribe("system.notifications.*"):
                # Return relevant system events
                if event.get("type") in [
                    "notification_quota_exceeded",
                    "channel_failure_threshold_reached",
                    "bulk_operation_completed",
                    "system_maintenance_scheduled",
                ]:
                    import json

                    system_event = {
                        "event_type": event.get("type"),
                        "severity": event.get("severity", "info"),
                        "message": event.get("message"),
                        "details": event.get("details"),
                        "timestamp": event.get("timestamp").isoformat()
                        if event.get("timestamp")
                        else None,
                    }
                    yield json.dumps(system_event)

        except Exception as e:
            logger.exception(f"Error in system notification subscription: {e}")
