"""
Notification Mutation Resolvers

GraphQL mutation resolvers for notification operations including creation,
updates, sending, and bulk operations.
"""

from uuid import UUID

import strawberry

from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger
from app.modules.identity.presentation.graphql.decorators import (
    audit_log,
    batch_size_limit,
    rate_limit,
    require_auth,
    require_permission,
    track_metrics,
)

logger = get_logger(__name__)

from ...schemas.inputs.notification_inputs import (
    BulkNotificationCreateInput,
    NotificationCancelInput,
    NotificationCreateInput,
    NotificationPreferencesInput,
    NotificationResendInput,
    NotificationUpdateInput,
)
from ...schemas.types.notification_type import NotificationBatchType, NotificationType


@strawberry.type
class NotificationMutations:
    """Notification mutation resolvers with comprehensive operations."""

    @strawberry.field(description="Create a new notification")
    @require_auth()
    @require_permission("notifications:create")
    @rate_limit(key="notification_create", max_attempts=50, window=60)
    @audit_log("notification.create")
    @track_metrics("notification_create")
    async def create_notification(
        self, info: strawberry.Info, input: NotificationCreateInput
    ) -> NotificationType:
        """Create a new notification."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve("NotificationService")

            # Convert GraphQL input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            notification_dto = NotificationMapper.create_input_to_dto(input)
            notification_dto["created_by"] = auth_context.user_id

            # Create notification
            created_dto = await service.create_notification(notification_dto)

            return NotificationMapper.to_graphql_type(created_dto)

        except Exception as e:
            logger.exception(f"Error creating notification: {e}")
            raise ValidationError("Failed to create notification")

    @strawberry.field(description="Update an existing notification")
    @require_auth()
    @require_permission("notifications:update")
    @rate_limit(key="notification_update", max_attempts=30, window=60)
    @audit_log("notification.update")
    @track_metrics("notification_update")
    async def update_notification(
        self, info: strawberry.Info, id: UUID, input: NotificationUpdateInput
    ) -> NotificationType:
        """Update an existing notification."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve("NotificationService")

            # Check if notification exists and user has permission
            existing = await service.get_notification_by_id(id)
            if not existing:
                raise ValidationError("Notification not found")

            # Convert input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            update_dto = NotificationMapper.update_input_to_dto(input)

            # Update notification
            updated_dto = await service.update_notification(id, update_dto)

            return NotificationMapper.to_graphql_type(updated_dto)

        except Exception as e:
            logger.exception(f"Error updating notification {id}: {e}")
            raise ValidationError("Failed to update notification")

    @strawberry.field(description="Send a notification immediately")
    @require_auth()
    @require_permission("notifications:send")
    @rate_limit(key="notification_send", max_attempts=20, window=60)
    @audit_log("notification.send")
    @track_metrics("notification_send")
    async def send_notification(
        self, info: strawberry.Info, id: UUID
    ) -> NotificationType:
        """Send a notification immediately."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Send notification
            result_dto = await service.send_notification(id)

            from ...mappers.notification_mapper import NotificationMapper

            return NotificationMapper.to_graphql_type(result_dto)

        except Exception as e:
            logger.exception(f"Error sending notification {id}: {e}")
            raise ValidationError("Failed to send notification")

    @strawberry.field(description="Create notifications in bulk")
    @require_auth()
    @require_permission("notifications:bulk_create")
    @rate_limit(key="bulk_notification_create", max_attempts=10, window=60)
    @audit_log("notification.bulk_create")
    @track_metrics("bulk_notification_create")
    @batch_size_limit(max_size=100)
    async def create_bulk_notifications(
        self, info: strawberry.Info, input: BulkNotificationCreateInput
    ) -> NotificationBatchType:
        """Create multiple notifications in bulk."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve("NotificationBatchService")

            # Convert input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            bulk_dto = NotificationMapper.bulk_create_input_to_dto(input)
            bulk_dto["created_by"] = auth_context.user_id

            # Create bulk notifications
            batch_dto = await service.create_bulk_notifications(bulk_dto)

            return NotificationMapper.batch_dto_to_graphql_type(batch_dto)

        except Exception as e:
            logger.exception(f"Error creating bulk notifications: {e}")
            raise ValidationError("Failed to create bulk notifications")

    @strawberry.field(description="Resend failed notifications")
    @require_auth()
    @require_permission("notifications:resend")
    @rate_limit(key="notification_resend", max_attempts=20, window=60)
    @audit_log("notification.resend")
    @track_metrics("notification_resend")
    async def resend_notification(
        self, info: strawberry.Info, input: NotificationResendInput
    ) -> NotificationType:
        """Resend a failed notification."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Convert input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            resend_dto = NotificationMapper.resend_input_to_dto(input)

            # Resend notification
            result_dto = await service.resend_notification(resend_dto)

            return NotificationMapper.to_graphql_type(result_dto)

        except Exception as e:
            logger.exception(f"Error resending notification: {e}")
            raise ValidationError("Failed to resend notification")

    @strawberry.field(description="Cancel scheduled notifications")
    @require_auth()
    @require_permission("notifications:cancel")
    @rate_limit(key="notification_cancel", max_attempts=30, window=60)
    @audit_log("notification.cancel")
    @track_metrics("notification_cancel")
    @batch_size_limit(max_size=50)
    async def cancel_notifications(
        self, info: strawberry.Info, input: NotificationCancelInput
    ) -> list[NotificationType]:
        """Cancel scheduled notifications."""
        try:
            service = info.context["container"].resolve("NotificationService")

            # Convert input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            cancel_dto = NotificationMapper.cancel_input_to_dto(input)

            # Cancel notifications
            results = await service.cancel_notifications(cancel_dto)

            return [NotificationMapper.to_graphql_type(dto) for dto in results]

        except Exception as e:
            logger.exception(f"Error canceling notifications: {e}")
            raise ValidationError("Failed to cancel notifications")

    @strawberry.field(description="Delete a notification")
    @require_auth()
    @require_permission("notifications:delete")
    @rate_limit(key="notification_delete", max_attempts=20, window=60)
    @audit_log("notification.delete")
    @track_metrics("notification_delete")
    async def delete_notification(self, info: strawberry.Info, id: UUID) -> bool:
        """Delete a notification."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve("NotificationService")

            # Check if notification exists and user has permission
            existing = await service.get_notification_by_id(id)
            if not existing:
                raise ValidationError("Notification not found")

            # Delete notification
            return await service.delete_notification(id)

        except Exception as e:
            logger.exception(f"Error deleting notification {id}: {e}")
            raise ValidationError("Failed to delete notification")

    @strawberry.field(description="Update notification preferences")
    @require_auth()
    @require_permission("notifications:update_preferences")
    @rate_limit(key="notification_preferences", max_attempts=30, window=60)
    @audit_log("notification.update_preferences")
    @track_metrics("notification_update_preferences")
    async def update_notification_preferences(
        self, info: strawberry.Info, input: NotificationPreferencesInput
    ) -> bool:
        """Update notification preferences for a recipient."""
        try:
            auth_context = info.context.get("auth_context")
            if not auth_context:
                raise AuthorizationError("Authentication required")

            service = info.context["container"].resolve(
                "NotificationPreferencesService"
            )

            # Convert input to DTO
            from ...mappers.notification_mapper import NotificationMapper

            preferences_dto = NotificationMapper.preferences_input_to_dto(input)

            # Update preferences
            return await service.update_preferences(preferences_dto)

        except Exception as e:
            logger.exception(f"Error updating notification preferences: {e}")
            raise ValidationError("Failed to update preferences")
