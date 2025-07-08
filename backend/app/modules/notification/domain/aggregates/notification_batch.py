"""NotificationBatch aggregate for managing bulk notification processing.

This aggregate handles the creation and processing of notification batches,
enabling efficient bulk sending of notifications to multiple recipients.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    BatchStatus,
    NotificationChannel,
    NotificationPriority,
)
from app.modules.notification.domain.events import BatchCreated, BatchProcessed
from app.modules.notification.domain.value_objects import RecipientAddress

# Constants
MAX_BATCH_NAME_LENGTH = 200
MAX_PROCESSING_ERRORS = 1000


class NotificationBatch(AggregateRoot):
    """Aggregate for managing batch notification processing.

    This aggregate handles the creation, validation, and processing of
    bulk notifications, providing efficient delivery to multiple recipients
    while tracking success and failure rates.
    """

    def __init__(
        self,
        name: str,
        template_id: UUID,
        created_by: UUID,
        priority: NotificationPriority | None = None,
        scheduled_for: datetime | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize notification batch.

        Args:
            name: Batch name/description
            template_id: Template to use for notifications
            created_by: User creating the batch
            priority: Batch priority level
            scheduled_for: When to process the batch
            expires_at: When batch expires
            metadata: Additional batch metadata
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Basic fields
        self.name = self._validate_name(name)
        self.template_id = template_id
        self.created_by = created_by
        self.priority = priority or NotificationPriority.NORMAL
        self.scheduled_for = scheduled_for
        self.expires_at = expires_at
        self.metadata = metadata or {}

        # Batch configuration
        self.channels: set[NotificationChannel] = set()
        self.template_variables: dict[str, Any] = {}
        self.recipient_variables: dict[UUID, dict[str, Any]] = {}

        # Recipients tracking
        self.recipients: list[dict[str, Any]] = []
        self.total_recipients: int = 0

        # Processing state
        self.status = BatchStatus.CREATED
        self.processing_started_at: datetime | None = None
        self.processing_completed_at: datetime | None = None

        # Results tracking
        self.notifications_created: list[UUID] = []
        self.successful_count: int = 0
        self.failed_count: int = 0
        self.skipped_count: int = 0
        self.processing_errors: list[dict[str, Any]] = []

        # Performance tracking
        self.processing_time_seconds: float | None = None
        self.average_time_per_notification: float | None = None

        # Add creation event
        self.add_event(
            BatchCreated(
                batch_id=self.id,
                template_id=self.template_id,
                total_recipients=0,  # Will be updated when recipients are added
                channels=[],  # Will be updated when channels are set
                created_by=self.created_by,
                scheduled_for=self.scheduled_for,
            )
        )

    def _validate_name(self, name: str) -> str:
        """Validate batch name."""
        if not name or not name.strip():
            raise ValidationError("Batch name is required")

        name = name.strip()
        if len(name) > MAX_BATCH_NAME_LENGTH:
            raise ValidationError(f"Batch name cannot exceed {MAX_BATCH_NAME_LENGTH} characters")

        return name

    def add_recipients(
        self, recipients: list[dict[str, Any]], channel: NotificationChannel
    ) -> None:
        """Add recipients to the batch.

        Args:
            recipients: List of recipient data with format:
                [
                    {
                        "user_id": UUID,
                        "address": str,  # Channel-specific address
                        "display_name": str | None,
                        "variables": dict[str, Any] | None  # Recipient-specific vars
                    }
                ]
            channel: Channel for these recipients
        """
        if not self.status.can_add_notifications():
            raise ValidationError(
                f"Cannot add recipients to batch in {self.status.value} status"
            )

        # Validate recipients
        validated_recipients = []
        for recipient_data in recipients:
            validated = self._validate_recipient_data(recipient_data, channel)
            validated_recipients.append(validated)

        # Add to batch
        self.channels.add(channel)

        for recipient in validated_recipients:
            # Store recipient
            self.recipients.append(
                {
                    "user_id": recipient["user_id"],
                    "channel": channel,
                    "address": recipient["address"],
                    "display_name": recipient.get("display_name"),
                }
            )

            # Store recipient-specific variables if provided
            if recipient.get("variables"):
                self.recipient_variables[recipient["user_id"]] = recipient["variables"]

        self.total_recipients = len(self.recipients)
        self.mark_modified()

    def _validate_recipient_data(
        self, recipient_data: dict[str, Any], channel: NotificationChannel
    ) -> dict[str, Any]:
        """Validate recipient data format."""
        if "user_id" not in recipient_data:
            raise ValidationError("Recipient data must include user_id")

        if "address" not in recipient_data:
            raise ValidationError("Recipient data must include address")

        # Validate address format for channel
        try:
            RecipientAddress(
                channel=channel,
                address=recipient_data["address"],
                display_name=recipient_data.get("display_name"),
            )
        except Exception as e:
            raise ValidationError(f"Invalid address for {channel.value}: {e!s}")

        return recipient_data

    def add_recipients_from_query(
        self, user_ids: list[UUID], channels: list[NotificationChannel]
    ) -> None:
        """Add recipients from a user query result.

        Args:
            user_ids: List of user IDs
            channels: Channels to use (addresses will be looked up)
        """
        if not self.status.can_add_notifications():
            raise ValidationError(
                f"Cannot add recipients to batch in {self.status.value} status"
            )

        for channel in channels:
            self.channels.add(channel)

        # Store user IDs for lookup during processing
        for user_id in user_ids:
            for channel in channels:
                self.recipients.append(
                    {
                        "user_id": user_id,
                        "channel": channel,
                        "address": None,  # Will be looked up during processing
                        "lookup_required": True,
                    }
                )

        self.total_recipients = len(self.recipients)
        self.mark_modified()

    def set_template_variables(self, variables: dict[str, Any]) -> None:
        """Set variables that apply to all recipients.

        Args:
            variables: Template variables
        """
        if not self.status.can_add_notifications():
            raise ValidationError(
                f"Cannot set variables for batch in {self.status.value} status"
            )

        self.template_variables.update(variables)
        self.mark_modified()

    def set_recipient_variables(
        self, recipient_id: UUID, variables: dict[str, Any]
    ) -> None:
        """Set variables for a specific recipient.

        Args:
            recipient_id: Recipient user ID
            variables: Recipient-specific variables
        """
        if not self.status.can_add_notifications():
            raise ValidationError(
                f"Cannot set variables for batch in {self.status.value} status"
            )

        # Ensure recipient exists
        recipient_exists = any(r["user_id"] == recipient_id for r in self.recipients)
        if not recipient_exists:
            raise ValidationError(f"Recipient {recipient_id} not found in batch")

        self.recipient_variables[recipient_id] = variables
        self.mark_modified()

    def validate_for_processing(self) -> None:
        """Validate batch is ready for processing.

        Raises:
            ValidationError: If batch is not ready
        """
        if self.total_recipients == 0:
            raise ValidationError("Batch has no recipients")

        if not self.channels:
            raise ValidationError("Batch has no channels configured")

        if self.expires_at and datetime.utcnow() > self.expires_at:
            raise ValidationError("Batch has expired")

        if self.status != BatchStatus.CREATED:
            raise ValidationError(
                f"Batch in {self.status.value} status cannot be processed"
            )

    def start_processing(self) -> list[dict[str, Any]]:
        """Start batch processing and return recipient data.

        Returns:
            List of recipient data for notification creation
        """
        self.validate_for_processing()

        self.status = BatchStatus.PROCESSING
        self.processing_started_at = datetime.utcnow()
        self.mark_modified()

        # Prepare recipient data for processing
        processing_data = []

        for recipient in self.recipients:
            # Merge template and recipient variables
            variables = {**self.template_variables}
            if recipient["user_id"] in self.recipient_variables:
                variables.update(self.recipient_variables[recipient["user_id"]])

            processing_data.append(
                {
                    "user_id": recipient["user_id"],
                    "channel": recipient["channel"],
                    "address": recipient.get("address"),
                    "display_name": recipient.get("display_name"),
                    "lookup_required": recipient.get("lookup_required", False),
                    "variables": variables,
                    "priority": self.priority,
                    "expires_at": self.expires_at,
                    "template_id": self.template_id,
                    "batch_id": self.id,
                }
            )

        return processing_data

    def record_notification_created(
        self, notification_id: UUID, recipient_id: UUID, channel: NotificationChannel
    ) -> None:
        """Record successful notification creation.

        Args:
            notification_id: Created notification ID
            recipient_id: Recipient user ID
            channel: Notification channel
        """
        self.notifications_created.append(notification_id)
        self.successful_count += 1
        self.mark_modified()

    def record_notification_failed(
        self,
        recipient_id: UUID,
        channel: NotificationChannel,
        error: str,
        is_skipped: bool = False,
    ) -> None:
        """Record failed notification creation.

        Args:
            recipient_id: Recipient user ID
            channel: Notification channel
            error: Error message
            is_skipped: Whether notification was skipped (vs failed)
        """
        if is_skipped:
            self.skipped_count += 1
        else:
            self.failed_count += 1

        self.processing_errors.append(
            {
                "recipient_id": str(recipient_id),
                "channel": channel.value,
                "error": error,
                "is_skipped": is_skipped,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )

        # Keep only last MAX_PROCESSING_ERRORS errors
        if len(self.processing_errors) > MAX_PROCESSING_ERRORS:
            self.processing_errors = self.processing_errors[-MAX_PROCESSING_ERRORS:]

        self.mark_modified()

    def complete_processing(self) -> None:
        """Mark batch processing as completed."""
        if self.status != BatchStatus.PROCESSING:
            raise ValidationError(
                f"Cannot complete batch in {self.status.value} status"
            )

        self.processing_completed_at = datetime.utcnow()

        # Calculate processing time
        if self.processing_started_at:
            self.processing_time_seconds = (
                self.processing_completed_at - self.processing_started_at
            ).total_seconds()

            if self.successful_count > 0:
                self.average_time_per_notification = (
                    self.processing_time_seconds / self.successful_count
                )

        # Determine final status
        if self.failed_count == 0 and self.skipped_count == 0:
            self.status = BatchStatus.COMPLETED
        elif self.successful_count == 0:
            self.status = BatchStatus.FAILED
        else:
            self.status = BatchStatus.PARTIAL

        # Add completion event
        self.add_event(
            BatchProcessed(
                batch_id=self.id,
                total_notifications=self.total_recipients,
                successful_count=self.successful_count,
                failed_count=self.failed_count + self.skipped_count,
                processing_time_seconds=self.processing_time_seconds or 0,
                completed_at=self.processing_completed_at,
            )
        )

        self.mark_modified()

    def fail_processing(self, reason: str) -> None:
        """Mark batch as failed.

        Args:
            reason: Failure reason
        """
        self.status = BatchStatus.FAILED
        self.processing_completed_at = datetime.utcnow()

        if self.processing_started_at:
            self.processing_time_seconds = (
                self.processing_completed_at - self.processing_started_at
            ).total_seconds()

        self.add_metadata("failure_reason", reason)

        # Add completion event
        self.add_event(
            BatchProcessed(
                batch_id=self.id,
                total_notifications=self.total_recipients,
                successful_count=self.successful_count,
                failed_count=self.total_recipients - self.successful_count,
                processing_time_seconds=self.processing_time_seconds or 0,
                completed_at=self.processing_completed_at,
            )
        )

        self.mark_modified()

    def cancel(self, reason: str | None = None) -> None:
        """Cancel the batch.

        Args:
            reason: Cancellation reason
        """
        if self.status.is_final():
            raise ValidationError(f"Cannot cancel batch in {self.status.value} status")

        self.status = BatchStatus.CANCELLED
        if reason:
            self.add_metadata("cancellation_reason", reason)
        self.add_metadata("cancelled_at", datetime.utcnow().isoformat())

        self.mark_modified()

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to batch.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.metadata[key] = value
        self.mark_modified()

    def get_processing_summary(self) -> dict[str, Any]:
        """Get batch processing summary."""
        success_rate = (
            (self.successful_count / self.total_recipients * 100)
            if self.total_recipients > 0
            else 0
        )

        return {
            "batch_id": str(self.id),
            "name": self.name,
            "status": self.status.value,
            "total_recipients": self.total_recipients,
            "channels": [ch.value for ch in self.channels],
            "successful_count": self.successful_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "success_rate": round(success_rate, 2),
            "processing_started_at": (
                self.processing_started_at.isoformat()
                if self.processing_started_at
                else None
            ),
            "processing_completed_at": (
                self.processing_completed_at.isoformat()
                if self.processing_completed_at
                else None
            ),
            "processing_time_seconds": self.processing_time_seconds,
            "average_time_per_notification": self.average_time_per_notification,
            "notifications_created": len(self.notifications_created),
        }

    def get_error_summary(self) -> dict[str, Any]:
        """Get summary of processing errors."""
        error_by_type = {}
        error_by_channel = {}

        for error in self.processing_errors:
            # Count by error message
            error_msg = error["error"]
            if error_msg not in error_by_type:
                error_by_type[error_msg] = 0
            error_by_type[error_msg] += 1

            # Count by channel
            channel = error["channel"]
            if channel not in error_by_channel:
                error_by_channel[channel] = 0
            error_by_channel[channel] += 1

        return {
            "total_errors": len(self.processing_errors),
            "errors_by_type": error_by_type,
            "errors_by_channel": error_by_channel,
            "recent_errors": self.processing_errors[-10:],  # Last 10 errors
        }

    def estimate_processing_time(self) -> timedelta:
        """Estimate time to process batch based on size and priority."""
        # Base estimate: 0.1 seconds per notification
        base_time = self.total_recipients * 0.1

        # Adjust for priority
        if self.priority == NotificationPriority.URGENT:
            multiplier = 0.5  # Faster processing
        elif self.priority == NotificationPriority.HIGH:
            multiplier = 0.75
        elif self.priority == NotificationPriority.LOW:
            multiplier = 1.5  # Slower processing
        else:
            multiplier = 1.0

        estimated_seconds = base_time * multiplier
        return timedelta(seconds=estimated_seconds)

    def __str__(self) -> str:
        """String representation."""
        channels = ", ".join(ch.value for ch in self.channels)
        return (
            f"NotificationBatch({self.name}) - "
            f"Status: {self.status.value} - "
            f"Recipients: {self.total_recipients} - "
            f"Channels: [{channels}]"
        )
