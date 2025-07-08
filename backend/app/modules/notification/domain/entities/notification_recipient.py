"""NotificationRecipient entity for managing recipient preferences and status.

This entity manages recipient information, preferences, and delivery status
across different notification channels.
"""

from datetime import datetime
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    NotificationChannel,
    RecipientStatus,
    TemplateType,
)
from app.modules.notification.domain.errors import RecipientBlockedError
from app.modules.notification.domain.value_objects import RecipientAddress


class NotificationRecipient(Entity):
    """Manages recipient information and preferences for notifications.

    This entity tracks recipient addresses across different channels,
    their preferences for different types of notifications, and their
    current status (active, unsubscribed, bounced, etc.).
    """

    def __init__(
        self,
        user_id: UUID,
        email: str | None = None,
        phone: str | None = None,
        device_tokens: list[str] | None = None,
        preferences: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize notification recipient.

        Args:
            user_id: Associated user ID
            email: Email address
            phone: Phone number
            device_tokens: Push notification device tokens
            preferences: Notification preferences
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        self.user_id = user_id

        # Channel addresses
        self.addresses: dict[NotificationChannel, RecipientAddress] = {}

        # Initialize addresses
        if email:
            self.set_address(NotificationChannel.EMAIL, email)
        if phone:
            self.set_address(NotificationChannel.SMS, phone)
        if device_tokens:
            for token in device_tokens:
                self.add_device_token(token)

        # Always add in-app address using user ID
        self.set_address(NotificationChannel.IN_APP, str(user_id))

        # Channel status tracking
        self.channel_status: dict[NotificationChannel, RecipientStatus] = dict.fromkeys(NotificationChannel, RecipientStatus.ACTIVE)

        # Preferences by channel and template type
        self.preferences = preferences or self._default_preferences()

        # Unsubscribe tracking
        self.unsubscribed_channels: set[NotificationChannel] = set()
        self.unsubscribed_types: set[TemplateType] = set()
        self.unsubscribe_history: list[dict[str, Any]] = []

        # Bounce and complaint tracking
        self.bounce_count: dict[NotificationChannel, int] = dict.fromkeys(NotificationChannel, 0)
        self.complaint_count: dict[NotificationChannel, int] = dict.fromkeys(NotificationChannel, 0)

        # Last activity tracking
        self.last_notification_at: datetime | None = None
        self.last_read_at: datetime | None = None
        self.last_bounce_at: datetime | None = None
        self.last_complaint_at: datetime | None = None

    def _default_preferences(self) -> dict[str, Any]:
        """Get default notification preferences."""
        return {
            "channels": {
                NotificationChannel.EMAIL.value: {
                    "enabled": True,
                    "frequency": "immediate",
                    "digest": False,
                },
                NotificationChannel.SMS.value: {
                    "enabled": True,
                    "frequency": "immediate",
                    "quiet_hours": {"start": "22:00", "end": "08:00"},
                },
                NotificationChannel.PUSH.value: {
                    "enabled": True,
                    "frequency": "immediate",
                    "sound": True,
                    "vibrate": True,
                },
                NotificationChannel.IN_APP.value: {
                    "enabled": True,
                    "frequency": "immediate",
                },
            },
            "types": {
                TemplateType.TRANSACTIONAL.value: {
                    "enabled": True,
                    "channels": ["email", "sms", "push", "in_app"],
                },
                TemplateType.MARKETING.value: {
                    "enabled": True,
                    "channels": ["email", "push"],
                },
                TemplateType.SYSTEM.value: {
                    "enabled": True,
                    "channels": ["email", "in_app"],
                },
                TemplateType.ALERT.value: {
                    "enabled": True,
                    "channels": ["sms", "push", "in_app"],
                },
            },
            "timezone": "UTC",
            "language": "en",
        }

    def set_address(
        self,
        channel: NotificationChannel,
        address: str,
        display_name: str | None = None,
    ) -> None:
        """Set address for a channel.

        Args:
            channel: Notification channel
            address: Channel-specific address
            display_name: Optional display name
        """
        recipient_address = RecipientAddress(
            channel=channel, address=address, display_name=display_name
        )
        self.addresses[channel] = recipient_address

        # Ensure channel is active when address is set
        if self.channel_status.get(channel) == RecipientStatus.UNSUBSCRIBED:
            self.channel_status[channel] = RecipientStatus.ACTIVE

        self.mark_modified()

    def remove_address(self, channel: NotificationChannel) -> None:
        """Remove address for a channel.

        Args:
            channel: Notification channel
        """
        if channel in self.addresses:
            del self.addresses[channel]
            self.channel_status[channel] = RecipientStatus.UNSUBSCRIBED
            self.mark_modified()

    def add_device_token(self, token: str, display_name: str | None = None) -> None:
        """Add a push notification device token.

        Args:
            token: Device token
            display_name: Optional device name
        """
        # For push notifications, we store multiple tokens
        if NotificationChannel.PUSH not in self.addresses:
            self.addresses[NotificationChannel.PUSH] = []

        if not isinstance(self.addresses[NotificationChannel.PUSH], list):
            self.addresses[NotificationChannel.PUSH] = [
                self.addresses[NotificationChannel.PUSH]
            ]

        # Add new token if not already present
        recipient_address = RecipientAddress(
            channel=NotificationChannel.PUSH, address=token, display_name=display_name
        )

        # Check if token already exists
        existing_tokens = [
            addr.address
            for addr in self.addresses[NotificationChannel.PUSH]
            if isinstance(addr, RecipientAddress)
        ]

        if token not in existing_tokens:
            self.addresses[NotificationChannel.PUSH].append(recipient_address)
            self.mark_modified()

    def remove_device_token(self, token: str) -> None:
        """Remove a push notification device token.

        Args:
            token: Device token to remove
        """
        if NotificationChannel.PUSH in self.addresses and isinstance(
            self.addresses[NotificationChannel.PUSH], list
        ):
            self.addresses[NotificationChannel.PUSH] = [
                addr
                for addr in self.addresses[NotificationChannel.PUSH]
                if addr.address != token
            ]
            if not self.addresses[NotificationChannel.PUSH]:
                del self.addresses[NotificationChannel.PUSH]
            self.mark_modified()

    def get_address(self, channel: NotificationChannel) -> RecipientAddress | None:
        """Get primary address for a channel.

        Args:
            channel: Notification channel

        Returns:
            Primary recipient address or None
        """
        address = self.addresses.get(channel)
        if isinstance(address, list) and address:
            return address[0]  # Return first device token for push
        return address

    def get_all_addresses(self, channel: NotificationChannel) -> list[RecipientAddress]:
        """Get all addresses for a channel (mainly for push tokens).

        Args:
            channel: Notification channel

        Returns:
            List of recipient addresses
        """
        address = self.addresses.get(channel)
        if address is None:
            return []
        if isinstance(address, list):
            return address
        return [address]

    def can_receive_on_channel(
        self, channel: NotificationChannel, template_type: TemplateType | None = None
    ) -> bool:
        """Check if recipient can receive notifications on a channel.

        Args:
            channel: Notification channel
            template_type: Type of notification

        Returns:
            True if recipient can receive notifications
        """
        # Check if address exists for channel
        if channel not in self.addresses:
            return False

        # Check channel status
        status = self.channel_status.get(channel, RecipientStatus.ACTIVE)
        if not status.can_receive_notifications():
            return False

        # Check if channel is unsubscribed
        if channel in self.unsubscribed_channels:
            return False

        # Check if template type is unsubscribed
        if template_type and template_type in self.unsubscribed_types:
            return False

        # Check preferences
        channel_prefs = self.preferences.get("channels", {}).get(channel.value, {})
        if not channel_prefs.get("enabled", True):
            return False

        # Check template type preferences
        if template_type:
            type_prefs = self.preferences.get("types", {}).get(template_type.value, {})
            if not type_prefs.get("enabled", True):
                return False
            allowed_channels = type_prefs.get("channels", [])
            if allowed_channels and channel.value not in allowed_channels:
                return False

        return True

    def unsubscribe(
        self,
        channel: NotificationChannel | None = None,
        template_type: TemplateType | None = None,
        reason: str | None = None,
    ) -> None:
        """Unsubscribe from notifications.

        Args:
            channel: Specific channel to unsubscribe from (None = all)
            template_type: Specific type to unsubscribe from (None = all)
            reason: Unsubscribe reason
        """
        timestamp = datetime.utcnow()

        if channel:
            self.unsubscribed_channels.add(channel)
            self.channel_status[channel] = RecipientStatus.UNSUBSCRIBED
        else:
            # Unsubscribe from all channels
            self.unsubscribed_channels.update(NotificationChannel)
            for ch in NotificationChannel:
                self.channel_status[ch] = RecipientStatus.UNSUBSCRIBED

        if template_type:
            self.unsubscribed_types.add(template_type)
        else:
            # Unsubscribe from all types
            self.unsubscribed_types.update(TemplateType)

        # Record in history
        self.unsubscribe_history.append(
            {
                "timestamp": timestamp,
                "channel": channel.value if channel else "all",
                "template_type": template_type.value if template_type else "all",
                "reason": reason,
            }
        )

        self.mark_modified()

    def resubscribe(
        self,
        channel: NotificationChannel | None = None,
        template_type: TemplateType | None = None,
    ) -> None:
        """Resubscribe to notifications.

        Args:
            channel: Specific channel to resubscribe to (None = all)
            template_type: Specific type to resubscribe to (None = all)
        """
        if channel:
            self.unsubscribed_channels.discard(channel)
            if channel in self.addresses:
                self.channel_status[channel] = RecipientStatus.ACTIVE
        else:
            # Resubscribe to all channels
            self.unsubscribed_channels.clear()
            for ch in self.addresses:
                self.channel_status[ch] = RecipientStatus.ACTIVE

        if template_type:
            self.unsubscribed_types.discard(template_type)
        else:
            # Resubscribe to all types
            self.unsubscribed_types.clear()

        self.mark_modified()

    def record_bounce(
        self, channel: NotificationChannel, is_permanent: bool = False
    ) -> None:
        """Record a delivery bounce.

        Args:
            channel: Channel that bounced
            is_permanent: Whether bounce is permanent
        """
        self.bounce_count[channel] = self.bounce_count.get(channel, 0) + 1
        self.last_bounce_at = datetime.utcnow()

        # Mark as bounced if permanent or too many bounces
        if is_permanent or self.bounce_count[channel] >= 3:
            self.channel_status[channel] = RecipientStatus.BOUNCED

        self.mark_modified()

    def record_complaint(self, channel: NotificationChannel) -> None:
        """Record a spam complaint.

        Args:
            channel: Channel with complaint
        """
        self.complaint_count[channel] = self.complaint_count.get(channel, 0) + 1
        self.last_complaint_at = datetime.utcnow()

        # Immediately mark as complained
        self.channel_status[channel] = RecipientStatus.COMPLAINED

        self.mark_modified()

    def suppress(
        self,
        channel: NotificationChannel | None = None,
        reason: str = "Administrative suppression",
    ) -> None:
        """Administratively suppress recipient.

        Args:
            channel: Specific channel to suppress (None = all)
            reason: Suppression reason
        """
        if channel:
            self.channel_status[channel] = RecipientStatus.SUPPRESSED
        else:
            for ch in NotificationChannel:
                self.channel_status[ch] = RecipientStatus.SUPPRESSED

        # Add to metadata
        if "suppression_history" not in self.metadata:
            self.metadata["suppression_history"] = []

        self.metadata["suppression_history"].append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "channel": channel.value if channel else "all",
                "reason": reason,
            }
        )

        self.mark_modified()

    def update_preferences(self, preferences: dict[str, Any]) -> None:
        """Update notification preferences.

        Args:
            preferences: New preferences to merge
        """
        # Deep merge preferences
        self._merge_preferences(self.preferences, preferences)
        self.mark_modified()

    def _merge_preferences(self, current: dict, updates: dict) -> None:
        """Recursively merge preference dictionaries."""
        for key, value in updates.items():
            if (
                key in current
                and isinstance(current[key], dict)
                and isinstance(value, dict)
            ):
                self._merge_preferences(current[key], value)
            else:
                current[key] = value

    def record_notification_sent(self) -> None:
        """Record that a notification was sent."""
        self.last_notification_at = datetime.utcnow()
        self.mark_modified()

    def record_notification_read(self) -> None:
        """Record that a notification was read."""
        self.last_read_at = datetime.utcnow()
        self.mark_modified()

    def validate_for_sending(
        self, channel: NotificationChannel, template_type: TemplateType | None = None
    ) -> None:
        """Validate recipient can receive notifications.

        Args:
            channel: Target channel
            template_type: Notification type

        Raises:
            RecipientBlockedError: If recipient is blocked
            ValidationError: If recipient cannot receive notifications
        """
        # Check if address exists
        if channel not in self.addresses:
            raise ValidationError(
                f"No {channel.value} address configured for recipient"
            )

        # Check channel status
        status = self.channel_status.get(channel, RecipientStatus.ACTIVE)
        if status.is_permanently_blocked():
            raise RecipientBlockedError(
                recipient_id=self.id,
                recipient_address=str(self.get_address(channel)),
                block_reason=f"Recipient status is {status.value}",
            )

        # Check if can receive
        if not self.can_receive_on_channel(channel, template_type):
            raise ValidationError(
                f"Recipient cannot receive {template_type.value if template_type else 'notifications'} "
                f"on {channel.value} channel"
            )

    def get_channel_summary(self) -> dict[str, Any]:
        """Get summary of recipient's channel configuration."""
        summary = {}

        for channel in NotificationChannel:
            address = self.get_address(channel)
            status = self.channel_status.get(channel, RecipientStatus.ACTIVE)

            summary[channel.value] = {
                "configured": address is not None,
                "address": str(address) if address else None,
                "status": status.value,
                "can_receive": status.can_receive_notifications(),
                "bounce_count": self.bounce_count.get(channel, 0),
                "complaint_count": self.complaint_count.get(channel, 0),
                "unsubscribed": channel in self.unsubscribed_channels,
            }

        return summary

    def __str__(self) -> str:
        """String representation."""
        active_channels = [
            ch.value
            for ch in NotificationChannel
            if ch in self.addresses and self.can_receive_on_channel(ch)
        ]
        return f"NotificationRecipient({self.user_id}) - Active: {', '.join(active_channels)}"
