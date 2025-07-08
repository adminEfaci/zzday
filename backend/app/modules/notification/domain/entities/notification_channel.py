"""NotificationChannel entity for managing channel configurations.

This entity manages the configuration and status of notification delivery
channels (email, SMS, push, in-app) including provider settings and limits.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import ChannelStatus
from app.modules.notification.domain.enums import NotificationChannel as ChannelType
from app.modules.notification.domain.errors import (
    ChannelNotConfiguredError,
    RateLimitExceededError,
)
from app.modules.notification.domain.value_objects import ChannelConfig


class NotificationChannel(Entity):
    """Manages configuration and state for a notification delivery channel.

    This entity handles provider configuration, rate limiting, health monitoring,
    and feature management for each notification channel.
    """

    def __init__(
        self,
        channel_type: ChannelType,
        provider: str,
        config: ChannelConfig,
        is_primary: bool = True,
        entity_id: UUID | None = None,
    ):
        """Initialize notification channel.

        Args:
            channel_type: Type of notification channel
            provider: Provider name
            config: Channel configuration
            is_primary: Whether this is the primary provider for the channel
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        self.channel_type = channel_type
        self.provider = provider
        self.config = self._validate_config(config, channel_type)
        self.is_primary = is_primary

        # Status tracking
        self.status = ChannelStatus.CONFIGURING
        self.last_health_check: datetime | None = None
        self.last_error: str | None = None
        self.consecutive_failures: int = 0
        self.max_consecutive_failures: int = 5

        # Rate limiting
        self.rate_limit_window: dict[str, datetime] = {}
        self.rate_limit_counts: dict[str, int] = {}

        # Performance metrics
        self.total_sent: int = 0
        self.total_delivered: int = 0
        self.total_failed: int = 0
        self.total_bounced: int = 0

        # Cost tracking (for paid services)
        self.cost_per_message: float | None = None
        self.total_cost: float = 0.0
        self.cost_currency: str = "USD"

        # Feature flags
        self.enabled_features: set[str] = set(config.features)

        # Provider-specific metadata
        self.provider_metadata: dict[str, Any] = {}

    def _validate_config(
        self, config: ChannelConfig, channel_type: ChannelType
    ) -> ChannelConfig:
        """Validate channel configuration."""
        if not isinstance(config, ChannelConfig):
            raise ValidationError("Config must be a ChannelConfig instance")

        if config.channel != channel_type:
            raise ValidationError(
                f"Config channel {config.channel.value} does not match "
                f"channel type {channel_type.value}"
            )

        return config

    @property
    def is_operational(self) -> bool:
        """Check if channel is operational."""
        return self.status.is_operational()

    @property
    def is_healthy(self) -> bool:
        """Check if channel is healthy based on recent checks."""
        if not self.last_health_check:
            return False

        # Consider unhealthy if no check in last 5 minutes
        time_since_check = datetime.utcnow() - self.last_health_check
        if time_since_check > timedelta(minutes=5):
            return False

        return self.status == ChannelStatus.ACTIVE and self.consecutive_failures == 0

    def activate(self) -> None:
        """Activate the channel for use."""
        if self.status == ChannelStatus.ERROR:
            raise ChannelNotConfiguredError(
                channel=self.channel_type.value,
                reason="Cannot activate channel in error state",
            )

        self.status = ChannelStatus.ACTIVE
        self.consecutive_failures = 0
        self.last_error = None
        self.mark_modified()

    def deactivate(self, reason: str | None = None) -> None:
        """Deactivate the channel.

        Args:
            reason: Deactivation reason
        """
        self.status = ChannelStatus.INACTIVE
        if reason:
            self.add_metadata("deactivation_reason", reason)
        self.add_metadata("deactivated_at", datetime.utcnow().isoformat())
        self.mark_modified()

    def suspend(self, reason: str, duration_minutes: int | None = None) -> None:
        """Temporarily suspend the channel.

        Args:
            reason: Suspension reason
            duration_minutes: How long to suspend (None = manual resume required)
        """
        self.status = ChannelStatus.SUSPENDED
        self.add_metadata("suspension_reason", reason)
        self.add_metadata("suspended_at", datetime.utcnow().isoformat())

        if duration_minutes:
            resume_at = datetime.utcnow() + timedelta(minutes=duration_minutes)
            self.add_metadata("auto_resume_at", resume_at.isoformat())

        self.mark_modified()

    def record_health_check(
        self, is_healthy: bool, details: dict[str, Any] | None = None
    ) -> None:
        """Record health check result.

        Args:
            is_healthy: Whether check passed
            details: Check details
        """
        self.last_health_check = datetime.utcnow()

        if is_healthy:
            self.consecutive_failures = 0
            self.last_error = None
            if self.status == ChannelStatus.ERROR:
                self.status = ChannelStatus.ACTIVE
        else:
            self.consecutive_failures += 1
            if details and "error" in details:
                self.last_error = details["error"]

            # Auto-suspend if too many failures
            if self.consecutive_failures >= self.max_consecutive_failures:
                self.status = ChannelStatus.ERROR
                self.suspend(
                    f"Too many consecutive health check failures ({self.consecutive_failures})",
                    duration_minutes=30,  # Auto-resume after 30 minutes
                )

        # Store health check history
        if "health_checks" not in self.provider_metadata:
            self.provider_metadata["health_checks"] = []

        self.provider_metadata["health_checks"].append(
            {
                "timestamp": self.last_health_check.isoformat(),
                "healthy": is_healthy,
                "details": details,
            }
        )

        # Keep only last 100 health checks
        if len(self.provider_metadata["health_checks"]) > 100:
            self.provider_metadata["health_checks"] = self.provider_metadata[
                "health_checks"
            ][-100:]

        self.mark_modified()

    def check_rate_limit(self, limit_type: str = "per_second") -> bool:
        """Check if rate limit allows sending.

        Args:
            limit_type: Type of rate limit to check

        Returns:
            True if within rate limit
        """
        limit = self.config.get_rate_limit(limit_type)
        if not limit:
            return True  # No limit configured

        now = datetime.utcnow()

        # Determine window duration
        if limit_type == "per_second":
            window_duration = timedelta(seconds=1)
        elif limit_type == "per_minute":
            window_duration = timedelta(minutes=1)
        elif limit_type == "per_hour":
            window_duration = timedelta(hours=1)
        else:
            window_duration = timedelta(seconds=1)

        # Check if window has expired
        if limit_type in self.rate_limit_window:
            if now - self.rate_limit_window[limit_type] > window_duration:
                # Reset window
                self.rate_limit_window[limit_type] = now
                self.rate_limit_counts[limit_type] = 0
        else:
            # Initialize window
            self.rate_limit_window[limit_type] = now
            self.rate_limit_counts[limit_type] = 0

        # Check count
        current_count = self.rate_limit_counts.get(limit_type, 0)
        return current_count < limit

    def increment_rate_limit(self, limit_type: str = "per_second") -> None:
        """Increment rate limit counter.

        Args:
            limit_type: Type of rate limit to increment

        Raises:
            RateLimitExceededError: If rate limit exceeded
        """
        if not self.check_rate_limit(limit_type):
            limit = self.config.get_rate_limit(limit_type)
            raise RateLimitExceededError(
                channel=self.channel_type.value,
                limit=limit,
                window=limit_type.replace("per_", ""),
                retry_after=60,  # Default retry after 60 seconds
            )

        self.rate_limit_counts[limit_type] = (
            self.rate_limit_counts.get(limit_type, 0) + 1
        )

    def record_send(self, cost: float | None = None) -> None:
        """Record a message send.

        Args:
            cost: Cost of sending the message
        """
        self.total_sent += 1
        if cost:
            self.total_cost += cost
        self.mark_modified()

    def record_delivery(self) -> None:
        """Record successful delivery."""
        self.total_delivered += 1
        self.mark_modified()

    def record_failure(self, is_bounce: bool = False) -> None:
        """Record delivery failure.

        Args:
            is_bounce: Whether this was a bounce
        """
        self.total_failed += 1
        if is_bounce:
            self.total_bounced += 1
        self.mark_modified()

    def update_config(self, new_config: ChannelConfig) -> None:
        """Update channel configuration.

        Args:
            new_config: New configuration
        """
        self.config = self._validate_config(new_config, self.channel_type)
        self.enabled_features = set(new_config.features)
        self.status = ChannelStatus.CONFIGURING
        self.mark_modified()

    def add_feature(self, feature: str) -> None:
        """Enable a feature.

        Args:
            feature: Feature to enable
        """
        self.enabled_features.add(feature)
        self.mark_modified()

    def remove_feature(self, feature: str) -> None:
        """Disable a feature.

        Args:
            feature: Feature to disable
        """
        self.enabled_features.discard(feature)
        self.mark_modified()

    def has_feature(self, feature: str) -> bool:
        """Check if feature is enabled.

        Args:
            feature: Feature to check

        Returns:
            True if feature is enabled
        """
        return feature in self.enabled_features

    def set_cost_per_message(self, cost: float, currency: str = "USD") -> None:
        """Set cost per message for tracking.

        Args:
            cost: Cost per message
            currency: Currency code
        """
        self.cost_per_message = cost
        self.cost_currency = currency
        self.mark_modified()

    def add_metadata(self, key: str, value: Any) -> None:
        """Add provider-specific metadata.

        Args:
            key: Metadata key
            value: Metadata value
        """
        self.provider_metadata[key] = value
        self.mark_modified()

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get channel performance metrics."""
        delivery_rate = (
            (self.total_delivered / self.total_sent * 100) if self.total_sent > 0 else 0
        )

        failure_rate = (
            (self.total_failed / self.total_sent * 100) if self.total_sent > 0 else 0
        )

        bounce_rate = (
            (self.total_bounced / self.total_sent * 100) if self.total_sent > 0 else 0
        )

        return {
            "total_sent": self.total_sent,
            "total_delivered": self.total_delivered,
            "total_failed": self.total_failed,
            "total_bounced": self.total_bounced,
            "delivery_rate": round(delivery_rate, 2),
            "failure_rate": round(failure_rate, 2),
            "bounce_rate": round(bounce_rate, 2),
            "total_cost": self.total_cost,
            "cost_currency": self.cost_currency,
            "average_cost_per_message": (
                self.total_cost / self.total_sent if self.total_sent > 0 else 0
            ),
        }

    def get_status_info(self) -> dict[str, Any]:
        """Get channel status information."""
        return {
            "channel": self.channel_type.value,
            "provider": self.provider,
            "status": self.status.value,
            "is_operational": self.is_operational,
            "is_healthy": self.is_healthy,
            "is_primary": self.is_primary,
            "last_health_check": (
                self.last_health_check.isoformat() if self.last_health_check else None
            ),
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "features": list(self.enabled_features),
        }

    def check_auto_resume(self) -> bool:
        """Check if channel should auto-resume from suspension.

        Returns:
            True if channel was auto-resumed
        """
        if self.status != ChannelStatus.SUSPENDED:
            return False

        auto_resume_at = self.provider_metadata.get("auto_resume_at")
        if not auto_resume_at:
            return False

        resume_time = datetime.fromisoformat(auto_resume_at)
        if datetime.utcnow() >= resume_time:
            self.status = ChannelStatus.ACTIVE
            self.consecutive_failures = 0
            self.add_metadata("auto_resumed_at", datetime.utcnow().isoformat())
            self.mark_modified()
            return True

        return False

    def __str__(self) -> str:
        """String representation."""
        return (
            f"NotificationChannel({self.channel_type.value}) - "
            f"{self.provider} - {self.status.value}"
        )
