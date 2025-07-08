"""Notification domain value objects.

This module contains immutable value objects that represent domain concepts
without identity. These objects encapsulate validation and business logic
for specific domain values.
"""

import re
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.notification.domain.enums import (
    DeliveryStatus,
    NotificationChannel,
    NotificationPriority,
    VariableType,
)


class NotificationContent(ValueObject):
    """Represents notification message content with variable substitution support."""

    def __init__(
        self,
        subject: str | None = None,
        body: str = "",
        html_body: str | None = None,
        variables: dict[str, Any] | None = None,
        attachments: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize notification content.

        Args:
            subject: Message subject (required for email)
            body: Plain text message body
            html_body: HTML message body (for channels supporting rich content)
            variables: Template variables for substitution
            attachments: List of attachment metadata
            metadata: Additional content metadata
        """
        super().__init__()

        # Validate inputs
        self.validate_not_empty(body, "body")

        self.subject = subject.strip() if subject else None
        self.body = body.strip()
        self.html_body = html_body.strip() if html_body else None
        self.variables = variables or {}
        self.attachments = attachments or []
        self.metadata = metadata or {}

        # Validate content
        self._validate_content()

        # Freeze the object
        self._freeze()

    def _validate_content(self) -> None:
        """Validate content structure and values."""
        # Validate subject length if provided
        if self.subject and len(self.subject) > 200:
            raise ValidationError("Subject cannot exceed 200 characters")

        # Validate body length
        if len(self.body) > 100000:
            raise ValidationError("Body cannot exceed 100KB")

        # Validate HTML body if provided
        if self.html_body and len(self.html_body) > 500000:
            raise ValidationError("HTML body cannot exceed 500KB")

        # Validate attachments
        for attachment in self.attachments:
            if not isinstance(attachment, dict):
                raise ValidationError("Each attachment must be a dictionary")
            if "filename" not in attachment:
                raise ValidationError("Attachment must have a filename")
            if "size" in attachment and attachment["size"] > 10485760:  # 10MB
                raise ValidationError(
                    f"Attachment {attachment['filename']} exceeds 10MB limit"
                )

    def render(
        self, template_variables: dict[str, Any] | None = None
    ) -> "NotificationContent":
        """Render content with variables substituted.

        Args:
            template_variables: Variables to substitute in content

        Returns:
            New NotificationContent instance with rendered content
        """
        # Merge template variables with instance variables
        all_variables = {**self.variables}
        if template_variables:
            all_variables.update(template_variables)

        # Render subject
        rendered_subject = (
            self._render_template(self.subject, all_variables) if self.subject else None
        )

        # Render body
        rendered_body = self._render_template(self.body, all_variables)

        # Render HTML body
        rendered_html_body = (
            self._render_template(self.html_body, all_variables)
            if self.html_body
            else None
        )

        return NotificationContent(
            subject=rendered_subject,
            body=rendered_body,
            html_body=rendered_html_body,
            attachments=self.attachments,
            metadata=self.metadata,
        )

    def _render_template(self, template: str, variables: dict[str, Any]) -> str:
        """Render template with variable substitution.

        Uses simple {{variable}} syntax for substitution.
        """
        if not template:
            return template

        result = template
        for key, value in variables.items():
            placeholder = f"{{{{{key}}}}}"
            result = result.replace(placeholder, str(value))

        return result

    def extract_variables(self) -> list[str]:
        """Extract variable names from content templates."""
        variables = set()

        # Extract from all content fields
        for content in [self.subject, self.body, self.html_body]:
            if content:
                # Find all {{variable}} patterns
                matches = re.findall(r"\{\{(\w+)\}\}", content)
                variables.update(matches)

        return sorted(variables)

    def for_channel(self, channel: NotificationChannel) -> "NotificationContent":
        """Get content optimized for specific channel.

        Args:
            channel: Target notification channel

        Returns:
            New NotificationContent instance optimized for channel
        """
        if channel == NotificationChannel.SMS:
            # SMS: Use plain text body only, truncate if needed
            sms_body = self.body[:160] if len(self.body) > 160 else self.body
            return NotificationContent(body=sms_body)

        if channel == NotificationChannel.PUSH:
            # Push: Use subject as title, truncate body
            push_body = self.body[:100] if len(self.body) > 100 else self.body
            return NotificationContent(subject=self.subject, body=push_body)

        if channel == NotificationChannel.EMAIL:
            # Email: Use full content including HTML
            return self

        if channel == NotificationChannel.IN_APP:
            # In-app: Can use HTML but no attachments
            return NotificationContent(
                subject=self.subject,
                body=self.body,
                html_body=self.html_body,
                metadata=self.metadata,
            )

        return self

    def __str__(self) -> str:
        """String representation."""
        if self.subject:
            return f"Subject: {self.subject[:50]}..."
        return f"Body: {self.body[:50]}..."


class RecipientAddress(ValueObject):
    """Represents a recipient address for a specific channel."""

    def __init__(
        self,
        channel: NotificationChannel,
        address: str,
        display_name: str | None = None,
    ):
        """Initialize recipient address.

        Args:
            channel: Notification channel
            address: Channel-specific address (email, phone, device token)
            display_name: Optional display name for recipient
        """
        super().__init__()

        self.channel = channel
        self.address = self._validate_and_normalize_address(channel, address)
        self.display_name = display_name.strip() if display_name else None

        self._freeze()

    def _validate_and_normalize_address(
        self, channel: NotificationChannel, address: str
    ) -> str:
        """Validate and normalize address based on channel requirements."""
        if not address:
            raise ValidationError("Address cannot be empty")

        address = address.strip()

        if channel == NotificationChannel.EMAIL:
            # Basic email validation
            if not re.match(
                r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", address
            ):
                raise ValidationError(f"Invalid email address: {address}")
            return address.lower()

        if channel == NotificationChannel.SMS:
            # Basic phone number validation and normalization
            # Remove common formatting characters
            normalized = re.sub(r"[\s\-\(\)\.]", "", address)
            # Ensure it starts with + for international format
            if not normalized.startswith("+"):
                normalized = "+" + normalized
            # Basic validation: should be digits after +
            if not re.match(r"^\+\d{10,15}$", normalized):
                raise ValidationError(f"Invalid phone number: {address}")
            return normalized

        if channel == NotificationChannel.PUSH:
            # Device token validation (basic)
            if len(address) < 32:
                raise ValidationError("Invalid device token")
            return address

        if channel == NotificationChannel.IN_APP:
            # In-app uses user ID
            try:
                UUID(address)
                return address
            except ValueError:
                raise ValidationError("In-app address must be a valid UUID")

        return address

    def __str__(self) -> str:
        """String representation."""
        if self.display_name:
            return f"{self.display_name} <{self.address}>"
        return self.address


class ChannelConfig(ValueObject):
    """Channel-specific configuration settings."""

    def __init__(
        self,
        channel: NotificationChannel,
        provider: str,
        settings: dict[str, Any],
        credentials: dict[str, str] | None = None,
        rate_limits: dict[str, int] | None = None,
        features: list[str] | None = None,
    ):
        """Initialize channel configuration.

        Args:
            channel: Notification channel
            provider: Provider name (e.g., "sendgrid", "twilio", "firebase")
            settings: Provider-specific settings
            credentials: Encrypted credentials (keys should be encrypted)
            rate_limits: Rate limiting configuration
            features: List of enabled features
        """
        super().__init__()

        self.channel = channel
        self.provider = provider.lower().strip()
        self.settings = settings or {}
        self.credentials = credentials or {}
        self.rate_limits = rate_limits or {}
        self.features = features or []

        self._validate_config()
        self._freeze()

    def _validate_config(self) -> None:
        """Validate configuration based on channel requirements."""
        # Validate provider
        if not self.provider:
            raise ValidationError("Provider name is required")

        # Channel-specific validation
        if self.channel == NotificationChannel.EMAIL:
            self._validate_email_config()
        elif self.channel == NotificationChannel.SMS:
            self._validate_sms_config()
        elif self.channel == NotificationChannel.PUSH:
            self._validate_push_config()

    def _validate_email_config(self) -> None:
        """Validate email channel configuration."""
        required_settings = ["from_email", "from_name"]
        for setting in required_settings:
            if setting not in self.settings:
                raise ValidationError(
                    f"Email config missing required setting: {setting}"
                )

        # Validate from_email
        from_email = self.settings["from_email"]
        if not re.match(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", from_email
        ):
            raise ValidationError(f"Invalid from_email: {from_email}")

    def _validate_sms_config(self) -> None:
        """Validate SMS channel configuration."""
        if "from_number" not in self.settings:
            raise ValidationError("SMS config missing required setting: from_number")

    def _validate_push_config(self) -> None:
        """Validate push notification configuration."""
        if self.provider == "firebase" and "project_id" not in self.settings:
            raise ValidationError(
                "Firebase config missing required setting: project_id"
            )

    def get_rate_limit(self, limit_type: str = "per_second") -> int | None:
        """Get rate limit for specific type."""
        return self.rate_limits.get(limit_type)

    def has_feature(self, feature: str) -> bool:
        """Check if a feature is enabled."""
        return feature in self.features

    def __str__(self) -> str:
        """String representation."""
        return f"{self.channel.value} via {self.provider}"


class NotificationPriorityValue(ValueObject):
    """Encapsulates notification priority with associated rules."""

    def __init__(
        self,
        level: NotificationPriority,
        reason: str | None = None,
        expires_at: datetime | None = None,
        escalation_rules: dict[str, Any] | None = None,
    ):
        """Initialize notification priority.

        Args:
            level: Priority level
            reason: Reason for priority assignment
            expires_at: When this priority expires
            escalation_rules: Rules for priority escalation
        """
        super().__init__()

        self.level = level
        self.reason = reason
        self.expires_at = expires_at
        self.escalation_rules = escalation_rules or {}

        self._validate_priority()
        self._freeze()

    def _validate_priority(self) -> None:
        """Validate priority settings."""
        if self.expires_at and self.expires_at < datetime.utcnow():
            raise ValidationError("Priority expiration must be in the future")

    def should_escalate(self, current_time: datetime) -> bool:
        """Check if priority should be escalated based on rules."""
        if not self.escalation_rules:
            return False

        # Check time-based escalation
        if "escalate_after_minutes" in self.escalation_rules:
            self.escalation_rules["escalate_after_minutes"]
            # This would need the notification creation time to properly implement
            # For now, return False
            return False

        return False

    def get_next_level(self) -> NotificationPriority | None:
        """Get next priority level for escalation."""
        escalation_map = {
            NotificationPriority.LOW: NotificationPriority.NORMAL,
            NotificationPriority.NORMAL: NotificationPriority.HIGH,
            NotificationPriority.HIGH: NotificationPriority.URGENT,
            NotificationPriority.URGENT: None,
        }
        return escalation_map.get(self.level)

    def __str__(self) -> str:
        """String representation."""
        return f"{self.level.value} priority"


class DeliveryStatusValue(ValueObject):
    """Encapsulates delivery status with metadata."""

    def __init__(
        self,
        status: DeliveryStatus,
        timestamp: datetime,
        details: str | None = None,
        provider_message_id: str | None = None,
        provider_status: str | None = None,
        error_code: str | None = None,
        retry_count: int = 0,
    ):
        """Initialize delivery status.

        Args:
            status: Current delivery status
            timestamp: When this status was recorded
            details: Human-readable status details
            provider_message_id: Message ID from provider
            provider_status: Raw status from provider
            error_code: Error code if failed
            retry_count: Number of retries attempted
        """
        super().__init__()

        self.status = status
        self.timestamp = timestamp
        self.details = details
        self.provider_message_id = provider_message_id
        self.provider_status = provider_status
        self.error_code = error_code
        self.retry_count = retry_count

        self._validate_status()
        self._freeze()

    def _validate_status(self) -> None:
        """Validate status values."""
        if self.retry_count < 0:
            raise ValidationError("Retry count cannot be negative")

        if self.retry_count > 100:
            raise ValidationError("Retry count exceeds maximum limit")

    def can_retry(self, max_retries: int) -> bool:
        """Check if delivery can be retried."""
        return self.status.is_retryable() and self.retry_count < max_retries

    def with_retry(self) -> "DeliveryStatusValue":
        """Create new status for retry attempt."""
        return DeliveryStatusValue(
            status=DeliveryStatus.QUEUED,
            timestamp=datetime.utcnow(),
            details=f"Retry attempt {self.retry_count + 1}",
            retry_count=self.retry_count + 1,
        )

    def __str__(self) -> str:
        """String representation."""
        return f"{self.status.value} at {self.timestamp.isoformat()}"


class TemplateVariable(ValueObject):
    """Represents a template variable definition."""

    def __init__(
        self,
        name: str,
        var_type: VariableType,
        required: bool = True,
        default_value: Any | None = None,
        description: str | None = None,
        format_pattern: str | None = None,
        validation_rules: dict[str, Any] | None = None,
    ):
        """Initialize template variable.

        Args:
            name: Variable name
            var_type: Variable data type
            required: Whether variable is required
            default_value: Default value if not provided
            description: Variable description
            format_pattern: Format pattern for display
            validation_rules: Additional validation rules
        """
        super().__init__()

        self.validate_not_empty(name, "name")

        self.name = name.strip()
        self.var_type = var_type
        self.required = required
        self.default_value = default_value
        self.description = description
        self.format_pattern = format_pattern
        self.validation_rules = validation_rules or {}

        self._validate_variable()
        self._freeze()

    def _validate_variable(self) -> None:
        """Validate variable definition."""
        # Validate variable name format
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", self.name):
            raise ValidationError(f"Invalid variable name: {self.name}")

        # Validate default value matches type
        if self.default_value is not None:
            if not self.var_type.validate_value(self.default_value):
                raise ValidationError(
                    f"Default value does not match type {self.var_type.value}"
                )

    def validate_value(self, value: Any) -> bool:
        """Validate a value against this variable definition."""
        # Check required
        if value is None:
            return not self.required or self.default_value is not None

        # Check type
        if not self.var_type.validate_value(value):
            return False

        # Apply custom validation rules
        if "min_length" in self.validation_rules and isinstance(value, str):
            if len(value) < self.validation_rules["min_length"]:
                return False

        if "max_length" in self.validation_rules and isinstance(value, str):
            if len(value) > self.validation_rules["max_length"]:
                return False

        if "min_value" in self.validation_rules and isinstance(value, int | float):
            if value < self.validation_rules["min_value"]:
                return False

        if "max_value" in self.validation_rules and isinstance(value, int | float):
            if value > self.validation_rules["max_value"]:
                return False

        if "pattern" in self.validation_rules and isinstance(value, str):
            if not re.match(self.validation_rules["pattern"], value):
                return False

        return True

    def format_value(self, value: Any) -> str:
        """Format value according to variable rules."""
        if value is None:
            value = self.default_value

        if value is None:
            return ""

        # Apply format pattern if provided
        if self.format_pattern:
            try:
                return self.format_pattern.format(value)
            except:
                pass

        # Default formatting based on type
        if self.var_type == VariableType.CURRENCY:
            return f"${value:,.2f}"
        if self.var_type == VariableType.DATE:
            # Assuming ISO format input
            return value.split("T")[0] if "T" in value else value
        if self.var_type == VariableType.DATETIME:
            return value.replace("T", " ").replace("Z", " UTC")

        return str(value)

    def __str__(self) -> str:
        """String representation."""
        return f"{self.name} ({self.var_type.value})"


# Export all value objects
__all__ = [
    "ChannelConfig",
    "DeliveryStatusValue",
    "NotificationContent",
    "NotificationPriorityValue",
    "RecipientAddress",
    "TemplateVariable",
]
