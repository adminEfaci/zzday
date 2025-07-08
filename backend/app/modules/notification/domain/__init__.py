"""Notification domain layer.

This layer contains the core business logic for the notification module,
including aggregates, entities, value objects, domain events, and business rules.
All components are framework-agnostic and follow pure Python principles.
"""

# Import with error handling
import warnings

# Import aggregates
try:
    from .aggregates.notification_batch import NotificationBatch
except ImportError as e:
    warnings.warn(f"NotificationBatch aggregate not available: {e}", ImportWarning, stacklevel=2)
    NotificationBatch = None

try:
    from .aggregates.notification_template import NotificationTemplate
except ImportError as e:
    warnings.warn(f"NotificationTemplate aggregate not available: {e}", ImportWarning, stacklevel=2)
    NotificationTemplate = None

# Import entities
try:
    from .entities.notification import Notification
except ImportError as e:
    warnings.warn(f"Notification entity not available: {e}", ImportWarning, stacklevel=2)
    Notification = None

try:
    from .entities.notification_channel import NotificationChannel
except ImportError as e:
    warnings.warn(f"NotificationChannel entity not available: {e}", ImportWarning, stacklevel=2)
    NotificationChannel = None

try:
    from .entities.notification_recipient import NotificationRecipient
except ImportError as e:
    warnings.warn(f"NotificationRecipient entity not available: {e}", ImportWarning, stacklevel=2)
    NotificationRecipient = None

try:
    from .entities.notification_schedule import NotificationSchedule
except ImportError as e:
    warnings.warn(f"NotificationSchedule entity not available: {e}", ImportWarning, stacklevel=2)
    NotificationSchedule = None

# Import enums with fallbacks
try:
    from .enums import (
        BatchStatus,
        ChannelStatus,
        DeliveryStatus,
        NotificationPriority,
        RecipientStatus,
        ScheduleStatus,
        TemplateType,
        VariableType,
    )
    from .enums import NotificationChannel as ChannelType
except ImportError as e:
    warnings.warn(f"Notification enums not available: {e}", ImportWarning, stacklevel=2)
    
    # Create fallback enum-like classes
    class FallbackEnum:
        def __init__(self, name):
            self.name = name
        def __str__(self):
            return self.name
    
    BatchStatus = FallbackEnum("BatchStatus")
    ChannelStatus = FallbackEnum("ChannelStatus")
    DeliveryStatus = FallbackEnum("DeliveryStatus")
    ChannelType = FallbackEnum("ChannelType")
    NotificationPriority = FallbackEnum("NotificationPriority")
    RecipientStatus = FallbackEnum("RecipientStatus")
    ScheduleStatus = FallbackEnum("ScheduleStatus")
    TemplateType = FallbackEnum("TemplateType")
    VariableType = FallbackEnum("VariableType")

# Import errors with fallbacks
try:
    from .errors import (
        BatchProcessingError,
        ChannelNotConfiguredError,
        DeliveryFailedError,
        DuplicateNotificationError,
        InvalidChannelError,
        InvalidPriorityError,
        InvalidTemplateError,
        NotificationError,
        NotificationExpiredError,
        NotificationNotFoundError,
        RateLimitExceededError,
        RecipientBlockedError,
        RecipientNotFoundError,
        ScheduleError,
        TemplateNotFoundError,
        TemplateRenderError,
        TemplateVariableError,
    )
except ImportError as e:
    warnings.warn(f"Notification errors not available: {e}", ImportWarning, stacklevel=2)
    
    # Create fallback error classes
    class NotificationError(Exception):
        """Base notification error."""
    
    class BatchProcessingError(NotificationError):
        """Batch processing error."""
    
    class ChannelNotConfiguredError(NotificationError):
        """Channel not configured error."""
    
    class DeliveryFailedError(NotificationError):
        """Delivery failed error."""
    
    class DuplicateNotificationError(NotificationError):
        """Duplicate notification error."""
    
    class InvalidChannelError(NotificationError):
        """Invalid channel error."""
    
    class InvalidPriorityError(NotificationError):
        """Invalid priority error."""
    
    class InvalidTemplateError(NotificationError):
        """Invalid template error."""
    
    class NotificationExpiredError(NotificationError):
        """Notification expired error."""
    
    class NotificationNotFoundError(NotificationError):
        """Notification not found error."""
    
    class RateLimitExceededError(NotificationError):
        """Rate limit exceeded error."""
    
    class RecipientBlockedError(NotificationError):
        """Recipient blocked error."""
    
    class RecipientNotFoundError(NotificationError):
        """Recipient not found error."""
    
    class ScheduleError(NotificationError):
        """Schedule error."""
    
    class TemplateNotFoundError(NotificationError):
        """Template not found error."""
    
    class TemplateRenderError(NotificationError):
        """Template render error."""
    
    class TemplateVariableError(NotificationError):
        """Template variable error."""

# Import events with fallbacks
try:
    from .events import (
        BatchCreated,
        BatchProcessed,
        ChannelConfigured,
        ChannelDisabled,
        NotificationCreated,
        NotificationDelivered,
        NotificationFailed,
        NotificationRead,
        NotificationScheduled,
        NotificationSent,
        RecipientResubscribed,
        RecipientUnsubscribed,
        TemplateCreated,
        TemplateDeleted,
        TemplateUpdated,
    )
except ImportError as e:
    warnings.warn(f"Notification events not available: {e}", ImportWarning, stacklevel=2)
    
    # Create fallback event classes
    class FallbackEvent:
        def __init__(self, *args, **kwargs):
            pass
    
    BatchCreated = BatchProcessed = ChannelConfigured = ChannelDisabled = FallbackEvent
    NotificationCreated = NotificationDelivered = NotificationFailed = FallbackEvent
    NotificationRead = NotificationScheduled = NotificationSent = FallbackEvent
    RecipientResubscribed = RecipientUnsubscribed = FallbackEvent
    TemplateCreated = TemplateDeleted = TemplateUpdated = FallbackEvent

# Import value objects with fallbacks
try:
    from .value_objects import (
        ChannelConfig,
        DeliveryStatusValue,
        NotificationContent,
        NotificationPriorityValue,
        RecipientAddress,
        TemplateVariable,
    )
except ImportError as e:
    warnings.warn(f"Notification value objects not available: {e}", ImportWarning, stacklevel=2)
    
    # Create fallback value object classes
    class FallbackValueObject:
        def __init__(self, *args, **kwargs):
            pass
    
    ChannelConfig = DeliveryStatusValue = NotificationContent = FallbackValueObject
    NotificationPriorityValue = RecipientAddress = TemplateVariable = FallbackValueObject

__all__ = [
    "BatchCreated",
    "BatchProcessed",
    "BatchProcessingError",
    "BatchStatus",
    "ChannelConfig",
    "ChannelConfigured",
    "ChannelDisabled",
    "ChannelNotConfiguredError",
    "ChannelStatus",
    # Enums
    "ChannelType",
    "DeliveryFailedError",
    "DeliveryStatus",
    "DeliveryStatusValue",
    "DuplicateNotificationError",
    "InvalidChannelError",
    "InvalidPriorityError",
    "InvalidTemplateError",
    # Entities
    "Notification",
    "NotificationBatch",
    "NotificationChannel",
    # Value Objects
    "NotificationContent",
    # Events
    "NotificationCreated",
    "NotificationDelivered",
    # Errors
    "NotificationError",
    "NotificationExpiredError",
    "NotificationFailed",
    "NotificationNotFoundError",
    "NotificationPriority",
    "NotificationPriorityValue",
    "NotificationRead",
    "NotificationRecipient",
    "NotificationSchedule",
    "NotificationScheduled",
    "NotificationSent",
    # Aggregates
    "NotificationTemplate",
    "RateLimitExceededError",
    "RecipientAddress",
    "RecipientBlockedError",
    "RecipientNotFoundError",
    "RecipientResubscribed",
    "RecipientStatus",
    "RecipientUnsubscribed",
    "ScheduleError",
    "ScheduleStatus",
    "TemplateCreated",
    "TemplateDeleted",
    "TemplateNotFoundError",
    "TemplateRenderError",
    "TemplateType",
    "TemplateUpdated",
    "TemplateVariable",
    "TemplateVariableError",
    "VariableType",
]
