"""Notification infrastructure layer.

This module contains the infrastructure implementations for the notification domain,
including repositories, database models, channel adapters, template engines, and
infrastructure services.
"""

from app.modules.notification.infrastructure.adapters import (
    EmailChannelAdapter,
    InAppChannelAdapter,
    PushChannelAdapter,
    SMSChannelAdapter,
)
from app.modules.notification.infrastructure.engines import (
    JinjaTemplateEngine,
    TemplateCache,
)
from app.modules.notification.infrastructure.repositories import (
    NotificationBatchRepository,
    NotificationRepository,
    NotificationTemplateRepository,
    RecipientRepository,
    ScheduleRepository,
)
from app.modules.notification.infrastructure.services import (
    DeliveryTrackingService,
    QueueService,
    RateLimitingService,
    SchedulerService,
)

__all__ = [
    "DeliveryTrackingService",
    # Channel Adapters
    "EmailChannelAdapter",
    "InAppChannelAdapter",
    # Template Engines
    "JinjaTemplateEngine",
    "NotificationBatchRepository",
    # Repositories
    "NotificationRepository",
    "NotificationTemplateRepository",
    "PushChannelAdapter",
    # Infrastructure Services
    "QueueService",
    "RateLimitingService",
    "RecipientRepository",
    "SMSChannelAdapter",
    "ScheduleRepository",
    "SchedulerService",
    "TemplateCache",
]
