"""Notification repository interfaces."""

from app.modules.notification.domain.interfaces.repositories.notification_batch_repository import (
    INotificationBatchRepository,
)
from app.modules.notification.domain.interfaces.repositories.notification_recipient_repository import (
    INotificationRecipientRepository,
)
from app.modules.notification.domain.interfaces.repositories.notification_repository import (
    INotificationRepository,
)
from app.modules.notification.domain.interfaces.repositories.notification_schedule_repository import (
    INotificationScheduleRepository,
)
from app.modules.notification.domain.interfaces.repositories.notification_template_repository import (
    INotificationTemplateRepository,
)

__all__ = [
    "INotificationBatchRepository",
    "INotificationRecipientRepository",
    "INotificationRepository",
    "INotificationScheduleRepository",
    "INotificationTemplateRepository",
]
