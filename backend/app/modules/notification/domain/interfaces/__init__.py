"""Notification domain interfaces."""

from app.modules.notification.domain.interfaces.repositories import (
    INotificationBatchRepository,
    INotificationRecipientRepository,
    INotificationRepository,
    INotificationScheduleRepository,
    INotificationTemplateRepository,
)

__all__ = [
    "INotificationBatchRepository",
    "INotificationRecipientRepository",
    "INotificationRepository",
    "INotificationScheduleRepository",
    "INotificationTemplateRepository",
]
