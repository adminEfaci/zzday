"""Notification infrastructure database models.

This module contains SQLAlchemy models for persisting notification domain entities
and aggregates to the database.
"""

from app.modules.notification.infrastructure.models.delivery_log import DeliveryLogModel
from app.modules.notification.infrastructure.models.notification import (
    NotificationModel,
)
from app.modules.notification.infrastructure.models.notification_batch import (
    NotificationBatchModel,
)
from app.modules.notification.infrastructure.models.notification_template import (
    NotificationTemplateModel,
)
from app.modules.notification.infrastructure.models.recipient import RecipientModel
from app.modules.notification.infrastructure.models.schedule import ScheduleModel

__all__ = [
    "DeliveryLogModel",
    "NotificationBatchModel",
    "NotificationModel",
    "NotificationTemplateModel",
    "RecipientModel",
    "ScheduleModel",
]
