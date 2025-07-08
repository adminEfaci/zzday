"""Notification channel adapters.

This module contains adapter implementations for various notification channels,
providing a unified interface for sending notifications through different providers.
"""

from app.modules.notification.infrastructure.adapters.base import (
    BaseChannelAdapter,
    ChannelAdapterError,
    DeliveryResult,
)
from app.modules.notification.infrastructure.adapters.email_adapter import (
    EmailChannelAdapter,
)
from app.modules.notification.infrastructure.adapters.in_app_adapter import (
    InAppChannelAdapter,
)
from app.modules.notification.infrastructure.adapters.push_adapter import (
    PushChannelAdapter,
)
from app.modules.notification.infrastructure.adapters.sms_adapter import (
    SMSChannelAdapter,
)

__all__ = [
    "BaseChannelAdapter",
    "ChannelAdapterError",
    "DeliveryResult",
    "EmailChannelAdapter",
    "InAppChannelAdapter",
    "PushChannelAdapter",
    "SMSChannelAdapter",
]
