"""
External adapters for Integration module.

This is the ONLY module in the system that should contain external adapters
for third-party services. All other modules must use internal adapters to
communicate through the Integration module.
"""

from .base import BaseChannelAdapter, ChannelAdapterError, DeliveryResult
from .email.email_adapter import EmailChannelAdapter
from .sms.sms_adapter import SMSChannelAdapter
from .push.push_adapter import PushChannelAdapter
from .in_app_adapter import InAppChannelAdapter

__all__ = [
    "BaseChannelAdapter",
    "ChannelAdapterError", 
    "DeliveryResult",
    "EmailChannelAdapter",
    "SMSChannelAdapter",
    "PushChannelAdapter",
    "InAppChannelAdapter",
]