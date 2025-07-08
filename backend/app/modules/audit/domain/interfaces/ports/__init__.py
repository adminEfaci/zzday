"""Audit domain port interfaces."""

from app.modules.audit.domain.interfaces.ports.identity_port import IIdentityPort
from app.modules.audit.domain.interfaces.ports.notification_port import (
    INotificationPort,
)

__all__ = [
    "IIdentityPort",
    "INotificationPort",
]
