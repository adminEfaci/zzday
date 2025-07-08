"""Integration command handlers.

This module provides command handlers for integration operations,
implementing the write side of CQRS pattern.
"""

from .connect_integration import (
    ConnectIntegrationCommand,
    ConnectIntegrationCommandHandler,
)
from .disconnect_integration import (
    DisconnectIntegrationCommand,
    DisconnectIntegrationCommandHandler,
)
from .process_webhook import ProcessWebhookCommand, ProcessWebhookCommandHandler
from .refresh_credentials import (
    RefreshCredentialsCommand,
    RefreshCredentialsCommandHandler,
)
from .start_sync import StartSyncCommand, StartSyncCommandHandler
from .update_mapping import UpdateMappingCommand, UpdateMappingCommandHandler

__all__ = [
    # Connect Integration
    "ConnectIntegrationCommand",
    "ConnectIntegrationCommandHandler",
    # Disconnect Integration
    "DisconnectIntegrationCommand",
    "DisconnectIntegrationCommandHandler",
    # Process Webhook
    "ProcessWebhookCommand",
    "ProcessWebhookCommandHandler",
    # Refresh Credentials
    "RefreshCredentialsCommand",
    "RefreshCredentialsCommandHandler",
    # Start Sync
    "StartSyncCommand",
    "StartSyncCommandHandler",
    # Update Mapping
    "UpdateMappingCommand",
    "UpdateMappingCommandHandler",
]
