"""Integration query handlers.

This module provides query handlers for integration read operations,
implementing the read side of CQRS pattern.
"""

from .get_integration import GetIntegrationQuery, GetIntegrationQueryHandler
from .get_integration_health import (
    GetIntegrationHealthQuery,
    GetIntegrationHealthQueryHandler,
)
from .get_mappings import GetMappingsQuery, GetMappingsQueryHandler
from .get_sync_status import GetSyncStatusQuery, GetSyncStatusQueryHandler
from .get_webhook_history import GetWebhookHistoryQuery, GetWebhookHistoryQueryHandler
from .list_integrations import ListIntegrationsQuery, ListIntegrationsQueryHandler

__all__ = [
    # Get Integration Health
    "GetIntegrationHealthQuery",
    "GetIntegrationHealthQueryHandler",
    # Get Integration
    "GetIntegrationQuery",
    "GetIntegrationQueryHandler",
    # Get Mappings
    "GetMappingsQuery",
    "GetMappingsQueryHandler",
    # Get Sync Status
    "GetSyncStatusQuery",
    "GetSyncStatusQueryHandler",
    # Get Webhook History
    "GetWebhookHistoryQuery",
    "GetWebhookHistoryQueryHandler",
    # List Integrations
    "ListIntegrationsQuery",
    "ListIntegrationsQueryHandler",
]
