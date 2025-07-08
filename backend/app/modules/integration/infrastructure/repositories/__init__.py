"""Integration infrastructure repositories.

This module provides repository implementations for the Integration domain.
"""

from app.modules.integration.infrastructure.repositories.credential import (
    CredentialRepository,
)
from app.modules.integration.infrastructure.repositories.integration import (
    IntegrationRepository,
)
from app.modules.integration.infrastructure.repositories.mapping import (
    MappingRepository,
)
from app.modules.integration.infrastructure.repositories.sync_job import (
    SyncJobRepository,
)
from app.modules.integration.infrastructure.repositories.webhook_endpoint import (
    WebhookEndpointRepository,
)

__all__ = [
    "CredentialRepository",
    "IntegrationRepository",
    "MappingRepository",
    "SyncJobRepository",
    "WebhookEndpointRepository",
]
