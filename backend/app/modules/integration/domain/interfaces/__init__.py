"""Integration Domain Interfaces."""

from .repositories import (
    ICredentialRepository,
    IIntegrationRepository,
    IMappingRepository,
    ISyncJobRepository,
    IWebhookEndpointRepository,
)

__all__ = [
    "ICredentialRepository",
    "IIntegrationRepository",
    "IMappingRepository",
    "ISyncJobRepository",
    "IWebhookEndpointRepository",
]
