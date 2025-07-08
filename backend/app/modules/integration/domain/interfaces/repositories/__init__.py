"""Repository interfaces for Integration module."""

from .credential_repository import ICredentialRepository
from .integration_repository import IIntegrationRepository
from .mapping_repository import IMappingRepository
from .sync_job_repository import ISyncJobRepository
from .webhook_endpoint_repository import IWebhookEndpointRepository

__all__ = [
    "ICredentialRepository",
    "IIntegrationRepository",
    "IMappingRepository",
    "ISyncJobRepository",
    "IWebhookEndpointRepository",
]
