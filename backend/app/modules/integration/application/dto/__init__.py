"""Integration application DTOs.

This module provides Data Transfer Objects for the Integration application layer,
ensuring clean data transfer between layers without exposing domain internals.
"""

from .credential_dto import CredentialCreateDTO, CredentialDTO, CredentialUpdateDTO
from .health_dto import HealthCheckResultDTO, IntegrationHealthDTO, SystemStatusDTO
from .integration_dto import (
    IntegrationConfigDTO,
    IntegrationDetailDTO,
    IntegrationListItemDTO,
)
from .mapping_dto import FieldMappingDTO, MappingConfigDTO, MappingValidationResultDTO
from .sync_dto import SyncJobDTO, SyncResultDTO, SyncStatusDTO
from .webhook_dto import WebhookEventDTO, WebhookHistoryDTO, WebhookPayloadDTO

__all__ = [
    "CredentialCreateDTO",
    # Credential DTOs
    "CredentialDTO",
    "CredentialUpdateDTO",
    "FieldMappingDTO",
    "HealthCheckResultDTO",
    # Integration DTOs
    "IntegrationConfigDTO",
    "IntegrationDetailDTO",
    # Health DTOs
    "IntegrationHealthDTO",
    "IntegrationListItemDTO",
    # Mapping DTOs
    "MappingConfigDTO",
    "MappingValidationResultDTO",
    "SyncJobDTO",
    "SyncResultDTO",
    # Sync DTOs
    "SyncStatusDTO",
    "SystemStatusDTO",
    "WebhookEventDTO",
    "WebhookHistoryDTO",
    # Webhook DTOs
    "WebhookPayloadDTO",
]
