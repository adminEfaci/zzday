"""
Integration Domain Service Interfaces

Ports for integration domain services including connector management,
data transformation, webhook handling, and API orchestration.
"""

from .integration_connector_service import IIntegrationConnectorService
from .data_mapping_service import IDataMappingService
from .webhook_service import IWebhookService
from .api_gateway_service import IApiGatewayService
from .integration_orchestration_service import IIntegrationOrchestrationService

__all__ = [
    "IIntegrationConnectorService",
    "IDataMappingService",
    "IWebhookService",
    "IApiGatewayService",
    "IIntegrationOrchestrationService",
]