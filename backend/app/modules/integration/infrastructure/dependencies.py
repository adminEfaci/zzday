"""Integration module dependency configuration."""

from app.core.dependencies import Container, RegistrationRequest
from app.core.enums import ServiceLifetime


async def configure_integration_dependencies(container: Container) -> None:
    """Configure integration module dependencies in the main container.

    Args:
        container: Dependency injection container
    """
    
    # Try to import and register integration services with fallbacks
    try:
        # Core integration services
        from app.modules.integration.domain.interfaces.repositories import IIntegrationRepository
        from app.modules.integration.infrastructure.repositories.integration_repository import IntegrationRepository
        
        await container.register(RegistrationRequest(
            interface=IIntegrationRepository,
            implementation=IntegrationRepository,
            lifetime=ServiceLifetime.SINGLETON,
            name="integration_repository",
            description="Integration data repository implementation"
        ))
        
    except ImportError:
        # Fallback registration for missing implementations
        await container.register(RegistrationRequest(
            interface=type('IIntegrationRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="integration_repository_placeholder"
        ))

    try:
        # Integration orchestration services
        from app.modules.integration.domain.interfaces.services import IIntegrationService
        from app.modules.integration.application.services.integration_service import IntegrationService
        
        await container.register(RegistrationRequest(
            interface=IIntegrationService,
            implementation=IntegrationService,
            lifetime=ServiceLifetime.SINGLETON,
            name="integration_service",
            description="Integration orchestration service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IIntegrationService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="integration_service_placeholder"
        ))

    try:
        # API client services
        from app.modules.integration.application.services.api_client_service import ApiClientService
        from app.modules.integration.domain.interfaces.services import IApiClientService
        
        await container.register(RegistrationRequest(
            interface=IApiClientService,
            implementation=ApiClientService,
            lifetime=ServiceLifetime.SINGLETON,
            name="api_client_service",
            description="External API client service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IApiClientService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="api_client_service_placeholder"
        ))

    try:
        # Webhook services
        from app.modules.integration.application.services.webhook_service import WebhookService
        from app.modules.integration.domain.interfaces.services import IWebhookService
        
        await container.register(RegistrationRequest(
            interface=IWebhookService,
            implementation=WebhookService,
            lifetime=ServiceLifetime.SINGLETON,
            name="webhook_service",
            description="Webhook handling service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IWebhookService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="webhook_service_placeholder"
        ))
