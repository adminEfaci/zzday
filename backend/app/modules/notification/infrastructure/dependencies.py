"""Notification module dependency configuration."""

from app.core.dependencies import Container, RegistrationRequest
from app.core.enums import ServiceLifetime


async def configure_notification_dependencies(container: Container) -> None:
    """Configure notification module dependencies in the main container.

    Args:
        container: Dependency injection container
    """
    
    # Try to import and register notification services with fallbacks
    try:
        # Core notification services
        from app.modules.notification.domain.interfaces.repositories import (
            INotificationRepository,
        )
        from app.modules.notification.infrastructure.repositories.notification_repository import (
            NotificationRepository,
        )
        
        await container.register(RegistrationRequest(
            interface=INotificationRepository,
            implementation=NotificationRepository,
            lifetime=ServiceLifetime.SINGLETON,
            name="notification_repository",
            description="Notification data repository implementation"
        ))
        
    except ImportError:
        # Fallback registration for missing implementations
        await container.register(RegistrationRequest(
            interface=type('INotificationRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="notification_repository_placeholder"
        ))

    try:
        # Notification services
        from app.modules.notification.application.services.notification_service import (
            NotificationService,
        )
        from app.modules.notification.domain.interfaces.services import (
            INotificationService,
        )
        
        await container.register(RegistrationRequest(
            interface=INotificationService,
            implementation=NotificationService,
            lifetime=ServiceLifetime.SINGLETON,
            name="notification_service",
            description="Notification delivery service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('INotificationService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="notification_service_placeholder"
        ))

    try:
        # Email notification services
        from app.modules.notification.application.services.email_service import (
            EmailService,
        )
        from app.modules.notification.domain.interfaces.services import IEmailService
        
        await container.register(RegistrationRequest(
            interface=IEmailService,
            implementation=EmailService,
            lifetime=ServiceLifetime.SINGLETON,
            name="email_service",
            description="Email notification delivery service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IEmailService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="email_service_placeholder"
        ))

    try:
        # Push notification services
        from app.modules.notification.application.services.push_service import (
            PushService,
        )
        from app.modules.notification.domain.interfaces.services import IPushService
        
        await container.register(RegistrationRequest(
            interface=IPushService,
            implementation=PushService,
            lifetime=ServiceLifetime.SINGLETON,
            name="push_service",
            description="Push notification delivery service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IPushService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="push_service_placeholder"
        ))
