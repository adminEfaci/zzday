"""Audit module dependency configuration."""

from app.core.dependencies import Container, RegistrationRequest
from app.core.enums import ServiceLifetime


async def configure_audit_dependencies(container: Container) -> None:
    """Configure audit module dependencies in the main container.

    Args:
        container: Dependency injection container
    """
    
    # Try to import and register audit services with fallbacks
    try:
        # Core audit services
        from app.modules.audit.domain.interfaces.repositories import IAuditLogRepository
        from app.modules.audit.infrastructure.repositories.audit_log_repository import AuditLogRepository
        
        await container.register(RegistrationRequest(
            interface=IAuditLogRepository,
            implementation=AuditLogRepository,
            lifetime=ServiceLifetime.SINGLETON,
            name="audit_log_repository",
            description="Audit log data repository implementation"
        ))
        
    except ImportError:
        # Fallback registration for missing implementations
        await container.register(RegistrationRequest(
            interface=type('IAuditLogRepository', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="audit_log_repository_placeholder"
        ))

    try:
        # Audit services
        from app.modules.audit.domain.interfaces.services import IAuditService
        from app.modules.audit.application.services.audit_service import AuditService
        
        await container.register(RegistrationRequest(
            interface=IAuditService,
            implementation=AuditService,
            lifetime=ServiceLifetime.SINGLETON,
            name="audit_service",
            description="Audit logging and compliance service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IAuditService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="audit_service_placeholder"
        ))

    try:
        # Compliance services
        from app.modules.audit.application.services.compliance_service import ComplianceService
        from app.modules.audit.domain.interfaces.services import IComplianceService
        
        await container.register(RegistrationRequest(
            interface=IComplianceService,
            implementation=ComplianceService,
            lifetime=ServiceLifetime.SINGLETON,
            name="compliance_service",
            description="Compliance monitoring and reporting service"
        ))
        
    except ImportError:
        await container.register(RegistrationRequest(
            interface=type('IComplianceService', (), {}),
            implementation=lambda: None,
            lifetime=ServiceLifetime.SINGLETON,
            name="compliance_service_placeholder"
        ))
