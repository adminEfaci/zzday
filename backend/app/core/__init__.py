"""Core infrastructure following DDD principles and hexagonal architecture.

This module provides the core infrastructure components that implement sophisticated
Domain-Driven Design and Hexagonal Architecture patterns. All components are designed
for production use with comprehensive error handling, metrics, and monitoring.

Architecture Components:
- domain: Base domain primitives (ValueObject, Entity, AggregateRoot)
- application: Use cases and application services
- cqrs: Command Query Responsibility Segregation
- events: Event-driven architecture with multiple bus implementations
- infrastructure: Repository pattern, Unit of Work, persistence
- Cross-cutting: Security, configuration, errors, logging, monitoring

Key Features:
- Domain-driven design patterns
- Event sourcing and CQRS
- Sophisticated event bus (in-memory, distributed, hybrid)
- Repository pattern with specifications
- Comprehensive error hierarchy
- Production-ready security and configuration
"""

# Application layer
from .application.base import (
    DTO,
    ApplicationService,
    Request,
    Response,
    UseCase,
)

# Configuration management
from .config import Settings, get_settings, settings

# CQRS components
from .cqrs.base import (
    Command,
    CommandBus,
    CommandHandler,
    Query,
    QueryBus,
    QueryHandler,
)

# Domain layer
from .domain.base import AggregateRoot, DomainService, Entity, ValueObject

# Domain specifications
from .domain.specification import (
    AndSpecification,
    FalseSpecification,
    NotSpecification,
    OrSpecification,
    Specification,
    TrueSpecification,
)

# Error hierarchy
from .errors import (
    ApplicationError,
    ConfigurationError,
    ConflictError,
    DomainError,
    ExternalServiceError,
    EzzDayError,
    ForbiddenError,
    InfrastructureError,
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
    ValidationError,
)

# Event system
from .events.bus import (
    DistributedEventBus,
    EventBus,
    HybridEventBus,
    InMemoryEventBus,
    create_event_bus,
)

# Infrastructure - Repository pattern
from .infrastructure.repository import (
    BaseRepository,
    CacheableRepository,
    EventSourcedRepository,
    ReadOnlyRepository,
    Repository,
    RepositoryFactory,
    SQLRepository,
    SpecificationRepository,
)

# Security services and utilities
from .security import (
    CryptographyService,
    MaskingService,
    PasswordService,
    SecurityAuditService,
    SecurityService,
    TokenService,
    create_security_service,
    # Backward compatibility functions
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_secret_key,
    generate_secure_key,
    generate_token,
    generate_verification_code,
    hash_password,
    is_token_expired,
    mask_email,
    mask_phone,
    verify_password,
)

__all__ = [
    # ===== APPLICATION LAYER =====
    "DTO",
    "ApplicationService",
    "Request",
    "Response",
    "UseCase",
    
    # ===== CONFIGURATION =====
    "Settings",
    "get_settings",
    "settings",
    
    # ===== CQRS =====
    "Command",
    "CommandBus",
    "CommandHandler",
    "Query",
    "QueryBus",
    "QueryHandler",
    
    # ===== DOMAIN LAYER =====
    "AggregateRoot",
    "DomainService",
    "Entity",
    "ValueObject",
    
    # ===== SPECIFICATIONS =====
    "AndSpecification",
    "FalseSpecification",
    "NotSpecification",
    "OrSpecification",
    "Specification",
    "TrueSpecification",
    
    # ===== ERROR HANDLING =====
    "ApplicationError",
    "ConfigurationError",
    "ConflictError",
    "DomainError",
    "ExternalServiceError",
    "EzzDayError",
    "ForbiddenError",
    "InfrastructureError",
    "NotFoundError",
    "RateLimitError",
    "UnauthorizedError",
    "ValidationError",
    
    # ===== EVENT SYSTEM =====
    "DistributedEventBus",
    "EventBus",
    "HybridEventBus",
    "InMemoryEventBus",
    "create_event_bus",
    
    # ===== INFRASTRUCTURE =====
    "BaseRepository",
    "CacheableRepository",
    "EventSourcedRepository",
    "ReadOnlyRepository",
    "Repository",
    "RepositoryFactory",
    "SQLRepository",
    "SpecificationRepository",
    
    # ===== SECURITY SERVICES =====
    "CryptographyService",
    "MaskingService",
    "PasswordService",
    "SecurityAuditService",
    "SecurityService",
    "TokenService",
    "create_security_service",
    
    # ===== SECURITY UTILITIES (Backward Compatibility) =====
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "generate_secret_key",
    "generate_secure_key",
    "generate_token",
    "generate_verification_code",
    "hash_password",
    "is_token_expired",
    "mask_email",
    "mask_phone",
    "verify_password",
]
