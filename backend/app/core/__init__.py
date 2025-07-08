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
from app.core.application.base import (
    DTO,
    ApplicationService,
    Request,
    Response,
    UseCase,
)

# Configuration management
from app.core.config import Settings, get_settings, settings

# CQRS components
from app.core.cqrs.base import (
    Command,
    CommandBus,
    CommandHandler,
    Query,
    QueryBus,
    QueryHandler,
)
from app.core.domain.base import AggregateRoot, DomainService, Entity, ValueObject

# Domain specifications
from app.core.domain.specification import (
    AndSpecification,
    FalseSpecification,
    NotSpecification,
    OrSpecification,
    Specification,
    TrueSpecification,
)

# Error hierarchy
from app.core.errors import (
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
from app.core.events.bus import (
    DistributedEventBus,
    EventBus,
    HybridEventBus,
    InMemoryEventBus,
    create_event_bus,
)

# Infrastructure - Repository pattern
from app.core.infrastructure.repository import (
    BaseRepository,
    CachedRepository,
    EventSourcedRepository,
)

# Security utilities
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_secret_key,
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
    # ===== DOMAIN LAYER =====
    "AggregateRoot",
    # ===== SPECIFICATIONS =====
    "AndSpecification",
    # ===== ERROR HANDLING =====
    "ApplicationError",
    "ApplicationService",
    # ===== INFRASTRUCTURE =====
    "BaseRepository",
    "CachedRepository",
    # ===== CQRS =====
    "Command",
    "CommandBus",
    "CommandHandler",
    "ConfigurationError",
    "ConflictError",
    # ===== EVENT SYSTEM =====
    "DistributedEventBus",
    "DomainError",
    "DomainService",
    "Entity",
    "EventBus",
    "EventSourcedRepository",
    "ExternalServiceError",
    "EzzDayError",
    "FalseSpecification",
    "ForbiddenError",
    "HybridEventBus",
    "InMemoryEventBus",
    "InfrastructureError",
    "NotFoundError",
    "NotSpecification",
    "OrSpecification",
    "Query",
    "QueryBus",
    "QueryHandler",
    "RateLimitError",
    "Request",
    "Response",
    # ===== CONFIGURATION =====
    "Settings",
    "Specification",
    "TrueSpecification",
    "UnauthorizedError",
    "UseCase",
    "ValidationError",
    "ValueObject",
    # ===== SECURITY =====
    "create_access_token",
    "create_event_bus",
    "create_refresh_token",
    "decode_token",
    "generate_secret_key",
    "generate_token",
    "generate_verification_code",
    "get_settings",
    "hash_password",
    "is_token_expired",
    "mask_email",
    "mask_phone",
    "settings",
    "verify_password",
]
