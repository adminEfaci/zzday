"""
EzzDay Event System - Production-Ready Cross-Module Event Communication

This module provides a comprehensive event-driven architecture for the EzzDay backend,
implementing Domain-Driven Design principles with PostgreSQL persistence, Redis distribution,
and robust cross-module communication.

Architecture Overview:
=====================

Event Flow:
Identity Module → Audit Module (user actions, security events)
Identity Module → Notification Module (user registration, password changes)
Integration Module → Audit Module (external API calls, webhook processing)
All Modules → Audit Module (compliance and security auditing)

Key Components:
- Event Bus: Hybrid in-memory/distributed processing with Redis fallback
- Event Store: PostgreSQL-based persistence with compression and encryption
- Event Registry: Dynamic event registration with priority and routing
- Cross-Module Orchestrator: Coordinates event flow between modules
- Serialization: PostgreSQL-optimized with JSONB support
- Docker Integration: Container-native configuration and health checks

Features:
- At-least-once delivery semantics
- Automatic retry with exponential backoff
- Dead letter queue for failed events
- Event compression for large payloads
- Optional encryption for sensitive events
- Comprehensive audit trails
- Performance monitoring and metrics
- Health checks and graceful degradation
"""

from datetime import datetime

from app.core.events.bus import HybridEventBus, InMemoryEventBus
from app.core.events.cross_module import (
    CrossModuleEventOrchestrator,
    create_cross_module_event_system,
)
from app.core.events.docker_config import (
    DockerEventSystemConfig,
    event_system_health_check,
    initialize_docker_event_system,
)
from app.core.events.registry import EventRegistry, get_registry
from app.core.events.serialization import (
    PostgreSQLEventSerializer,
    create_postgresql_serializer,
)
from app.core.events.types import DomainEvent, EventFactory, EventMetadata, IEventBus
from app.core.logging import get_logger

logger = get_logger(__name__)

# Global event system instance for application lifecycle
_global_event_system: CrossModuleEventOrchestrator | None = None


async def initialize_production_event_system(
    redis_url: str | None = None,
    enable_postgresql: bool = True,
    config_override: dict | None = None
) -> CrossModuleEventOrchestrator:
    """
    Initialize production-ready event system for EzzDay backend.
    
    This is the main entry point for initializing the complete event system
    with PostgreSQL persistence, Redis distribution, and cross-module handlers.
    
    Args:
        redis_url: Redis URL for distributed processing (auto-detected in Docker)
        enable_postgresql: Enable PostgreSQL event persistence
        config_override: Override configuration values
        
    Returns:
        CrossModuleEventOrchestrator: Initialized event system
        
    Raises:
        ConfigurationError: If initialization fails
        
    Example:
        # Docker environment (auto-configured)
        event_system = await initialize_production_event_system()
        
        # Manual configuration
        event_system = await initialize_production_event_system(
            redis_url="redis://localhost:6379/0",
            enable_postgresql=True
        )
    """
    global _global_event_system
    
    if _global_event_system is not None:
        logger.warning("Event system already initialized, returning existing instance")
        return _global_event_system
    
    logger.info(
        "Initializing production event system",
        redis_url=bool(redis_url),
        postgresql=enable_postgresql,
        config_override=bool(config_override)
    )
    
    try:
        # Try Docker initialization first
        if not redis_url and not config_override:
            try:
                _global_event_system = await initialize_docker_event_system()
                logger.info("Event system initialized with Docker configuration")
                return _global_event_system
            except Exception as e:
                logger.warning(f"Docker initialization failed, falling back to manual: {e}")
        
        # Manual initialization
        _global_event_system = await create_cross_module_event_system(
            redis_url=redis_url,
            enable_postgresql_persistence=enable_postgresql,
            fallback_to_memory=True
        )
        
        logger.info("Event system initialized with manual configuration")
        return _global_event_system
        
    except Exception as e:
        logger.exception("Failed to initialize production event system", error=str(e))
        raise


async def get_event_system() -> CrossModuleEventOrchestrator:
    """
    Get the global event system instance.
    
    Returns:
        CrossModuleEventOrchestrator: Global event system
        
    Raises:
        RuntimeError: If event system not initialized
    """
    global _global_event_system
    
    if _global_event_system is None:
        raise RuntimeError(
            "Event system not initialized. Call initialize_production_event_system() first."
        )
    
    return _global_event_system


async def shutdown_event_system() -> None:
    """
    Shutdown the global event system gracefully.
    
    This should be called during application shutdown to ensure
    proper cleanup of resources and event processing completion.
    """
    global _global_event_system
    
    if _global_event_system is not None:
        logger.info("Shutting down global event system")
        await _global_event_system.shutdown()
        _global_event_system = None
        logger.info("Global event system shutdown completed")
    else:
        logger.debug("No global event system to shutdown")


# High-level convenience functions
async def publish_event(event: DomainEvent, correlation_id: str | None = None) -> None:
    """
    Publish an event using the global event system.
    
    Args:
        event: Domain event to publish
        correlation_id: Optional correlation ID for tracing
        
    Raises:
        RuntimeError: If event system not initialized
    """
    event_system = await get_event_system()
    await event_system.event_bus.publish(event, correlation_id)


def subscribe_to_event(
    event_type: type[DomainEvent],
    handler,
    scope: str = "global"
) -> None:
    """
    Subscribe to an event type using the global event system.
    
    Args:
        event_type: Event class to subscribe to
        handler: Event handler function
        scope: Handler scope (for lifecycle management)
        
    Raises:
        RuntimeError: If event system not initialized
    """
    import asyncio
    
    async def _subscribe():
        event_system = await get_event_system()
        event_system.event_bus.subscribe(event_type, handler)
    
    # Handle sync context
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Schedule for later
            loop.create_task(_subscribe())
        else:
            loop.run_until_complete(_subscribe())
    except RuntimeError:
        # No event loop, create new one
        asyncio.run(_subscribe())


# Event system status and health
async def get_event_system_status() -> dict:
    """
    Get comprehensive event system status and statistics.
    
    Returns:
        dict: Event system status including health, performance, and statistics
    """
    try:
        event_system = await get_event_system()
        
        # Get orchestrator statistics
        orchestrator_stats = event_system.get_registration_statistics()
        
        # Get event bus statistics
        bus_stats = {}
        if hasattr(event_system.event_bus, 'get_statistics'):
            bus_stats = event_system.event_bus.get_statistics()
        
        # Get registry statistics
        registry = get_registry()
        registry_stats = registry.get_statistics()
        
        # Combine all statistics
        return {
            "status": "healthy",
            "initialized": True,
            "orchestrator": orchestrator_stats,
            "event_bus": bus_stats,
            "registry": registry_stats,
            "timestamp": str(datetime.now())
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "initialized": _global_event_system is not None,
            "error": str(e),
            "timestamp": str(datetime.now())
        }


# Register system event types for proper event reconstruction
def _register_system_events():
    """Register core system events with the event factory."""
    try:
        from app.core.events.types import ApplicationStarted, ApplicationStopping, SystemEvent
        
        EventFactory.register_event_type(SystemEvent)
        EventFactory.register_event_type(ApplicationStarted)
        EventFactory.register_event_type(ApplicationStopping)
        
        logger.debug("Core system events registered with EventFactory")
        
    except Exception as e:
        logger.warning(f"Failed to register system events: {e}")


def _register_module_events():
    """Register module events with the event factory."""
    try:
        # Register Identity events
        from app.modules.identity.domain.entities.user.user_events import (
            LoginFailed,
            LoginSuccessful,
            PasswordChanged,
            UserCreated,
            UserDeleted,
            UserUpdated
        )
        
        events_to_register = [
            UserCreated, UserUpdated, UserDeleted, PasswordChanged,
            LoginSuccessful, LoginFailed
        ]
        
        for event_class in events_to_register:
            EventFactory.register_event_type(event_class)
        
        logger.debug(f"Registered {len(events_to_register)} Identity events")
        
        # Register Audit events
        from app.modules.audit.domain.events.audit_events import (
            AuditEntryRecorded,
            AuditReportGenerated,
            HighRiskAuditDetected
        )
        
        audit_events = [AuditEntryRecorded, AuditReportGenerated, HighRiskAuditDetected]
        
        for event_class in audit_events:
            EventFactory.register_event_type(event_class)
        
        logger.debug(f"Registered {len(audit_events)} Audit events")
        
        # Register Integration events
        from app.modules.integration.domain.events.webhook_events import (
            WebhookFailed,
            WebhookProcessed,
            WebhookReceived
        )
        
        integration_events = [WebhookReceived, WebhookProcessed, WebhookFailed]
        
        for event_class in integration_events:
            EventFactory.register_event_type(event_class)
        
        logger.debug(f"Registered {len(integration_events)} Integration events")
        
    except ImportError as e:
        logger.warning(f"Some module events not available for registration: {e}")
    except Exception as e:
        logger.exception(f"Failed to register module events: {e}")


# Initialize event registration on module import
_register_system_events()
_register_module_events()

# Public API exports
__all__ = [
    # Main initialization
    "initialize_production_event_system",
    "get_event_system", 
    "shutdown_event_system",
    
    # High-level convenience
    "publish_event",
    "subscribe_to_event",
    "get_event_system_status",
    
    # Core components (for advanced usage)
    "CrossModuleEventOrchestrator",
    "HybridEventBus",
    "InMemoryEventBus",
    "PostgreSQLEventSerializer",
    "EventRegistry",
    "DomainEvent",
    "EventMetadata",
    "IEventBus",
    
    # Docker integration
    "DockerEventSystemConfig",
    "event_system_health_check",
    
    # Factory functions
    "create_cross_module_event_system",
    "create_postgresql_serializer",
]

logger.info(
    "EzzDay Event System initialized",
    version="1.0.0",
    components=len(__all__),
    features=[
        "PostgreSQL persistence",
        "Redis distribution", 
        "Cross-module communication",
        "Event compression",
        "Audit trails",
        "Docker integration"
    ]
)
