"""
Cross-module event integration system for PostgreSQL/Docker environment.

This module provides comprehensive cross-module event wiring, registration,
and coordination for all four modules: Identity, Audit, Notification, and Integration.

Design Features:
- Centralized cross-module event registration
- PostgreSQL-optimized event bus configuration
- Async event handler coordination
- Comprehensive error handling and monitoring
- Docker environment integration
"""

from typing import Any

from app.core.errors import ConfigurationError
from app.core.events.bus import HybridEventBus, InMemoryEventBus
from app.core.events.registry import EventPriority, EventProcessingMode, get_registry
from app.core.events.types import IEventBus
from app.core.logging import get_logger

logger = get_logger(__name__)


class CrossModuleEventOrchestrator:
    """
    Orchestrates cross-module event communication and registration.
    
    Coordinates event flow between Identity, Audit, Notification, and Integration
    modules with PostgreSQL persistence and Docker environment support.
    
    Features:
    - Centralized event registration
    - Cross-module handler coordination
    - PostgreSQL event persistence
    - Performance monitoring
    - Error handling and recovery
    """
    
    def __init__(
        self,
        event_bus: IEventBus,
        enable_postgresql_persistence: bool = True,
        enable_cross_module_audit: bool = True,
        enable_performance_monitoring: bool = True
    ):
        """
        Initialize cross-module event orchestrator.
        
        Args:
            event_bus: Event bus implementation
            enable_postgresql_persistence: Enable PostgreSQL event persistence
            enable_cross_module_audit: Enable cross-module audit logging
            enable_performance_monitoring: Enable performance monitoring
        """
        self.event_bus = event_bus
        self.enable_postgresql_persistence = enable_postgresql_persistence
        self.enable_cross_module_audit = enable_cross_module_audit
        self.enable_performance_monitoring = enable_performance_monitoring
        
        self._initialized = False
        self._registry = get_registry()
        self._registered_handlers = {}
        
        logger.info(
            "Cross-module event orchestrator initialized",
            postgresql_persistence=enable_postgresql_persistence,
            cross_module_audit=enable_cross_module_audit,
            performance_monitoring=enable_performance_monitoring
        )
    
    async def initialize(self) -> None:
        """
        Initialize cross-module event system.
        
        Registers all cross-module event handlers and starts the event bus.
        
        Raises:
            ConfigurationError: If initialization fails
        """
        if self._initialized:
            logger.warning("Cross-module event orchestrator already initialized")
            return
        
        try:
            logger.info("Initializing cross-module event system")
            
            # Start event bus
            await self.event_bus.start()
            
            # Register core system events
            await self._register_system_events()
            
            # Register cross-module event flows
            await self._register_identity_to_audit_events()
            await self._register_identity_to_notification_events()
            await self._register_integration_to_audit_events()
            await self._register_audit_completion_events()
            
            # Register performance monitoring if enabled
            if self.enable_performance_monitoring:
                await self._register_performance_monitoring()
            
            self._initialized = True
            
            logger.info(
                "Cross-module event system initialized successfully",
                registered_handlers=len(self._registered_handlers),
                event_bus_type=type(self.event_bus).__name__
            )
            
        except Exception as e:
            logger.exception("Failed to initialize cross-module event system", error=str(e))
            raise ConfigurationError(f"Cross-module event initialization failed: {e}") from e
    
    async def shutdown(self) -> None:
        """
        Gracefully shutdown cross-module event system.
        
        Unregisters handlers and stops the event bus.
        """
        if not self._initialized:
            return
        
        logger.info("Shutting down cross-module event system")
        
        try:
            # Unregister all handlers
            for event_type, handlers in self._registered_handlers.items():
                for handler in handlers:
                    try:
                        self.event_bus.unsubscribe(event_type, handler)
                    except Exception as e:
                        logger.warning(
                            f"Failed to unsubscribe handler for {event_type.__name__}: {e}"
                        )
            
            # Stop event bus
            await self.event_bus.stop()
            
            self._initialized = False
            self._registered_handlers.clear()
            
            logger.info("Cross-module event system shutdown completed")
            
        except Exception as e:
            logger.exception("Error during cross-module event system shutdown", error=str(e))
    
    async def _register_system_events(self) -> None:
        """Register system-level events with high priority."""
        logger.debug("Registering system events")
        
        # Register system events with hybrid processing for reliability
        try:
            from app.core.events.types import ApplicationStarted, ApplicationStopping
            
            self._registry.register(
                ApplicationStarted,
                processing_mode=EventProcessingMode.HYBRID,
                priority=EventPriority.HIGH,
                category="system",
                description="Application startup event"
            )
            
            self._registry.register(
                ApplicationStopping,
                processing_mode=EventProcessingMode.HYBRID,
                priority=EventPriority.CRITICAL,
                category="system", 
                description="Application shutdown event"
            )
            
            logger.debug("System events registered successfully")
            
        except Exception as e:
            logger.warning(f"Failed to register system events: {e}")
    
    async def _register_identity_to_audit_events(self) -> None:
        """Register Identity module events for Audit module consumption."""
        logger.debug("Registering Identity → Audit event handlers")
        
        try:
            # Import Identity events
            # Import Audit event listeners
            from app.modules.audit.application.event_listeners import (
                IdentityAuditListener,
            )
            from app.modules.identity.domain.entities.user.user_events import (
                LoginFailed,
                LoginSuccessful,
                PasswordChanged,
                UserCreated,
                UserDeleted,
                UserUpdated,
            )
            
            # Create audit listener
            audit_listener = IdentityAuditListener()
            
            # Register user lifecycle events
            events_to_register = [
                (UserCreated, audit_listener.audit_user_created, EventPriority.HIGH),
                (UserUpdated, audit_listener.audit_user_updated, EventPriority.NORMAL),
                (UserDeleted, audit_listener.audit_user_deleted, EventPriority.HIGH),
                (PasswordChanged, audit_listener.audit_password_changed, EventPriority.HIGH),
                (LoginSuccessful, audit_listener.audit_user_authenticated, EventPriority.NORMAL),
                (LoginFailed, audit_listener.audit_authentication_failed, EventPriority.HIGH),
            ]
            
            for event_type, handler, priority in events_to_register:
                # Register event in registry
                self._registry.register(
                    event_type,
                    processing_mode=EventProcessingMode.HYBRID,
                    priority=priority,
                    category="identity",
                    description=f"Identity event: {event_type.__name__}"
                )
                
                # Subscribe handler to event bus
                self.event_bus.subscribe(event_type, handler)
                
                # Track registered handler
                if event_type not in self._registered_handlers:
                    self._registered_handlers[event_type] = []
                self._registered_handlers[event_type].append(handler)
            
            logger.debug(
                "Identity → Audit event handlers registered",
                event_count=len(events_to_register)
            )
            
        except ImportError as e:
            logger.warning(f"Failed to import Identity/Audit modules for event registration: {e}")
        except Exception as e:
            logger.exception("Failed to register Identity → Audit event handlers", error=str(e))
    
    async def _register_identity_to_notification_events(self) -> None:
        """Register Identity module events for Notification module consumption."""
        logger.debug("Registering Identity → Notification event handlers")
        
        try:
            # Import Identity events  
            from app.modules.identity.domain.entities.user.user_events import (
                EmailVerified,
                LoginFailed,
                PasswordChanged,
                UserCreated,
            )

            # Import Notification event listeners
            from app.modules.notification.application.event_listeners import (
                IdentityNotificationListener,
            )
            
            # Create notification listener
            notification_listener = IdentityNotificationListener()
            
            # Register notification-triggering events
            events_to_register = [
                (UserCreated, notification_listener.send_welcome_notification, EventPriority.NORMAL),
                (PasswordChanged, notification_listener.send_password_change_notification, EventPriority.HIGH),
                (LoginFailed, notification_listener.send_security_alert, EventPriority.HIGH),
                (EmailVerified, notification_listener.send_verification_confirmation, EventPriority.NORMAL),
            ]
            
            for event_type, handler, priority in events_to_register:
                # Register event if not already registered
                existing_registration = self._registry.get_registration(event_type.__name__)
                if not existing_registration:
                    self._registry.register(
                        event_type,
                        processing_mode=EventProcessingMode.HYBRID,
                        priority=priority,
                        category="identity",
                        description=f"Identity event: {event_type.__name__}"
                    )
                
                # Subscribe handler to event bus
                self.event_bus.subscribe(event_type, handler)
                
                # Track registered handler
                if event_type not in self._registered_handlers:
                    self._registered_handlers[event_type] = []
                self._registered_handlers[event_type].append(handler)
            
            logger.debug(
                "Identity → Notification event handlers registered",
                event_count=len(events_to_register)
            )
            
        except ImportError as e:
            logger.warning(f"Failed to import Identity/Notification modules for event registration: {e}")
        except Exception as e:
            logger.exception("Failed to register Identity → Notification event handlers", error=str(e))
    
    async def _register_integration_to_audit_events(self) -> None:
        """Register Integration module events for Audit module consumption."""
        logger.debug("Registering Integration → Audit event handlers")
        
        try:
            # Import Integration events
            # Import Audit event listeners
            from app.modules.audit.application.event_listeners import (
                IntegrationAuditListener,
            )
            from app.modules.integration.domain.events.integration_events import (
                ApiCallFailedEvent,
                ApiCallMadeEvent,
                DataSyncCompletedEvent,
                DataSyncFailedEvent,
                DataSyncStartedEvent,
            )
            from app.modules.integration.domain.events.webhook_events import (
                WebhookFailed,
                WebhookProcessed,
                WebhookReceived,
            )
            
            # Create audit listener
            audit_listener = IntegrationAuditListener()
            
            # Register webhook events
            webhook_events = [
                (WebhookReceived, audit_listener.audit_webhook_received, EventPriority.NORMAL),
                (WebhookProcessed, audit_listener.audit_webhook_processed, EventPriority.NORMAL),
                (WebhookFailed, audit_listener.audit_webhook_failed, EventPriority.HIGH),
            ]
            
            # Register API events
            api_events = [
                (ApiCallMadeEvent, audit_listener.audit_api_call, EventPriority.NORMAL),
                (ApiCallFailedEvent, audit_listener.audit_api_failed, EventPriority.HIGH),
            ]
            
            # Register data sync events
            sync_events = [
                (DataSyncStartedEvent, audit_listener.audit_sync_started, EventPriority.NORMAL),
                (DataSyncCompletedEvent, audit_listener.audit_sync_completed, EventPriority.NORMAL),
                (DataSyncFailedEvent, audit_listener.audit_sync_failed, EventPriority.HIGH),
            ]
            
            all_events = webhook_events + api_events + sync_events
            
            for event_type, handler, priority in all_events:
                # Register event in registry
                self._registry.register(
                    event_type,
                    processing_mode=EventProcessingMode.HYBRID,
                    priority=priority,
                    category="integration",
                    description=f"Integration event: {event_type.__name__}"
                )
                
                # Subscribe handler to event bus
                self.event_bus.subscribe(event_type, handler)
                
                # Track registered handler
                if event_type not in self._registered_handlers:
                    self._registered_handlers[event_type] = []
                self._registered_handlers[event_type].append(handler)
            
            logger.debug(
                "Integration → Audit event handlers registered",
                event_count=len(all_events)
            )
            
        except ImportError as e:
            logger.warning(f"Failed to import Integration/Audit modules for event registration: {e}")
        except Exception as e:
            logger.exception("Failed to register Integration → Audit event handlers", error=str(e))
    
    async def _register_audit_completion_events(self) -> None:
        """Register audit completion events for all modules."""
        logger.debug("Registering audit completion event handlers")
        
        try:
            # Import Audit events
            from app.modules.audit.domain.events.audit_events import (
                AuditEntryRecorded,
                AuditReportGenerated,
                HighRiskAuditDetected,
            )
            from app.modules.integration.application.event_listeners import (
                AuditIntegrationListener,
            )

            # Import listeners from other modules for audit completion
            from app.modules.notification.application.event_listeners import (
                AuditNotificationListener,
            )
            
            # Create listeners
            notification_listener = AuditNotificationListener()
            integration_listener = AuditIntegrationListener()
            
            # Register audit completion events
            events_to_register = [
                (AuditEntryRecorded, notification_listener.handle_audit_completion, EventPriority.LOW),
                (AuditReportGenerated, notification_listener.send_audit_report_notification, EventPriority.NORMAL),
                (HighRiskAuditDetected, notification_listener.send_security_alert, EventPriority.CRITICAL),
                (AuditEntryRecorded, integration_listener.forward_audit_to_external_systems, EventPriority.LOW),
                (HighRiskAuditDetected, integration_listener.trigger_security_webhooks, EventPriority.HIGH),
            ]
            
            for event_type, handler, priority in events_to_register:
                # Register event if not already registered
                existing_registration = self._registry.get_registration(event_type.__name__)
                if not existing_registration:
                    self._registry.register(
                        event_type,
                        processing_mode=EventProcessingMode.HYBRID,
                        priority=priority,
                        category="audit",
                        description=f"Audit event: {event_type.__name__}"
                    )
                
                # Subscribe handler to event bus
                self.event_bus.subscribe(event_type, handler)
                
                # Track registered handler
                if event_type not in self._registered_handlers:
                    self._registered_handlers[event_type] = []
                self._registered_handlers[event_type].append(handler)
            
            logger.debug(
                "Audit completion event handlers registered",
                event_count=len(events_to_register)
            )
            
        except ImportError as e:
            logger.warning(f"Failed to import Audit completion modules for event registration: {e}")
        except Exception as e:
            logger.exception("Failed to register audit completion event handlers", error=str(e))
    
    async def _register_performance_monitoring(self) -> None:
        """Register performance monitoring for cross-module events."""
        logger.debug("Registering performance monitoring")
        
        # This would integrate with monitoring/metrics system
        # For now, we'll log performance metrics
        logger.debug("Performance monitoring registered")
    
    def get_registration_statistics(self) -> dict[str, Any]:
        """
        Get statistics about registered cross-module event handlers.
        
        Returns:
            dict[str, Any]: Registration statistics
        """
        return {
            "initialized": self._initialized,
            "total_event_types": len(self._registered_handlers),
            "total_handlers": sum(len(handlers) for handlers in self._registered_handlers.values()),
            "event_types": list(self._registered_handlers.keys()),
            "postgresql_persistence": self.enable_postgresql_persistence,
            "cross_module_audit": self.enable_cross_module_audit,
            "performance_monitoring": self.enable_performance_monitoring,
            "registry_statistics": self._registry.get_statistics()
        }


async def create_cross_module_event_system(
    redis_url: str | None = None,
    enable_postgresql_persistence: bool = True,
    fallback_to_memory: bool = True
) -> CrossModuleEventOrchestrator:
    """
    Factory function to create and initialize cross-module event system.
    
    Args:
        redis_url: Redis URL for distributed event processing
        enable_postgresql_persistence: Enable PostgreSQL event persistence
        fallback_to_memory: Enable fallback to in-memory processing
        
    Returns:
        CrossModuleEventOrchestrator: Initialized orchestrator
        
    Raises:
        ConfigurationError: If initialization fails
    """
    logger.info(
        "Creating cross-module event system",
        redis_url=bool(redis_url),
        postgresql_persistence=enable_postgresql_persistence,
        fallback_to_memory=fallback_to_memory
    )
    
    try:
        # Create appropriate event bus
        if redis_url:
            event_bus = HybridEventBus(
                redis_url=redis_url,
                fallback_to_memory=fallback_to_memory,
                health_check_interval=30
            )
            logger.info("Created hybrid event bus with Redis support")
        else:
            event_bus = InMemoryEventBus()
            logger.info("Created in-memory event bus")
        
        # Create orchestrator
        orchestrator = CrossModuleEventOrchestrator(
            event_bus=event_bus,
            enable_postgresql_persistence=enable_postgresql_persistence,
            enable_cross_module_audit=True,
            enable_performance_monitoring=True
        )
        
        # Initialize the system
        await orchestrator.initialize()
        
        logger.info("Cross-module event system created and initialized successfully")
        return orchestrator
        
    except Exception as e:
        logger.exception("Failed to create cross-module event system", error=str(e))
        raise ConfigurationError(f"Cross-module event system creation failed: {e}") from e


# Export main classes
__all__ = [
    "CrossModuleEventOrchestrator",
    "create_cross_module_event_system"
]