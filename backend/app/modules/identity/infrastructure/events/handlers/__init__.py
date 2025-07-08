"""
Identity Event Handlers Infrastructure

Comprehensive event handler system for processing identity domain events
with support for synchronous and asynchronous handlers, error isolation,
retry logic, and health monitoring.
"""

__all__ = [
    # Base infrastructure
    "AuditLogHandler",
    "EventHandlerBase",
    "EventHandlerDecorator",
    "EventHandlerExecutor",
    "EventHandlerRegistry",
    "HandlerExecutionContext",
    "HandlerHealthStatus",
    "HandlerMetadata",
    "HandlerMetrics",
    "HandlerPriority",
    "HandlerResult",
    "HandlerRetryPolicy",
    "HandlersHealthMonitor",
    "NotificationHandler",
    "SecurityEventHandler",
    "UserCreatedHandler",
    "UserLoginHandler",
    "UserPasswordChangedHandler",
    "UserSuspendedHandler",
]