"""
Event Handler System Integration Example

Demonstrates how to use the comprehensive event handler system
for processing identity domain events.
"""

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.entities.admin.admin_events import (
    SecurityAlertRaised,
)
from app.modules.identity.domain.entities.user.user_events import (
    LoginSuccessful,
    PasswordChanged,
    UserCreated,
    UserSuspended,
)

from .executor import EventHandlerExecutor
from .monitor import HandlersHealthMonitor
from .notifications import NotificationHandler
from .registry import EventHandlerRegistry
from .security import AuditLogHandler, SecurityEventHandler
from .user import (
    UserCreatedHandler,
    UserLoginHandler,
    UserPasswordChangedHandler,
    UserSuspendedHandler,
)

logger = get_logger(__name__)


async def demonstrate_event_handler_system():
    """
    Comprehensive demonstration of the event handler system.
    
    Shows:
    1. Handler registration and discovery
    2. Event processing with multiple handlers
    3. Error handling and isolation
    4. Performance monitoring
    5. Health checks and alerting
    """
    
    print("🚀 Starting Event Handler System Demonstration")
    print("=" * 60)
    
    # Step 1: Initialize the system components
    print("\n📋 Step 1: Initializing System Components")
    
    registry = EventHandlerRegistry()
    executor = EventHandlerExecutor(registry)
    monitor = HandlersHealthMonitor(registry, executor)
    
    print("✅ Registry initialized")
    print(f"✅ Executor initialized (max concurrent: {executor.max_concurrent_handlers})")
    print("✅ Health monitor initialized")
    
    # Step 2: Register handlers manually
    print("\n🔧 Step 2: Registering Event Handlers")
    
    handlers_to_register = [
        UserCreatedHandler(),
        UserLoginHandler(),
        UserPasswordChangedHandler(),
        UserSuspendedHandler(),
        SecurityEventHandler(),
        AuditLogHandler(),
        NotificationHandler(),
    ]
    
    for handler in handlers_to_register:
        registry.register_handler(handler)
        print(f"✅ Registered: {handler.metadata.handler_name}")
    
    # Step 3: Start monitoring
    print("\n📊 Step 3: Starting Health Monitoring")
    await monitor.start_monitoring()
    print("✅ Health monitoring started")
    
    # Add health alert callback
    def health_alert_callback(health_result):
        print(f"🚨 HEALTH ALERT: {health_result.handler_id} - {health_result.status.value}")
        if health_result.issues:
            for issue in health_result.issues:
                print(f"   ⚠️  {issue}")
    
    monitor.add_health_alert_callback(health_alert_callback)
    
    # Step 4: Create and process events
    print("\n🎬 Step 4: Processing Domain Events")
    
    # Create sample events
    user_id = uuid4()
    session_id = uuid4()
    
    events_to_process = [
        UserCreated(
            user_id=user_id,
            email="john.doe@example.com",
            name="John Doe",
            role="user",
            registration_method="email"
        ),
        LoginSuccessful(
            user_id=user_id,
            session_id=session_id,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            risk_score=0.2,
            mfa_used=True,
            trusted_device=True
        ),
        PasswordChanged(
            user_id=user_id,
            strength_score=0.85,
            force_password_change=False
        ),
        SecurityAlertRaised(
            alert_type="suspicious_login",
            risk_level="medium",
            description="Login from unusual location",
            source_ip="10.0.0.50",
            user_agent="Unknown",
            user_id=user_id,
            evidence={"location": "Unknown", "device": "Unknown"}
        )
    ]
    
    # Process each event
    for i, event in enumerate(events_to_process, 1):
        print(f"\n📨 Processing Event {i}: {event.__class__.__name__}")
        
        # Execute handlers for the event
        results = await executor.execute_handlers(event, correlation_id=f"demo-{i}")
        
        # Display results
        successful = sum(1 for r in results if r.success)
        failed = len(results) - successful
        
        print(f"   📈 Results: {successful} successful, {failed} failed")
        
        for result in results:
            status = "✅" if result.success else "❌"
            handler_name = result.handler_id.split('.')[-1]
            print(f"   {status} {handler_name}: {result.duration_ms:.1f}ms")
        
        # Record results in monitor
        for result in results:
            monitor.record_handler_result(result)
        
        # Small delay between events
        await asyncio.sleep(0.1)
    
    # Step 5: Demonstrate system statistics
    print("\n📊 Step 5: System Statistics and Health")
    
    # Registry statistics
    registry_stats = registry.get_registry_stats()
    print("\n📋 Registry Statistics:")
    print(f"   Total Handlers: {registry_stats['total_handlers']}")
    print(f"   Enabled Handlers: {registry_stats['enabled_handlers']}")
    print(f"   Event Types Covered: {registry_stats['total_event_types']}")
    
    # Execution statistics
    execution_stats = executor.get_execution_metrics()
    print("\n⚡ Execution Statistics:")
    print(f"   Total Executions: {execution_stats['total_executions']}")
    print(f"   Success Rate: {execution_stats['overall_success_rate']:.2%}")
    print(f"   Active Executions: {execution_stats['active_executions']}")
    
    # Health overview
    health_overview = monitor.get_system_health_overview()
    print("\n🏥 Health Overview:")
    print(f"   Monitoring Active: {health_overview['monitoring_active']}")
    print(f"   Handlers with Metrics: {health_overview['handlers_with_metrics']}")
    
    status_dist = health_overview['status_distribution']
    for status, count in status_dist.items():
        print(f"   {status.title()}: {count}")
    
    # Step 6: Demonstrate handler filtering
    print("\n🔍 Step 6: Handler Discovery and Filtering")
    
    # Get handlers by category
    security_handlers = registry.get_handlers_by_category("security")
    user_handlers = registry.get_handlers_by_category("user_lifecycle")
    
    print(f"   Security Handlers: {len(security_handlers)}")
    print(f"   User Lifecycle Handlers: {len(user_handlers)}")
    
    # Get handlers by priority
    critical_handlers = registry.get_handlers_by_priority(registry.get_all_handlers()[0].metadata.priority.__class__.CRITICAL)
    print(f"   Critical Priority Handlers: {len(critical_handlers)}")
    
    # Get handlers for specific event
    user_created_handlers = registry.get_handlers_for_event("UserCreated")
    print(f"   UserCreated Event Handlers: {len(user_created_handlers)}")
    
    # Step 7: Demonstrate error handling
    print("\n💥 Step 7: Error Handling Demonstration")
    
    # Create an event that will trigger a suspension (high-risk scenario)
    suspension_event = UserSuspended(
        user_id=user_id,
        reason="Security violation detected",
        suspended_by=uuid4(),
        automatic_suspension=True,
        suspension_expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    
    print("   Processing high-priority suspension event...")
    suspension_results = await executor.execute_handlers(
        suspension_event, 
        correlation_id="demo-suspension"
    )
    
    for result in suspension_results:
        monitor.record_handler_result(result)
    
    successful = sum(1 for r in suspension_results if r.success)
    print(f"   🔒 Suspension processed: {successful}/{len(suspension_results)} handlers succeeded")
    
    # Step 8: Check final system health
    print("\n🏁 Step 8: Final System Health Check")
    
    # Perform manual health checks for all handlers
    all_handlers = registry.get_all_handlers()
    
    for handler in all_handlers:
        handler_id = handler.metadata.handler_id
        health_result = monitor.check_handler_health(handler_id)
        
        status_emoji = {
            "healthy": "✅",
            "warning": "⚠️",
            "critical": "🚨",
            "unknown": "❓"
        }.get(health_result.status.value, "❓")
        
        handler_name = handler_id.split('.')[-1]
        print(f"   {status_emoji} {handler_name}: {health_result.status.value}")
        
        if health_result.issues:
            for issue in health_result.issues[:2]:  # Show first 2 issues
                print(f"      - {issue}")
    
    # Step 9: Cleanup
    print("\n🧹 Step 9: System Cleanup")
    
    await monitor.stop_monitoring()
    print("   ✅ Health monitoring stopped")
    
    registry.clear()
    print("   ✅ Registry cleared")
    
    print("\n🎉 Event Handler System Demonstration Complete!")
    print("=" * 60)


if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(demonstrate_event_handler_system())