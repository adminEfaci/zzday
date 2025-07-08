"""
Event Publishing Infrastructure Examples

Demonstrates how to use the comprehensive event publishing infrastructure
for the identity module with various scenarios and use cases.
"""

import asyncio
from uuid import uuid4

from app.core.events.bus import create_event_bus
from app.core.logging import get_logger
from app.modules.identity.domain.entities.user.user_events import (
    LoginSuccessful,
    PasswordChanged,
    UserCreated,
    UserSuspended,
)

from .batch import BatchStrategy, EventBatch
from .delivery import EventDeliveryService
from .publisher import EventPublisher
from .router import EventRouter, RoutingRule, RoutingStrategy
from .serializer import EventSerializer, SerializationFormat

logger = get_logger(__name__)


class EventPublishingExamples:
    """
    Example implementations showing various use cases for the
    event publishing infrastructure.
    """
    
    def __init__(self):
        """Initialize the examples with required components."""
        self.event_bus = None
        self.publisher = None
        self.router = None
        self.serializer = None
        self.delivery_service = None
    
    async def setup(self):
        """Set up the event publishing infrastructure."""
        # Create event bus (hybrid mode with fallback)
        self.event_bus = create_event_bus(
            mode="hybrid",
            redis_url="redis://localhost:6379/0",
            fallback_to_memory=True,
            health_check_interval=15
        )
        
        # Initialize publisher with comprehensive features
        self.publisher = EventPublisher(
            event_bus=self.event_bus,
            enable_dead_letter_queue=True,
            enable_deduplication=True,
            enable_metrics=True,
            max_retry_attempts=3,
            batch_size=50,
            deduplication_window_seconds=300,
            circuit_breaker_threshold=5,
        )
        
        # Set up custom routing rules
        self.router = EventRouter()
        self._setup_custom_routing_rules()
        
        # Initialize serializer
        self.serializer = EventSerializer(
            compression_threshold=1024,
            enable_schema_validation=True,
            enable_type_checking=True
        )
        
        # Initialize delivery service
        self.delivery_service = EventDeliveryService(
            event_bus=self.event_bus,
            max_retry_attempts=3,
            enable_dead_letter_queue=True,
            circuit_breaker_threshold=5
        )
        
        # Start all services
        await self.event_bus.start()
        await self.publisher.start()
        await self.delivery_service.start()
        
        logger.info("Event publishing infrastructure setup completed")
    
    async def cleanup(self):
        """Clean up resources."""
        if self.delivery_service:
            await self.delivery_service.stop()
        if self.publisher:
            await self.publisher.stop()
        if self.event_bus:
            await self.event_bus.stop()
    
    def _setup_custom_routing_rules(self):
        """Set up custom routing rules for demonstration."""
        # High-priority security events
        security_rule = RoutingRule(
            rule_id="high_priority_security",
            name="High Priority Security Events",
            description="Route critical security events to immediate response handlers",
            priority=100,
            event_types={"LoginFailed", "AccountLockedOut", "SuspiciousActivityDetected"},
            strategy=RoutingStrategy.BROADCAST,
            target_handlers=["security_ops_handler", "alert_handler", "siem_handler"],
            target_queues=["security_alerts", "immediate_response"],
        )
        self.router.add_rule(security_rule)
        
        # User lifecycle events with special handling for VIP users
        vip_user_rule = RoutingRule(
            rule_id="vip_user_lifecycle",
            name="VIP User Lifecycle Events",
            description="Special handling for VIP user events",
            priority=90,
            event_types={"UserCreated", "UserSuspended", "UserDeleted"},
            content_filters={"user_type": "vip"},
            strategy=RoutingStrategy.BROADCAST,
            target_handlers=["vip_support_handler", "account_manager_handler"],
            target_queues=["vip_events", "priority_queue"],
        )
        self.router.add_rule(vip_user_rule)
        
        # Compliance events requiring special retention
        compliance_rule = RoutingRule(
            rule_id="compliance_events",
            name="Compliance Events",
            description="Route compliance-sensitive events with extended retention",
            priority=80,
            event_types={"UserExported", "ConsentGranted", "ConsentRevoked"},
            strategy=RoutingStrategy.DIRECT,
            target_handlers=["compliance_handler", "data_retention_handler"],
            target_queues=["compliance_events"],
        )
        self.router.add_rule(compliance_rule)
    
    async def example_single_event_publishing(self):
        """Example: Publishing a single event with metadata."""
        logger.info("=== Single Event Publishing Example ===")
        
        # Create a user creation event
        user_id = uuid4()
        event = UserCreated(
            user_id=user_id,
            email="john.doe@example.com",
            name="John Doe",
            role="customer",
            registration_method="web"
        )
        
        # Publish with correlation ID and metadata
        correlation_id = str(uuid4())
        metadata = {
            "source": "user_registration_api",
            "version": "1.0",
            "client_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0..."
        }
        
        success = await self.publisher.publish(
            event=event,
            correlation_id=correlation_id,
            metadata=metadata
        )
        
        logger.info(f"Event published successfully: {success}")
        return success
    
    async def example_batch_event_publishing(self):
        """Example: Publishing multiple events in a batch."""
        logger.info("=== Batch Event Publishing Example ===")
        
        # Create multiple events
        events = []
        user_ids = [uuid4() for _ in range(10)]
        
        for i, user_id in enumerate(user_ids):
            event = UserCreated(
                user_id=user_id,
                email=f"user{i}@example.com",
                name=f"User {i}",
                role="customer",
                registration_method="bulk_import"
            )
            events.append(event)
        
        # Publish as batch
        correlation_id = str(uuid4())
        metadata = {"batch_import": True, "source": "admin_api"}
        
        results = await self.publisher.publish_batch(
            events=events,
            correlation_id=correlation_id,
            metadata=metadata
        )
        
        logger.info(f"Batch publishing results: {results}")
        return results
    
    async def example_transactional_publishing(self):
        """Example: Transactional event publishing."""
        logger.info("=== Transactional Event Publishing Example ===")
        
        user_id = uuid4()
        
        try:
            # Use transaction context
            async with self.publisher.transaction() as tx:
                # Create user
                user_created = UserCreated(
                    user_id=user_id,
                    email="jane.doe@example.com",
                    name="Jane Doe",
                    role="admin"
                )
                await tx.publish(user_created)
                
                # Log successful login
                login_event = LoginSuccessful(
                    user_id=user_id,
                    session_id=uuid4(),
                    ip_address="192.168.1.101",
                    user_agent="Admin Dashboard v2.0",
                    mfa_used=True,
                    trusted_device=True
                )
                await tx.publish(login_event)
                
                # Both events will be published only if transaction succeeds
                logger.info("Transaction completed successfully")
                
        except Exception as e:
            logger.exception(f"Transaction failed: {e}")
            # Events are automatically rolled back
    
    async def example_advanced_batch_processing(self):
        """Example: Advanced batch processing with different strategies."""
        logger.info("=== Advanced Batch Processing Example ===")
        
        # Create events with different priorities and types
        events = []
        
        # High-priority security events
        for i in range(3):
            event = UserSuspended(
                user_id=uuid4(),
                reason="Security violation",
                suspended_by=uuid4(),
                automatic_suspension=True
            )
            events.append(event)
        
        # Normal priority user events
        for i in range(5):
            event = UserCreated(
                user_id=uuid4(),
                email=f"user{i}@example.com",
                name=f"User {i}",
                role="customer"
            )
            events.append(event)
        
        # Password change events
        for i in range(2):
            event = PasswordChanged(
                user_id=uuid4(),
                strength_score=8.5,
                force_password_change=False
            )
            events.append(event)
        
        # Create batch with priority-based strategy
        batch = EventBatch(
            events=events,
            batch_size=3,
            strategy=BatchStrategy.PRIORITY_BASED,
            preserve_order=True
        )
        
        # Process batch
        async for sub_batch in batch.get_batches():
            logger.info(f"Processing sub-batch with {len(sub_batch)} events")
            
            # Simulate processing each event in the sub-batch
            for event in sub_batch:
                success = await self.publisher.publish(event)
                if success:
                    batch.mark_event_success(event)
                else:
                    batch.mark_event_failure(event, "Publishing failed")
        
        # Get batch metrics
        metrics = batch.get_metrics()
        logger.info(f"Batch metrics: {metrics.success_rate:.2%} success rate")
        
        return batch.get_summary()
    
    async def example_event_serialization(self):
        """Example: Event serialization and deserialization."""
        logger.info("=== Event Serialization Example ===")
        
        # Create an event
        event = LoginSuccessful(
            user_id=uuid4(),
            session_id=uuid4(),
            ip_address="10.0.0.1",
            user_agent="Mobile App v3.0",
            device_fingerprint="mobile_device_123",
            risk_score=0.1,
            mfa_used=True,
            trusted_device=True
        )
        
        # Serialize to different formats
        formats = [
            SerializationFormat.JSON,
            SerializationFormat.COMPRESSED_JSON,
            SerializationFormat.BINARY
        ]
        
        results = {}
        
        for format in formats:
            # Serialize
            serialized = self.serializer.serialize(event, format)
            size = len(serialized) if isinstance(serialized, str | bytes) else 0
            
            # Deserialize
            deserialized = self.serializer.deserialize(serialized)
            
            results[format.value] = {
                "size_bytes": size,
                "serialization_success": True,
                "deserialization_success": deserialized.__class__.__name__ == event.__class__.__name__,
                "event_id_match": str(deserialized.event_id) == str(event.event_id)
            }
            
            logger.info(f"Format {format.value}: {size} bytes")
        
        # Get serializer statistics
        stats = self.serializer.get_statistics()
        logger.info(f"Serializer stats: {stats}")
        
        return results
    
    async def example_custom_routing(self):
        """Example: Custom event routing based on content."""
        logger.info("=== Custom Event Routing Example ===")
        
        # Create events with different characteristics
        events = [
            # VIP user creation (should match VIP rule)
            UserCreated(
                user_id=uuid4(),
                email="vip@example.com",
                name="VIP User",
                role="premium",
                # This would normally come from event metadata
            ),
            
            # Security event (should match security rule)
            UserSuspended(
                user_id=uuid4(),
                reason="Multiple failed login attempts",
                suspended_by=uuid4(),
                automatic_suspension=True
            ),
            
            # Regular user event (default routing)
            PasswordChanged(
                user_id=uuid4(),
                strength_score=7.0,
                force_password_change=False
            )
        ]
        
        # Route each event and show results
        routing_results = []
        
        for event in events:
            routing_info = self.router.route(event)
            
            result = {
                "event_type": event.__class__.__name__,
                "decision": routing_info.decision.value,
                "strategy": routing_info.strategy.value,
                "target_handlers": routing_info.target_handlers,
                "target_queues": routing_info.target_queues,
                "applied_rules": routing_info.applied_rules
            }
            
            routing_results.append(result)
            
            logger.info(f"Routed {event.__class__.__name__} to {len(routing_info.target_handlers)} handlers")
        
        # Get router statistics
        stats = self.router.get_statistics()
        logger.info(f"Router stats: {stats}")
        
        return routing_results
    
    async def example_publisher_statistics(self):
        """Example: Getting comprehensive publisher statistics."""
        logger.info("=== Publisher Statistics Example ===")
        
        # Publish some events to generate statistics
        for i in range(5):
            event = UserCreated(
                user_id=uuid4(),
                email=f"stats_user{i}@example.com",
                name=f"Stats User {i}",
                role="customer"
            )
            await self.publisher.publish(event)
        
        # Get comprehensive statistics
        stats = {
            "publisher": self.publisher.get_statistics(),
            "delivery_service": self.delivery_service.get_statistics(),
            "router": self.router.get_statistics(),
            "serializer": self.serializer.get_statistics(),
        }
        
        logger.info("=== Publisher Statistics ===")
        for component, component_stats in stats.items():
            logger.info(f"{component}: {component_stats}")
        
        return stats
    
    async def run_all_examples(self):
        """Run all examples in sequence."""
        logger.info("Starting comprehensive event publishing examples...")
        
        await self.setup()
        
        try:
            # Run all examples
            examples = [
                ("Single Event Publishing", self.example_single_event_publishing),
                ("Batch Event Publishing", self.example_batch_event_publishing), 
                ("Transactional Publishing", self.example_transactional_publishing),
                ("Advanced Batch Processing", self.example_advanced_batch_processing),
                ("Event Serialization", self.example_event_serialization),
                ("Custom Routing", self.example_custom_routing),
                ("Publisher Statistics", self.example_publisher_statistics),
            ]
            
            results = {}
            
            for name, example_func in examples:
                logger.info(f"\n{'='*50}")
                logger.info(f"Running: {name}")
                logger.info(f"{'='*50}")
                
                try:
                    result = await example_func()
                    results[name] = {"success": True, "result": result}
                    logger.info(f"✅ {name} completed successfully")
                except Exception as e:
                    results[name] = {"success": False, "error": str(e)}
                    logger.exception(f"❌ {name} failed: {e}")
                
                # Small delay between examples
                await asyncio.sleep(1)
            
            # Summary
            logger.info(f"\n{'='*50}")
            logger.info("EXAMPLES SUMMARY")
            logger.info(f"{'='*50}")
            
            successful = sum(1 for r in results.values() if r["success"])
            total = len(results)
            
            logger.info(f"Completed: {successful}/{total} examples")
            
            for name, result in results.items():
                status = "✅" if result["success"] else "❌"
                logger.info(f"{status} {name}")
            
            return results
            
        finally:
            await self.cleanup()


async def main():
    """Main function to run the examples."""
    examples = EventPublishingExamples()
    await examples.run_all_examples()


if __name__ == "__main__":
    asyncio.run(main())