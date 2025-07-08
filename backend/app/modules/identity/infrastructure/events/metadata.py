"""
Event Metadata Management

Provides comprehensive metadata tracking for events including timestamps,
correlation IDs, performance metrics, and monitoring information.
"""

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

logger = get_logger(__name__)


@dataclass
class EventMetadata:
    """
    Comprehensive metadata for event publishing and tracking.
    
    Tracks event publication lifecycle, performance metrics, routing
    information, and correlation data for monitoring and debugging.
    
    Features:
    - Event lifecycle tracking
    - Performance metrics collection
    - Correlation ID management
    - Source tracking and attribution
    - Retry and delivery tracking
    - Monitoring hooks and alerts
    
    Usage:
        # Create metadata for an event
        metadata = EventMetadata.create(
            event=user_created_event,
            correlation_id="req-123",
            additional_metadata={"source": "api", "version": "1.0"}
        )
        
        # Track publication lifecycle
        metadata.mark_published()
        metadata.mark_delivered()
        
        # Add performance metrics
        metadata.add_timing("serialization", 1.5)
        metadata.add_timing("routing", 0.8)
    """
    
    # Core identification
    metadata_id: str = field(default_factory=lambda: str(uuid4()))
    event_id: str | None = None
    event_type: str | None = None
    
    # Timing information
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    published_at: datetime | None = None
    delivered_at: datetime | None = None
    completed_at: datetime | None = None
    
    # Correlation and tracing
    correlation_id: str | None = None
    parent_event_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    
    # Source information
    source_service: str = "identity-service"
    source_module: str | None = None
    source_version: str | None = None
    publisher_instance_id: str | None = None
    
    # Event characteristics
    event_size_bytes: int = 0
    event_priority: str = "normal"
    event_category: str | None = None
    
    # Processing tracking
    retry_count: int = 0
    max_retries: int = 3
    processing_attempts: int = 0
    last_error: str | None = None
    
    # Performance metrics
    timings: dict[str, float] = field(default_factory=dict)
    processing_stages: list[str] = field(default_factory=list)
    performance_tags: dict[str, str] = field(default_factory=dict)
    
    # Routing information
    routing_rules_applied: list[str] = field(default_factory=list)
    target_handlers: list[str] = field(default_factory=list)
    delivery_destinations: list[str] = field(default_factory=list)
    
    # Custom metadata
    additional_metadata: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    
    # Internal tracking
    _stage_start_times: dict[str, float] = field(default_factory=dict, init=False)
    
    @classmethod
    def create(
        cls,
        event: IdentityDomainEvent,
        correlation_id: str | None = None,
        additional_metadata: dict[str, Any] | None = None,
        source_module: str | None = None,
    ) -> "EventMetadata":
        """
        Create metadata for an event.
        
        Args:
            event: Domain event
            correlation_id: Optional correlation ID
            additional_metadata: Additional metadata
            source_module: Source module name
            
        Returns:
            EventMetadata: Created metadata instance
        """
        # Extract event information
        event_id = str(getattr(event, 'event_id', uuid4()))
        event_type = event.__class__.__name__
        
        # Estimate event size
        event_size = 0
        try:
            # Try to get size from event if it has a method
            if hasattr(event, 'get_size'):
                event_size = event.get_size()
            else:
                # Rough estimate based on string representation
                event_size = len(str(event).encode('utf-8'))
        except Exception:
            event_size = 0
        
        # Get event characteristics
        event_priority = "normal"
        event_category = None
        
        if hasattr(event, 'get_risk_level'):
            risk_level = event.get_risk_level()
            if risk_level in ["high", "critical"]:
                event_priority = risk_level
        
        if hasattr(event, 'is_security_event') and event.is_security_event():
            event_category = "security"
        elif hasattr(event, 'is_compliance_event') and event.is_compliance_event():
            event_category = "compliance"
        
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid4())
        
        return cls(
            event_id=event_id,
            event_type=event_type,
            correlation_id=correlation_id,
            source_module=source_module or event.__module__,
            event_size_bytes=event_size,
            event_priority=event_priority,
            event_category=event_category,
            additional_metadata=additional_metadata or {},
        )
    
    def mark_published(self) -> None:
        """Mark event as published."""
        self.published_at = datetime.now(UTC)
        self.add_stage("published")
        
        logger.debug(
            "Event marked as published",
            event_id=self.event_id,
            event_type=self.event_type,
            correlation_id=self.correlation_id,
        )
    
    def mark_delivered(self) -> None:
        """Mark event as delivered."""
        self.delivered_at = datetime.now(UTC)
        self.add_stage("delivered")
        
        logger.debug(
            "Event marked as delivered",
            event_id=self.event_id,
            event_type=self.event_type,
            correlation_id=self.correlation_id,
        )
    
    def mark_completed(self) -> None:
        """Mark event processing as completed."""
        self.completed_at = datetime.now(UTC)
        self.add_stage("completed")
        
        logger.debug(
            "Event marked as completed",
            event_id=self.event_id,
            event_type=self.event_type,
            correlation_id=self.correlation_id,
        )
    
    def mark_failed(self, error: str) -> None:
        """Mark event as failed with error information."""
        self.last_error = error
        self.add_stage("failed")
        
        logger.warning(
            "Event marked as failed",
            event_id=self.event_id,
            event_type=self.event_type,
            error=error,
            correlation_id=self.correlation_id,
        )
    
    def increment_retry(self) -> None:
        """Increment retry count."""
        self.retry_count += 1
        self.add_stage(f"retry_{self.retry_count}")
        
        logger.debug(
            "Event retry incremented",
            event_id=self.event_id,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
        )
    
    def start_stage(self, stage_name: str) -> None:
        """Start timing a processing stage."""
        self._stage_start_times[stage_name] = time.time()
        
    def end_stage(self, stage_name: str) -> float:
        """End timing a processing stage and return duration."""
        start_time = self._stage_start_times.get(stage_name)
        if start_time is None:
            logger.warning(f"Stage {stage_name} was not started")
            return 0.0
        
        duration = time.time() - start_time
        self.add_timing(stage_name, duration)
        del self._stage_start_times[stage_name]
        
        return duration
    
    def add_timing(self, operation: str, duration_seconds: float) -> None:
        """Add timing information for an operation."""
        self.timings[operation] = duration_seconds
        
        logger.debug(
            "Timing recorded",
            operation=operation,
            duration_ms=round(duration_seconds * 1000, 2),
            event_id=self.event_id,
        )
    
    def add_stage(self, stage: str) -> None:
        """Add a processing stage."""
        self.processing_stages.append(stage)
        self.processing_attempts += 1
    
    def add_tag(self, key: str, value: str) -> None:
        """Add a tag for categorization and filtering."""
        self.tags[key] = value
    
    def add_performance_tag(self, key: str, value: str) -> None:
        """Add a performance-related tag."""
        self.performance_tags[key] = value
    
    def add_routing_rule(self, rule_id: str) -> None:
        """Add a routing rule that was applied."""
        if rule_id not in self.routing_rules_applied:
            self.routing_rules_applied.append(rule_id)
    
    def add_target_handler(self, handler_name: str) -> None:
        """Add a target handler."""
        if handler_name not in self.target_handlers:
            self.target_handlers.append(handler_name)
    
    def add_delivery_destination(self, destination: str) -> None:
        """Add a delivery destination."""
        if destination not in self.delivery_destinations:
            self.delivery_destinations.append(destination)
    
    @property
    def total_processing_time(self) -> float:
        """Get total processing time from creation to completion."""
        if self.completed_at:
            return (self.completed_at - self.created_at).total_seconds()
        return (datetime.now(UTC) - self.created_at).total_seconds()
    
    @property
    def publication_latency(self) -> float:
        """Get time from creation to publication."""
        if self.published_at:
            return (self.published_at - self.created_at).total_seconds()
        return 0.0
    
    @property
    def delivery_latency(self) -> float:
        """Get time from publication to delivery."""
        if self.delivered_at and self.published_at:
            return (self.delivered_at - self.published_at).total_seconds()
        return 0.0
    
    @property
    def is_high_priority(self) -> bool:
        """Check if event is high priority."""
        return self.event_priority in ["high", "critical"]
    
    @property
    def is_security_event(self) -> bool:
        """Check if event is security-related."""
        return self.event_category == "security"
    
    @property
    def is_compliance_event(self) -> bool:
        """Check if event is compliance-related."""
        return self.event_category == "compliance"
    
    @property
    def needs_retry(self) -> bool:
        """Check if event needs retry."""
        return self.retry_count < self.max_retries and self.last_error is not None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "metadata_id": self.metadata_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "correlation_id": self.correlation_id,
            "parent_event_id": self.parent_event_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "source_service": self.source_service,
            "source_module": self.source_module,
            "source_version": self.source_version,
            "publisher_instance_id": self.publisher_instance_id,
            "event_size_bytes": self.event_size_bytes,
            "event_priority": self.event_priority,
            "event_category": self.event_category,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "processing_attempts": self.processing_attempts,
            "last_error": self.last_error,
            "timings": self.timings,
            "processing_stages": self.processing_stages,
            "performance_tags": self.performance_tags,
            "routing_rules_applied": self.routing_rules_applied,
            "target_handlers": self.target_handlers,
            "delivery_destinations": self.delivery_destinations,
            "additional_metadata": self.additional_metadata,
            "tags": self.tags,
            "total_processing_time": self.total_processing_time,
            "publication_latency": self.publication_latency,
            "delivery_latency": self.delivery_latency,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EventMetadata":
        """Create metadata from dictionary."""
        # Convert datetime strings back to datetime objects
        datetime_fields = ["created_at", "published_at", "delivered_at", "completed_at"]
        for field in datetime_fields:
            if data.get(field):
                data[field] = datetime.fromisoformat(data[field])
        
        # Remove computed properties
        computed_fields = ["total_processing_time", "publication_latency", "delivery_latency"]
        for field in computed_fields:
            data.pop(field, None)
        
        return cls(**data)
    
    def get_monitoring_summary(self) -> dict[str, Any]:
        """Get summary for monitoring and alerting."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "correlation_id": self.correlation_id,
            "event_priority": self.event_priority,
            "event_category": self.event_category,
            "retry_count": self.retry_count,
            "processing_attempts": self.processing_attempts,
            "total_processing_time": self.total_processing_time,
            "publication_latency": self.publication_latency,
            "delivery_latency": self.delivery_latency,
            "last_error": self.last_error,
            "is_high_priority": self.is_high_priority,
            "is_security_event": self.is_security_event,
            "is_compliance_event": self.is_compliance_event,
            "needs_retry": self.needs_retry,
        }
    
    def __str__(self) -> str:
        """String representation of metadata."""
        return (
            f"EventMetadata("
            f"event_id={self.event_id}, "
            f"event_type={self.event_type}, "
            f"correlation_id={self.correlation_id}, "
            f"priority={self.event_priority}"
            f")"
        )