"""
Identity Module Event Publishing Infrastructure

This module provides comprehensive event publishing infrastructure for the identity
module's domain events, supporting both synchronous and asynchronous event publishing,
routing, delivery, and monitoring.

Key Components:
- EventPublisher: Main interface for publishing events
- EventRouter: Routes events to appropriate handlers
- EventSerializer: Converts events to/from JSON
- EventDeliveryService: Handles delivery with retry logic
- EventMetadata: Tracks event metadata and monitoring
- EventBatch: Supports batch event publishing for performance

Features:
- Dead letter queue for failed events
- Event deduplication
- Metrics and monitoring hooks
- Transaction support (events published only on commit)
- Error handling with circuit breaker pattern
- Support for event filtering and routing rules
"""

from .batch import EventBatch
from .delivery import EventDeliveryService
from .metadata import EventMetadata as PublisherEventMetadata
from .publisher import EventPublisher
from .router import EventRouter
from .serializer import EventSerializer

__all__ = [
    "EventBatch",
    "EventDeliveryService",
    "EventPublisher",
    "EventRouter",
    "EventSerializer",
    "PublisherEventMetadata",
]