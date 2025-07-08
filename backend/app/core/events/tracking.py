"""Event tracking and correlation/context propagation."""

import json
import threading
from collections import defaultdict
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.events.types import DomainEvent
from app.core.logging import get_logger

try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockCounter:
        def labels(self, **kwargs):
            return self
        def inc(self):
            pass
    
    class MockMetrics:
        def __init__(self):
            self.events_tracked = MockCounter()
    
    metrics = MockMetrics()

logger = get_logger(__name__)

# Context propagation for distributed tracing
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
causation_id_var: ContextVar[UUID | None] = ContextVar("causation_id", default=None)
user_id_var: ContextVar[UUID | None] = ContextVar("user_id", default=None)
trace_context_var: ContextVar[dict[str, Any] | None] = ContextVar(
    "trace_context", default=None
)


def set_correlation_id(correlation_id: str | None = None) -> str:
    """Set and return the correlation ID for the current context."""
    correlation_id = correlation_id or str(uuid4())
    correlation_id_var.set(correlation_id)
    return correlation_id


def get_correlation_id() -> str | None:
    return correlation_id_var.get()


def set_causation_id(causation_id: UUID | None = None) -> UUID | None:
    causation_id_var.set(causation_id)
    return causation_id


def get_causation_id() -> UUID | None:
    return causation_id_var.get()


def set_user_id(user_id: UUID | None) -> UUID | None:
    """Set the user ID for the current context."""
    user_id_var.set(user_id)
    return user_id


def get_user_id() -> UUID | None:
    """Get the user ID from the current context."""
    return user_id_var.get()


def set_trace_context(context: dict[str, Any]) -> dict[str, Any]:
    """Set additional trace context for distributed tracing."""
    trace_context_var.set(context)
    return context


def get_trace_context() -> dict[str, Any]:
    """Get the current trace context."""
    return trace_context_var.get() or {}


def track_event_flow(event: DomainEvent) -> None:
    """Log/track event for debugging or visualization."""
    logger.info(
        "Event tracked",
        event_type=event.event_type,
        event_id=str(event.metadata.event_id),
        correlation_id=event.metadata.correlation_id,
        causation_id=str(event.metadata.causation_id)
        if event.metadata.causation_id
        else None,
        timestamp=event.metadata.timestamp.isoformat(),
        user_id=str(get_user_id()) if get_user_id() else None,
        trace_context=get_trace_context(),
    )

    # Update metrics
    metrics.events_tracked.labels(event_type=event.event_type).inc()


@dataclass
class EventTraceInfo:
    """Detailed information about an event in a trace."""

    event_id: UUID
    event_type: str
    timestamp: datetime
    correlation_id: str
    causation_id: UUID | None
    user_id: UUID | None
    aggregate_id: str | None
    duration_ms: float | None = None
    handler_results: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EventChain:
    """Represents a chain of causally related events."""

    root_event_id: UUID
    correlation_id: str
    events: list[EventTraceInfo] = field(default_factory=list)
    total_duration_ms: float = 0.0

    def add_event(self, trace_info: EventTraceInfo) -> None:
        """Add an event to the chain."""
        self.events.append(trace_info)
        if trace_info.duration_ms:
            self.total_duration_ms += trace_info.duration_ms

    def get_depth(self) -> int:
        """Get the maximum depth of the event chain."""
        if not self.events:
            return 0

        # Build parent-child relationships
        children_map = defaultdict(list)
        for event in self.events:
            if event.causation_id:
                children_map[event.causation_id].append(event.event_id)

        # Calculate depth recursively
        def get_event_depth(event_id: UUID, depth: int = 0) -> int:
            children = children_map.get(event_id, [])
            if not children:
                return depth
            return max(get_event_depth(child, depth + 1) for child in children)

        return get_event_depth(self.root_event_id)


class EventFlowTracker:
    """Enhanced event flow tracker with comprehensive tracking capabilities."""

    def __init__(self, max_flows: int = 1000, max_age_hours: int = 24):
        self._flows: dict[str, list[EventTraceInfo]] = {}
        self._chains: dict[UUID, EventChain] = {}
        self._event_index: dict[UUID, EventTraceInfo] = {}
        self._max_flows = max_flows
        self._max_age = timedelta(hours=max_age_hours)
        self._flow_timestamps: dict[str, datetime] = {}
        self._lock: threading.Lock | None = (
            None  # Would use threading.Lock() in production
        )

    def add_event(self, event: DomainEvent, duration_ms: float | None = None) -> None:
        """Add an event to the tracker with optional duration."""
        correlation_id = event.metadata.correlation_id
        if not correlation_id:
            correlation_id = str(uuid4())

        # Create trace info with performance optimization
        trace_context = get_trace_context()
        trace_info = EventTraceInfo(
            event_id=event.metadata.event_id,
            event_type=event.event_type,
            timestamp=event.metadata.timestamp,
            correlation_id=correlation_id,
            causation_id=event.metadata.causation_id,
            user_id=get_user_id(),
            aggregate_id=getattr(event, "aggregate_id", None),
            duration_ms=duration_ms,
            metadata={
                "version": getattr(event, "version", None),
                "trace_context": trace_context if trace_context else {},
                "event_size": getattr(event, 'get_size', lambda: 0)(),
            },
        )

        # Add to flows
        self._flows.setdefault(correlation_id, []).append(trace_info)
        self._flow_timestamps[correlation_id] = datetime.now(UTC)

        # Index event
        self._event_index[event.metadata.event_id] = trace_info

        # Build event chains
        if event.metadata.causation_id is None:
            # This is a root event
            chain = EventChain(
                root_event_id=event.metadata.event_id, correlation_id=correlation_id
            )
            chain.add_event(trace_info)
            self._chains[event.metadata.event_id] = chain
        else:
            # Find parent chain
            parent_trace = self._event_index.get(event.metadata.causation_id)
            if parent_trace:
                # Find root of chain
                root_id = self._find_root_event(event.metadata.causation_id)
                if root_id in self._chains:
                    self._chains[root_id].add_event(trace_info)

        # Clean up old flows
        self._cleanup_old_flows()

        # Track the event
        track_event_flow(event)

    def get_flow(self, correlation_id: str) -> list[EventTraceInfo]:
        """Get all events for a correlation ID."""
        return self._flows.get(correlation_id, [])

    def get_event_chain(self, event_id: UUID) -> EventChain | None:
        """Get the complete event chain for an event."""
        # Find root
        root_id = self._find_root_event(event_id)
        return self._chains.get(root_id)

    def _find_root_event(self, event_id: UUID) -> UUID:
        """Find the root event in a chain."""
        current = event_id
        visited = set()

        while current and current not in visited:
            visited.add(current)
            trace = self._event_index.get(current)
            if not trace or not trace.causation_id:
                return current
            current = trace.causation_id

        return event_id  # Fallback if circular reference

    def visualize_flow(self, correlation_id: str) -> str:
        """Create a visual representation of the event flow."""
        events = self.get_flow(correlation_id)
        if not events:
            return f"No events found for correlation ID {correlation_id}"

        lines = [f"Event Flow for {correlation_id}:"]
        lines.append(f"Total events: {len(events)}")
        lines.append("")

        # Build parent-child map
        children_map = defaultdict(list)
        root_events = []

        for event in events:
            if event.causation_id:
                children_map[event.causation_id].append(event)
            else:
                root_events.append(event)

        # Recursive visualization
        def visualize_event(event: EventTraceInfo, indent: int = 0):
            prefix = "  " * indent + ("└─ " if indent > 0 else "")
            duration = f" ({event.duration_ms:.2f}ms)" if event.duration_ms else ""
            error_marker = " ❌" if event.error else ""

            lines.append(
                f"{prefix}{event.event_type} "
                f"[{event.timestamp.strftime('%H:%M:%S.%f')[:-3]}]"
                f"{duration}{error_marker}"
            )

            # Add children
            children = children_map.get(event.event_id, [])
            for child in sorted(children, key=lambda e: e.timestamp):
                visualize_event(child, indent + 1)

        # Visualize each root and its tree
        for root in sorted(root_events, key=lambda e: e.timestamp):
            visualize_event(root)

        return "\n".join(lines)

    def get_statistics(self, correlation_id: str | None = None) -> dict[str, Any]:
        """Get statistics about event flows."""
        if correlation_id:
            events = self.get_flow(correlation_id)
            if not events:
                return {"error": "No events found"}

            return {
                "correlation_id": correlation_id,
                "total_events": len(events),
                "start_time": min(e.timestamp for e in events).isoformat(),
                "end_time": max(e.timestamp for e in events).isoformat(),
                "duration_ms": sum(e.duration_ms or 0 for e in events),
                "event_types": list({e.event_type for e in events}),
                "error_count": sum(1 for e in events if e.error),
                "unique_users": len({e.user_id for e in events if e.user_id}),
            }

        # Global statistics
        total_events = sum(len(events) for events in self._flows.values())

        return {
            "total_flows": len(self._flows),
            "total_events": total_events,
            "total_chains": len(self._chains),
            "average_events_per_flow": total_events / len(self._flows)
            if self._flows
            else 0,
            "active_flows": len(
                [
                    fid
                    for fid, ts in self._flow_timestamps.items()
                    if datetime.now(datetime.UTC) - ts < timedelta(minutes=5)
                ]
            ),
        }

    def _cleanup_old_flows(self) -> None:
        """Remove flows older than max age."""
        if len(self._flows) <= self._max_flows:
            return

        now = datetime.now(UTC)
        to_remove = []

        for correlation_id, timestamp in self._flow_timestamps.items():
            if now - timestamp > self._max_age:
                to_remove.append(correlation_id)

        for correlation_id in to_remove:
            events = self._flows.pop(correlation_id, [])
            self._flow_timestamps.pop(correlation_id, None)

            # Clean up indices
            for event in events:
                self._event_index.pop(event.event_id, None)
                if event.event_id in self._chains:
                    del self._chains[event.event_id]

    def export_flow(self, correlation_id: str, format: str = "json") -> str:
        """Export flow data for analysis."""
        events = self.get_flow(correlation_id)
        if not events:
            return "{}" if format == "json" else ""

        if format == "json":
            data = {
                "correlation_id": correlation_id,
                "events": [
                    {
                        "event_id": str(e.event_id),
                        "event_type": e.event_type,
                        "timestamp": e.timestamp.isoformat(),
                        "causation_id": str(e.causation_id) if e.causation_id else None,
                        "user_id": str(e.user_id) if e.user_id else None,
                        "duration_ms": e.duration_ms,
                        "error": e.error,
                        "metadata": e.metadata,
                    }
                    for e in events
                ],
            }
            return json.dumps(data, indent=2)

        # Add other formats (CSV, etc.) as needed
        return str(events)


# Global tracker instance
_global_tracker = EventFlowTracker()


def get_event_tracker() -> EventFlowTracker:
    """Get the global event tracker instance."""
    return _global_tracker


# Distributed tracing integration
class DistributedTraceContext:
    """Context manager for distributed tracing."""

    def __init__(
        self,
        correlation_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        parent_span_id: str | None = None,
        baggage: dict[str, str] | None = None,
    ):
        self.correlation_id = correlation_id or str(uuid4())
        self.trace_id = trace_id or str(uuid4())
        self.span_id = span_id or str(uuid4())
        self.parent_span_id = parent_span_id
        self.baggage = baggage or {}

    def __enter__(self):
        """Enter the trace context."""
        set_correlation_id(self.correlation_id)
        set_trace_context(
            {
                "trace_id": self.trace_id,
                "span_id": self.span_id,
                "parent_span_id": self.parent_span_id,
                "baggage": self.baggage,
            }
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the trace context."""
        # Context vars are automatically cleaned up

    def create_child_context(self) -> "DistributedTraceContext":
        """Create a child context for nested operations."""
        return DistributedTraceContext(
            correlation_id=self.correlation_id,
            trace_id=self.trace_id,
            span_id=str(uuid4()),
            parent_span_id=self.span_id,
            baggage=self.baggage.copy(),
        )

    def to_headers(self) -> dict[str, str]:
        """Convert to HTTP headers for propagation."""
        headers = {
            "X-Correlation-ID": self.correlation_id,
            "X-Trace-ID": self.trace_id,
            "X-Span-ID": self.span_id,
        }

        if self.parent_span_id:
            headers["X-Parent-Span-ID"] = self.parent_span_id

        # Add baggage
        for key, value in self.baggage.items():
            headers[f"X-Baggage-{key}"] = value

        return headers

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "DistributedTraceContext":
        """Create context from HTTP headers."""
        baggage = {}
        for key, value in headers.items():
            if key.startswith("X-Baggage-"):
                baggage_key = key[10:]  # Remove "X-Baggage-"
                baggage[baggage_key] = value

        return cls(
            correlation_id=headers.get("X-Correlation-ID"),
            trace_id=headers.get("X-Trace-ID"),
            span_id=headers.get("X-Span-ID"),
            parent_span_id=headers.get("X-Parent-Span-ID"),
            baggage=baggage,
        )
