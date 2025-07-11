"""
Get security events query implementation.

Handles retrieval of security events with real-time monitoring, threat analysis,
and incident correlation capabilities.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SecurityEventsResponse
from app.modules.identity.domain.enums import (
    AlertSeverity,
    RiskLevel,
    SecurityEventType,
    ThreatCategory,
)
from app.modules.identity.domain.exceptions import (
    InvalidEventFilterError,
    SecurityQueryError,
    UnauthorizedAccessError,
)
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.security_event_repository import (
    ISecurityRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


class EventFilterType(Enum):
    """Types of security event filters."""
    BY_TYPE = "by_type"
    BY_SEVERITY = "by_severity"
    BY_USER = "by_user"
    BY_SOURCE_IP = "by_source_ip"
    BY_THREAT_CATEGORY = "by_threat_category"
    BY_RISK_LEVEL = "by_risk_level"
    BY_TIME_RANGE = "by_time_range"
    BY_INCIDENT = "by_incident"
    BY_CORRELATION_ID = "by_correlation_id"


class EventGrouping(Enum):
    """Grouping options for security events."""
    BY_TYPE = "by_type"
    BY_USER = "by_user"
    BY_SOURCE = "by_source"
    BY_TIME = "by_time"
    BY_THREAT = "by_threat"
    BY_SEVERITY = "by_severity"

@dataclass
class GetSecurityEventsQuery(Query[SecurityEventsResponse]):
    """Query to retrieve security events."""

    # Required fields (no defaults) - MUST come first
    requester_id: UUID

    # Optional fields (with defaults) - come after required fields
    # Time filters
    start_date: datetime | None = None
    end_date: datetime | None = None
    last_hours: int | None = None

    # Event filters
    event_types: list[SecurityEventType] | None = None
    severity_levels: list[AlertSeverity] | None = None
    risk_levels: list[RiskLevel] | None = None
    threat_categories: list[ThreatCategory] | None = None

    # Entity filters
    user_ids: list[UUID] | None = None
    session_ids: list[UUID] | None = None
    source_ips: list[str] | None = None
    correlation_ids: list[str] | None = None
    incident_ids: list[UUID] | None = None

    # Analysis options
    include_correlation: bool = False
    include_threat_intel: bool = False
    include_context: bool = True
    include_related_events: bool = False
    include_timeline: bool = False

    # Grouping and aggregation
    group_by: EventGrouping | None = None
    aggregate_similar: bool = False
    correlation_window_minutes: int = 60

    # Output options
    sort_by: str = "timestamp"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 100
    export_format: str | None = None

    # Real-time options
    real_time: bool = False
    subscription_id: str | None = None

    # Access control
    requester_permissions: list[str] = field(default_factory=list)

class GetSecurityEventsQueryHandler(QueryHandler[GetSecurityEventsQuery, SecurityEventsResponse]):
    """Handler for security events queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        security_repository: ISecurityRepository,
        user_repository: IUserRepository,
        session_repository: ISessionRepository
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.security_repository = security_repository
        self.user_repository = user_repository
        self.session_repository = session_repository
    
    @rate_limit(max_calls=200, window_seconds=3600)
    @require_permission("security.events.read")
    @validate_request
    async def handle(self, query: GetSecurityEventsQuery) -> SecurityEventsResponse:
        """Handle security events query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_security_access(query)
                
                # Normalize time range
                start_date, end_date = await self._normalize_time_range(query)
                
                # Build filter criteria
                filter_criteria = await self._build_filter_criteria(query, start_date, end_date)
                
                # Retrieve security events
                events = await self.security_repository.get_security_events(
                    filters=filter_criteria,
                    sort_by=query.sort_by,
                    sort_order=query.sort_order,
                    page=query.page,
                    page_size=query.page_size
                )
                
                # Get total count
                total_count = await self.security_repository.count_security_events(filter_criteria)
                
                # Apply correlation analysis if requested
                if query.include_correlation:
                    events = await self._apply_correlation_analysis(events, query)
                
                # Enrich with threat intelligence if requested
                if query.include_threat_intel:
                    events = await self._enrich_with_threat_intel(events)
                
                # Add context information if requested
                if query.include_context:
                    events = await self._add_context_information(events)
                
                # Find related events if requested
                related_events = []
                if query.include_related_events:
                    related_events = await self._find_related_events(events, query)
                
                # Generate timeline if requested
                timeline = None
                if query.include_timeline:
                    timeline = await self._generate_events_timeline(events, query)
                
                # Apply grouping if requested
                grouped_events = None
                if query.group_by:
                    grouped_events = await self._group_events(events, query.group_by)
                
                # Generate aggregated similar events
                aggregated_events = []
                if query.aggregate_similar:
                    aggregated_events = await self._aggregate_similar_events(events)
                
                # Generate statistics
                statistics = await self._generate_event_statistics(events, filter_criteria)
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(events, query.export_format)
                
                return SecurityEventsResponse(
                    events=events,
                    related_events=related_events,
                    grouped_events=grouped_events,
                    aggregated_events=aggregated_events,
                    timeline=timeline,
                    statistics=statistics,
                    total_count=total_count,
                    page=query.page,
                    page_size=query.page_size,
                    total_pages=(total_count + query.page_size - 1) // query.page_size,
                    filters_applied=filter_criteria,
                    query_timestamp=datetime.now(UTC),
                    export_data=export_data,
                    subscription_id=query.subscription_id if query.real_time else None
                )
                
        except Exception as e:
            raise SecurityQueryError(f"Failed to retrieve security events: {e!s}") from e
    
    async def _validate_security_access(self, query: GetSecurityEventsQuery) -> None:
        """Validate user has appropriate permissions for security events access."""
        
        # Check basic security events read permission
        if "security.events.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for security events access")
        
        # Check high-severity events access
        if query.severity_levels and AlertSeverity.CRITICAL in query.severity_levels:
            if "security.events.critical" not in query.requester_permissions:
                raise UnauthorizedAccessError("No access to critical security events")
        
        # Check threat intelligence access
        if query.include_threat_intel:
            if "security.threat_intel" not in query.requester_permissions:
                raise UnauthorizedAccessError("No access to threat intelligence data")
        
        # Check real-time monitoring access
        if query.real_time:
            if "security.realtime" not in query.requester_permissions:
                raise UnauthorizedAccessError("No access to real-time security monitoring")
        
        # Check correlation analysis access
        if query.include_correlation:
            if "security.analysis" not in query.requester_permissions:
                raise UnauthorizedAccessError("No access to security event correlation")
    
    async def _normalize_time_range(self, query: GetSecurityEventsQuery) -> tuple[datetime, datetime]:
        """Normalize and validate time range for the query."""
        
        if query.start_date and query.end_date:
            start_date, end_date = query.start_date, query.end_date
        elif query.last_hours:
            end_date = datetime.now(UTC)
            start_date = end_date - timedelta(hours=query.last_hours)
        else:
            # Default to last 24 hours
            end_date = datetime.now(UTC)
            start_date = end_date - timedelta(hours=24)
        
        # Validate time range
        if start_date >= end_date:
            raise InvalidEventFilterError("Start date must be before end date")
        
        # Limit maximum time range for performance
        max_days = 30 if query.real_time else 90
        if (end_date - start_date).days > max_days:
            raise InvalidEventFilterError(f"Time range cannot exceed {max_days} days")
        
        return start_date, end_date
    
    async def _build_filter_criteria(
        self, 
        query: GetSecurityEventsQuery,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Build filter criteria from query parameters."""
        
        filters = {
            "start_date": start_date,
            "end_date": end_date
        }
        
        if query.event_types:
            filters["event_types"] = [event_type.value for event_type in query.event_types]
        
        if query.severity_levels:
            filters["severity_levels"] = [severity.value for severity in query.severity_levels]
        
        if query.risk_levels:
            filters["risk_levels"] = [risk.value for risk in query.risk_levels]
        
        if query.threat_categories:
            filters["threat_categories"] = [category.value for category in query.threat_categories]
        
        if query.user_ids:
            filters["user_ids"] = [str(uid) for uid in query.user_ids]
        
        if query.session_ids:
            filters["session_ids"] = [str(sid) for sid in query.session_ids]
        
        if query.source_ips:
            filters["source_ips"] = query.source_ips
        
        if query.correlation_ids:
            filters["correlation_ids"] = query.correlation_ids
        
        if query.incident_ids:
            filters["incident_ids"] = [str(iid) for iid in query.incident_ids]
        
        return filters
    
    async def _apply_correlation_analysis(
        self, 
        events: list[dict[str, Any]], 
        query: GetSecurityEventsQuery
    ) -> list[dict[str, Any]]:
        """Apply correlation analysis to security events."""
        
        correlated_events = []
        
        for event in events:
            # Find correlated events within the time window
            correlation_window = timedelta(minutes=query.correlation_window_minutes)
            event_time = event.get("timestamp")
            
            if event_time:
                # Define correlation criteria
                correlation_criteria = {
                    "user_id": event.get("user_id"),
                    "source_ip": event.get("source_ip"),
                    "session_id": event.get("session_id"),
                    "time_window": correlation_window
                }
                
                # Find related events
                related = await self.security_repository.find_correlated_events(
                    event["id"], correlation_criteria
                )
                
                # Calculate correlation score
                correlation_score = await self._calculate_correlation_score(event, related)
                
                # Add correlation information
                enhanced_event = event.copy()
                enhanced_event.update({
                    "correlation": {
                        "score": correlation_score,
                        "related_event_count": len(related),
                        "related_event_ids": [r["id"] for r in related],
                        "correlation_patterns": await self._identify_patterns(event, related)
                    }
                })
                
                correlated_events.append(enhanced_event)
            else:
                correlated_events.append(event)
        
        return correlated_events
    
    async def _enrich_with_threat_intel(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich events with threat intelligence data."""
        
        enriched_events = []
        
        for event in events:
            enhanced_event = event.copy()
            
            # Get threat intelligence for source IP
            source_ip = event.get("source_ip")
            if source_ip:
                threat_intel = await self._get_threat_intelligence(source_ip)
                if threat_intel:
                    enhanced_event["threat_intelligence"] = threat_intel
            
            # Get threat intelligence for user behavior
            user_id = event.get("user_id")
            if user_id:
                behavioral_intel = await self._get_behavioral_intelligence(user_id, event)
                if behavioral_intel:
                    enhanced_event["behavioral_intelligence"] = behavioral_intel
            
            # Get threat intelligence for attack patterns
            attack_patterns = await self._identify_attack_patterns(event)
            if attack_patterns:
                enhanced_event["attack_patterns"] = attack_patterns
            
            enriched_events.append(enhanced_event)
        
        return enriched_events
    
    async def _add_context_information(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Add contextual information to security events."""
        
        contextualized_events = []
        
        for event in events:
            enhanced_event = event.copy()
            
            # Add user context
            user_id = event.get("user_id")
            if user_id:
                user = await self.user_repository.find_by_id(UUID(user_id))
                if user:
                    enhanced_event["user_context"] = {
                        "username": user.username,
                        "email": user.email,
                        "roles": user.roles,
                        "department": getattr(user, "department", None),
                        "last_login": user.last_login_at
                    }
            
            # Add session context
            session_id = event.get("session_id")
            if session_id:
                session = await self.session_repository.find_by_id(UUID(session_id))
                if session:
                    enhanced_event["session_context"] = {
                        "created_at": session.created_at,
                        "user_agent": session.user_agent,
                        "device_fingerprint": getattr(session, "device_fingerprint", None),
                        "location": getattr(session, "location", None)
                    }
            
            # Add geolocation context
            source_ip = event.get("source_ip")
            if source_ip:
                geo_data = await self._get_geolocation(source_ip)
                if geo_data:
                    enhanced_event["geolocation"] = geo_data
            
            # Add temporal context
            enhanced_event["temporal_context"] = await self._get_temporal_context(event)
            
            contextualized_events.append(enhanced_event)
        
        return contextualized_events
    
    async def _find_related_events(
        self, 
        events: list[dict[str, Any]], 
        query: GetSecurityEventsQuery
    ) -> list[dict[str, Any]]:
        """Find events related to the primary events."""
        
        related_events = []
        
        for event in events:
            # Find events with same correlation ID
            correlation_id = event.get("correlation_id")
            if correlation_id:
                correlated = await self.security_repository.get_events_by_correlation_id(
                    correlation_id
                )
                related_events.extend(correlated)
            
            # Find events from same session
            session_id = event.get("session_id")
            if session_id:
                session_events = await self.security_repository.get_events_by_session(
                    UUID(session_id)
                )
                related_events.extend(session_events)
            
            # Find events from same user around the same time
            user_id = event.get("user_id")
            timestamp = event.get("timestamp")
            if user_id and timestamp:
                time_window = timedelta(hours=1)
                start_time = timestamp - time_window
                end_time = timestamp + time_window
                
                user_events = await self.security_repository.get_user_events_in_timeframe(
                    UUID(user_id), start_time, end_time
                )
                related_events.extend(user_events)
        
        # Remove duplicates and events already in the main list
        event_ids = {event["id"] for event in events}
        unique_related = []
        seen_ids = set()
        
        for related_event in related_events:
            if (related_event["id"] not in event_ids and 
                related_event["id"] not in seen_ids):
                unique_related.append(related_event)
                seen_ids.add(related_event["id"])
        
        return unique_related
    
    async def _generate_events_timeline(
        self, 
        events: list[dict[str, Any]], 
        query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """Generate a timeline view of security events."""
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", datetime.min))
        
        # Group events by time intervals
        timeline_intervals = []
        current_interval = None
        interval_duration = timedelta(minutes=15)  # 15-minute intervals
        
        for event in sorted_events:
            event_time = event.get("timestamp")
            if not event_time:
                continue
                
            # Determine which interval this event belongs to
            interval_start = event_time.replace(
                minute=(event_time.minute // 15) * 15, 
                second=0, 
                microsecond=0
            )
            interval_end = interval_start + interval_duration
            
            # Create new interval if needed
            if not current_interval or current_interval["start"] != interval_start:
                current_interval = {
                    "start": interval_start,
                    "end": interval_end,
                    "events": [],
                    "event_count": 0,
                    "severity_distribution": {},
                    "type_distribution": {}
                }
                timeline_intervals.append(current_interval)
            
            # Add event to current interval
            current_interval["events"].append(event)
            current_interval["event_count"] += 1
            
            # Update distributions
            severity = event.get("severity", "unknown")
            current_interval["severity_distribution"][severity] = (
                current_interval["severity_distribution"].get(severity, 0) + 1
            )
            
            event_type = event.get("type", "unknown")
            current_interval["type_distribution"][event_type] = (
                current_interval["type_distribution"].get(event_type, 0) + 1
            )
        
        return {
            "timeline_intervals": timeline_intervals,
            "total_intervals": len(timeline_intervals),
            "interval_duration_minutes": 15,
            "earliest_event": sorted_events[0]["timestamp"] if sorted_events else None,
            "latest_event": sorted_events[-1]["timestamp"] if sorted_events else None
        }
    
    async def _group_events(
        self, 
        events: list[dict[str, Any]], 
        group_by: EventGrouping
    ) -> dict[str, list[dict[str, Any]]]:
        """Group events by specified criteria."""
        
        grouped = {}
        
        for event in events:
            if group_by == EventGrouping.BY_TYPE:
                key = event.get("type", "unknown")
            elif group_by == EventGrouping.BY_USER:
                key = event.get("user_id", "unknown")
            elif group_by == EventGrouping.BY_SOURCE:
                key = event.get("source_ip", "unknown")
            elif group_by == EventGrouping.BY_SEVERITY:
                key = event.get("severity", "unknown")
            elif group_by == EventGrouping.BY_THREAT:
                key = event.get("threat_category", "unknown")
            elif group_by == EventGrouping.BY_TIME:
                timestamp = event.get("timestamp")
                if timestamp:
                    # Group by hour
                    key = timestamp.strftime("%Y-%m-%d %H:00")
                else:
                    key = "unknown"
            else:
                key = "default"
            
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(event)
        
        return grouped
    
    async def _aggregate_similar_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Aggregate similar events to reduce noise."""
        
        # Group similar events
        similar_groups = {}
        
        for event in events:
            # Create similarity key based on type, user, and source
            similarity_key = (
                event.get("type"),
                event.get("user_id"),
                event.get("source_ip"),
                event.get("threat_category")
            )
            
            if similarity_key not in similar_groups:
                similar_groups[similarity_key] = []
            similar_groups[similarity_key].append(event)
        
        # Create aggregated events for groups with multiple occurrences
        aggregated = []
        
        for similarity_key, group_events in similar_groups.items():
            if len(group_events) > 1:
                # Create aggregated event
                first_event = group_events[0]
                last_event = group_events[-1]
                
                aggregated_event = {
                    "id": f"aggregated_{first_event['id']}",
                    "type": first_event.get("type"),
                    "aggregated": True,
                    "event_count": len(group_events),
                    "first_occurrence": first_event.get("timestamp"),
                    "last_occurrence": last_event.get("timestamp"),
                    "user_id": first_event.get("user_id"),
                    "source_ip": first_event.get("source_ip"),
                    "severity": max(
                        (event.get("severity") for event in group_events),
                        key=lambda x: ["low", "medium", "high", "critical"].index(x) if x in ["low", "medium", "high", "critical"] else 0,
                        default="medium"
                    ),
                    "threat_category": first_event.get("threat_category"),
                    "pattern_analysis": await self._analyze_event_pattern(group_events),
                    "original_event_ids": [event["id"] for event in group_events]
                }
                
                aggregated.append(aggregated_event)
            else:
                # Single event, add as-is
                aggregated.extend(group_events)
        
        return aggregated
    
    async def _generate_event_statistics(
        self, 
        events: list[dict[str, Any]], 
        filter_criteria: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate statistics for the security events."""
        
        if not events:
            return {
                "total_events": 0,
                "severity_distribution": {},
                "type_distribution": {},
                "hourly_distribution": {},
                "top_users": [],
                "top_source_ips": [],
                "threat_categories": {}
            }
        
        # Count by severity
        severity_count = {}
        for event in events:
            severity = event.get("severity", "unknown")
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        # Count by type
        type_count = {}
        for event in events:
            event_type = event.get("type", "unknown")
            type_count[event_type] = type_count.get(event_type, 0) + 1
        
        # Count by hour
        hourly_count = {}
        for event in events:
            timestamp = event.get("timestamp")
            if timestamp:
                hour = timestamp.hour
                hourly_count[hour] = hourly_count.get(hour, 0) + 1
        
        # Top users
        user_count = {}
        for event in events:
            user_id = event.get("user_id")
            if user_id:
                user_count[user_id] = user_count.get(user_id, 0) + 1
        
        top_users = sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Top source IPs
        ip_count = {}
        for event in events:
            source_ip = event.get("source_ip")
            if source_ip:
                ip_count[source_ip] = ip_count.get(source_ip, 0) + 1
        
        top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Threat categories
        threat_count = {}
        for event in events:
            threat_category = event.get("threat_category")
            if threat_category:
                threat_count[threat_category] = threat_count.get(threat_category, 0) + 1
        
        return {
            "total_events": len(events),
            "severity_distribution": severity_count,
            "type_distribution": type_count,
            "hourly_distribution": hourly_count,
            "top_users": top_users,
            "top_source_ips": top_ips,
            "threat_categories": threat_count,
            "time_range": {
                "start": filter_criteria.get("start_date"),
                "end": filter_criteria.get("end_date")
            }
        }
    
    # Helper methods (placeholder implementations)
    async def _calculate_correlation_score(self, event: dict[str, Any], related: list[dict[str, Any]]) -> float:
        """Calculate correlation score between events."""
        return min(len(related) * 0.2, 1.0)
    
    async def _identify_patterns(self, event: dict[str, Any], related: list[dict[str, Any]]) -> list[str]:
        """Identify patterns in correlated events."""
        patterns = []
        if len(related) > 3:
            patterns.append("high_frequency_pattern")
        if any(r.get("severity") == "high" for r in related):
            patterns.append("escalating_severity")
        return patterns
    
    async def _get_threat_intelligence(self, source_ip: str) -> dict[str, Any] | None:
        """Get threat intelligence for source IP."""
        # Placeholder implementation
        return {
            "reputation_score": 75,
            "known_threats": ["suspicious_login", "brute_force"],
            "geographic_risk": "medium"
        }
    
    async def _get_behavioral_intelligence(self, user_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
        """Get behavioral intelligence for user."""
        return {
            "risk_score": 65,
            "baseline_deviation": "moderate",
            "recent_anomalies": 2
        }
    
    async def _identify_attack_patterns(self, event: dict[str, Any]) -> list[str]:
        """Identify attack patterns in event."""
        return ["credential_stuffing", "lateral_movement"]
    
    async def _get_geolocation(self, ip_address: str) -> dict[str, Any] | None:
        """Get geolocation data for IP address."""
        return {
            "country": "Unknown",
            "city": "Unknown",
            "coordinates": {"lat": 0.0, "lon": 0.0}
        }
    
    async def _get_temporal_context(self, event: dict[str, Any]) -> dict[str, Any]:
        """Get temporal context for event."""
        return {
            "business_hours": True,
            "day_of_week": "Monday",
            "holiday": False
        }
    
    async def _analyze_event_pattern(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze patterns in aggregated events."""
        return {
            "frequency": "increasing",
            "duration": "30 minutes",
            "intensity": "medium"
        }
    
    async def _prepare_export_data(self, events: list[dict[str, Any]], export_format: str) -> dict[str, Any]:
        """Prepare events for export."""
        return {
            "format": export_format,
            "content": f"Security events in {export_format} format",
            "filename": f"security_events_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}"
        }