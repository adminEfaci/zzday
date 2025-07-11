"""
Get user activity query implementation.

Handles retrieval of detailed user activity logs including login patterns,
resource access, behavior analysis, and activity reporting.
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
from app.modules.identity.application.dtos.response import UserActivityResponse
from app.modules.identity.domain.enums import AuditAction, RiskLevel, SessionStatus
from app.modules.identity.domain.exceptions import (
    InvalidUserError,
    UnauthorizedAccessError,
    UserActivityQueryError,
)
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)


class ActivityType(Enum):
    """Types of user activities to track."""
    LOGIN_LOGOUT = "login_logout"
    RESOURCE_ACCESS = "resource_access"
    PRIVILEGE_USAGE = "privilege_usage"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGES = "configuration_changes"
    SECURITY_EVENTS = "security_events"
    FAILED_ATTEMPTS = "failed_attempts"
    SESSION_ACTIVITIES = "session_activities"


class ActivityGrouping(Enum):
    """Grouping options for user activities."""
    BY_DATE = "by_date"
    BY_HOUR = "by_hour"
    BY_ACTIVITY_TYPE = "by_activity_type"
    BY_RESOURCE = "by_resource"
    BY_DEVICE = "by_device"
    BY_LOCATION = "by_location"
    BY_SESSION = "by_session"


class ActivityAnalysis(Enum):
    """Types of activity analysis to perform."""
    BEHAVIOR_PATTERNS = "behavior_patterns"
    ANOMALY_DETECTION = "anomaly_detection"
    RISK_ASSESSMENT = "risk_assessment"
    TREND_ANALYSIS = "trend_analysis"
    COMPLIANCE_CHECK = "compliance_check"


@dataclass
class GetUserActivityQuery(Query[UserActivityResponse]):
    """Query to retrieve user activity information."""
    
    # Target user
    user_id: UUID
    requester_id: UUID

    # Time filters
    start_date: datetime | None = None
    end_date: datetime | None = None
    last_days: int | None = None
    
    # Activity filters
    activity_types: list[ActivityType] | None = None
    actions: list[AuditAction] | None = None
    resources: list[str] | None = None
    devices: list[str] | None = None
    locations: list[str] | None = None
    ip_addresses: list[str] | None = None
    
    # Analysis options
    include_behavior_analysis: bool = False
    include_anomaly_detection: bool = False
    include_risk_assessment: bool = False
    include_session_analysis: bool = True
    include_device_analysis: bool = False
    include_location_analysis: bool = False
    
    # Grouping and aggregation
    group_by: ActivityGrouping | None = None
    include_summary_statistics: bool = True
    include_trends: bool = False
    include_comparisons: bool = False
    
    # Output options
    sort_by: str = "timestamp"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 100
    export_format: str | None = None
    
    # Privacy and compliance
    mask_sensitive_data: bool = True
    compliance_mode: bool = False
    audit_access: bool = True
    
    # Access control

    requester_permissions: list[str] = field(default_factory=list)


class GetUserActivityQueryHandler(
    QueryHandler[GetUserActivityQuery, UserActivityResponse]
):
    """Handler for user activity queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        access_repository: IAccessRepository
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.access_repository = access_repository
    
    @rate_limit(max_calls=50, window_seconds=3600)
    @require_permission("audit.user_activity.read")
    @validate_request
    async def handle(self, query: GetUserActivityQuery) -> UserActivityResponse:
        """Handle user activity query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_activity_access(query)
                
                # Verify target user exists
                target_user = await self.user_repository.find_by_id(query.user_id)
                if not target_user:
                    raise InvalidUserError(f"User {query.user_id} not found")
                
                # Normalize time range
                start_date, end_date = await self._normalize_time_range(query)
                
                # Build filter criteria
                filter_criteria = await self._build_filter_criteria(
                    query, start_date, end_date
                )
                
                # Retrieve user activities
                activities = await self.audit_repository.get_user_activities(
                    user_id=query.user_id,
                    filters=filter_criteria,
                    sort_by=query.sort_by,
                    sort_order=query.sort_order,
                    page=query.page,
                    page_size=query.page_size
                )
                
                # Get total count
                total_count = await self.audit_repository.count_user_activities(
                    query.user_id, filter_criteria
                )
                
                # Apply data masking if required
                if query.mask_sensitive_data:
                    activities = await self._mask_sensitive_data(activities, query)
                
                # Retrieve session information if requested
                session_analysis = None
                if query.include_session_analysis:
                    session_analysis = await self._analyze_user_sessions(
                        query.user_id, start_date, end_date
                    )
                
                # Perform behavior analysis if requested
                behavior_analysis = None
                if query.include_behavior_analysis:
                    behavior_analysis = await self._analyze_user_behavior(
                        query.user_id, activities, start_date, end_date
                    )
                
                # Perform anomaly detection if requested
                anomaly_analysis = None
                if query.include_anomaly_detection:
                    anomaly_analysis = await self._detect_activity_anomalies(
                        query.user_id, activities
                    )
                
                # Perform risk assessment if requested
                risk_assessment = None
                if query.include_risk_assessment:
                    risk_assessment = await self._assess_activity_risk(
                        query.user_id, activities
                    )
                
                # Perform device analysis if requested
                device_analysis = None
                if query.include_device_analysis:
                    device_analysis = await self._analyze_device_usage(
                        query.user_id, activities, start_date, end_date
                    )
                
                # Perform location analysis if requested
                location_analysis = None
                if query.include_location_analysis:
                    location_analysis = await self._analyze_location_patterns(
                        query.user_id, activities, start_date, end_date
                    )
                
                # Apply grouping if requested
                grouped_activities = None
                if query.group_by:
                    grouped_activities = await self._group_activities(activities, query.group_by)
                
                # Generate summary statistics if requested
                summary_statistics = None
                if query.include_summary_statistics:
                    summary_statistics = await self._generate_summary_statistics(
                        activities, start_date, end_date
                    )
                
                # Generate trends if requested
                trend_analysis = None
                if query.include_trends:
                    trend_analysis = await self._generate_trend_analysis(
                        query.user_id, start_date, end_date
                    )
                
                # Generate comparisons if requested
                comparison_analysis = None
                if query.include_comparisons:
                    comparison_analysis = await self._generate_comparison_analysis(
                        query.user_id, activities, start_date, end_date
                    )
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        activities, query.export_format, query
                    )
                
                # Log audit access if enabled
                if query.audit_access:
                    await self._log_audit_access(query, target_user)
                
                return UserActivityResponse(
                    user_id=query.user_id,
                    user_info={
                        "username": target_user.username,
                        "email": target_user.email,
                        "full_name": f"{target_user.first_name} {target_user.last_name}",
                        "roles": target_user.roles
                    },
                    activities=activities,
                    grouped_activities=grouped_activities,
                    session_analysis=session_analysis,
                    behavior_analysis=behavior_analysis,
                    anomaly_analysis=anomaly_analysis,
                    risk_assessment=risk_assessment,
                    device_analysis=device_analysis,
                    location_analysis=location_analysis,
                    summary_statistics=summary_statistics,
                    trend_analysis=trend_analysis,
                    comparison_analysis=comparison_analysis,
                    total_count=total_count,
                    page=query.page,
                    page_size=query.page_size,
                    total_pages=(total_count + query.page_size - 1) // query.page_size,
                    filters_applied=filter_criteria,
                    query_timestamp=datetime.now(UTC),
                    export_data=export_data
                )
                
        except Exception as e:
            raise UserActivityQueryError(f"Failed to retrieve user activity: {e!s}") from e
    
    async def _validate_activity_access(self, query: GetUserActivityQuery) -> None:
        """Validate user has appropriate permissions for activity access."""
        
        # Check basic user activity read permission
        if "audit.user_activity.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for user activity access")
        
        # Check if accessing own activity vs others'
        if query.user_id != query.requester_id:
            if "audit.user_activity.read.all" not in query.requester_permissions:
                raise UnauthorizedAccessError("Cannot access other users' activity data")
        
        # Check sensitive analysis permissions
        sensitive_analyses = [
            query.include_behavior_analysis,
            query.include_anomaly_detection,
            query.include_risk_assessment
        ]
        
        if any(sensitive_analyses):
            if "audit.advanced_analysis" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for advanced activity analysis")
        
        # Check compliance mode access
        if query.compliance_mode:
            if "compliance.audit_access" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for compliance mode access")
    
    async def _normalize_time_range(self, query: GetUserActivityQuery) -> tuple[datetime, datetime]:
        """Normalize and validate time range for the query."""
        
        if query.start_date and query.end_date:
            start_date, end_date = query.start_date, query.end_date
        elif query.last_days:
            end_date = datetime.now(UTC)
            start_date = end_date - timedelta(days=query.last_days)
        else:
            # Default to last 7 days
            end_date = datetime.now(UTC)
            start_date = end_date - timedelta(days=7)
        
        # Validate time range
        if start_date >= end_date:
            raise UserActivityQueryError("Start date must be before end date")
        
        # Limit maximum time range for performance
        max_days = 90
        if (end_date - start_date).days > max_days:
            raise UserActivityQueryError(f"Time range cannot exceed {max_days} days")
        
        return start_date, end_date
    
    async def _build_filter_criteria(
        self,
        query: GetUserActivityQuery,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Build filter criteria from query parameters."""
        
        filters = {
            "start_date": start_date,
            "end_date": end_date
        }
        
        if query.activity_types:
            filters["activity_types"] = [activity_type.value for activity_type in query.activity_types]
        
        if query.actions:
            filters["actions"] = [action.value for action in query.actions]
        
        if query.resources:
            filters["resources"] = query.resources
        
        if query.devices:
            filters["devices"] = query.devices
        
        if query.locations:
            filters["locations"] = query.locations
        
        if query.ip_addresses:
            filters["ip_addresses"] = query.ip_addresses
        
        return filters
    
    async def _mask_sensitive_data(
        self,
        activities: list[dict[str, Any]],
        query: GetUserActivityQuery
    ) -> list[dict[str, Any]]:
        """Mask sensitive data in activities based on permissions."""
        
        masked_activities = []
        
        for activity in activities:
            masked_activity = activity.copy()
            
            # Mask IP addresses if not authorized
            if "audit.view_ip_addresses" not in query.requester_permissions:
                if "source_ip" in masked_activity:
                    ip_parts = masked_activity["source_ip"].split(".")
                    if len(ip_parts) == 4:
                        masked_activity["source_ip"] = f"{ip_parts[0]}.{ip_parts[1]}.*.* "
            
            # Mask detailed resource paths if not authorized
            if "audit.view_detailed_resources" not in query.requester_permissions:
                if "resource" in masked_activity:
                    resource = masked_activity["resource"]
                    if "/" in resource:
                        parts = resource.split("/")
                        masked_activity["resource"] = f"{parts[0]}/***"
            
            # Mask user agent details if not authorized
            if "audit.view_user_agents" not in query.requester_permissions:
                if "user_agent" in masked_activity:
                    masked_activity["user_agent"] = "***"
            
            # Mask session details if not authorized
            if "audit.view_session_details" not in query.requester_permissions:
                if "session_id" in masked_activity:
                    masked_activity["session_id"] = "***"
            
            masked_activities.append(masked_activity)
        
        return masked_activities
    
    async def _analyze_user_sessions(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Analyze user session patterns and statistics."""
        
        # Get user sessions in the time range
        sessions = await self.session_repository.get_user_sessions(
            user_id, start_date, end_date
        )
        
        if not sessions:
            return {
                "total_sessions": 0,
                "average_duration": None,
                "device_breakdown": {},
                "location_breakdown": {},
                "concurrent_sessions": []
            }
        
        # Calculate session statistics
        total_sessions = len(sessions)
        active_sessions = len([s for s in sessions if s.status == SessionStatus.ACTIVE])
        
        # Calculate average session duration
        durations = []
        for session in sessions:
            if session.ended_at:
                duration = (session.ended_at - session.created_at).total_seconds()
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else None
        
        # Device breakdown
        device_breakdown = {}
        for session in sessions:
            device = getattr(session, "device_type", "unknown")
            device_breakdown[device] = device_breakdown.get(device, 0) + 1
        
        # Location breakdown
        location_breakdown = {}
        for session in sessions:
            location = getattr(session, "location", "unknown")
            location_breakdown[location] = location_breakdown.get(location, 0) + 1
        
        # Find concurrent sessions
        concurrent_sessions = await self._find_concurrent_sessions(sessions)
        
        # Calculate session patterns
        session_patterns = await self._analyze_session_patterns(sessions)
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "average_duration_seconds": avg_duration,
            "device_breakdown": device_breakdown,
            "location_breakdown": location_breakdown,
            "concurrent_sessions": concurrent_sessions,
            "session_patterns": session_patterns,
            "unusual_sessions": await self._identify_unusual_sessions(sessions)
        }
    
    async def _analyze_user_behavior(
        self,
        user_id: UUID,
        activities: list[dict[str, Any]],
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Analyze user behavior patterns."""
        
        # Activity frequency analysis
        activity_frequency = await self._analyze_activity_frequency(activities)
        
        # Time pattern analysis
        time_patterns = await self._analyze_time_patterns(activities)
        
        # Resource access patterns
        resource_patterns = await self._analyze_resource_patterns(activities)
        
        # Behavior baseline comparison
        baseline_comparison = await self._compare_to_baseline(user_id, activities, start_date, end_date)
        
        # Identify behavior changes
        behavior_changes = await self._identify_behavior_changes(user_id, activities)
        
        return {
            "activity_frequency": activity_frequency,
            "time_patterns": time_patterns,
            "resource_patterns": resource_patterns,
            "baseline_comparison": baseline_comparison,
            "behavior_changes": behavior_changes,
            "risk_indicators": await self._identify_risk_indicators(activities)
        }
    
    async def _detect_activity_anomalies(
        self,
        user_id: UUID,
        activities: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Detect anomalies in user activities."""
        
        anomalies = []
        
        # Time-based anomalies
        time_anomalies = await self._detect_time_anomalies(activities)
        anomalies.extend(time_anomalies)
        
        # Frequency anomalies
        frequency_anomalies = await self._detect_frequency_anomalies(activities)
        anomalies.extend(frequency_anomalies)
        
        # Location anomalies
        location_anomalies = await self._detect_location_anomalies(activities)
        anomalies.extend(location_anomalies)
        
        # Access pattern anomalies
        access_anomalies = await self._detect_access_pattern_anomalies(activities)
        anomalies.extend(access_anomalies)
        
        # Calculate anomaly score
        anomaly_score = await self._calculate_anomaly_score(anomalies)
        
        return {
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "anomaly_score": anomaly_score,
            "risk_level": await self._determine_anomaly_risk_level(anomaly_score),
            "recommendations": await self._generate_anomaly_recommendations(anomalies)
        }
    
    async def _assess_activity_risk(
        self,
        user_id: UUID,
        activities: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Assess risk based on user activities."""
        
        risk_factors = []
        risk_score = 0
        
        # Assess privilege usage risk
        privilege_risk = await self._assess_privilege_usage_risk(activities)
        risk_factors.append(privilege_risk)
        risk_score += privilege_risk["score"]
        
        # Assess data access risk
        data_access_risk = await self._assess_data_access_risk(activities)
        risk_factors.append(data_access_risk)
        risk_score += data_access_risk["score"]
        
        # Assess authentication risk
        auth_risk = await self._assess_authentication_risk(activities)
        risk_factors.append(auth_risk)
        risk_score += auth_risk["score"]
        
        # Assess behavioral risk
        behavioral_risk = await self._assess_behavioral_risk(activities)
        risk_factors.append(behavioral_risk)
        risk_score += behavioral_risk["score"]
        
        # Normalize risk score
        normalized_score = min(risk_score / len(risk_factors), 100) if risk_factors else 0
        
        # Determine risk level
        if normalized_score >= 80:
            risk_level = RiskLevel.HIGH
        elif normalized_score >= 60:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return {
            "risk_score": normalized_score,
            "risk_level": risk_level.value,
            "risk_factors": risk_factors,
            "recommendations": await self._generate_risk_recommendations(risk_factors),
            "monitoring_suggestions": await self._generate_monitoring_suggestions(risk_level)
        }
    
    # Helper methods for data generation (placeholder implementations)
    async def _group_activities(
        self,
        activities: list[dict[str, Any]],
        group_by: ActivityGrouping
    ) -> dict[str, list[dict[str, Any]]]:
        """Group activities by specified criteria."""
        grouped = {}
        for activity in activities:
            if group_by == ActivityGrouping.BY_DATE:
                key = activity.get("timestamp", datetime.now()).strftime("%Y-%m-%d")
            elif group_by == ActivityGrouping.BY_ACTIVITY_TYPE:
                key = activity.get("type", "unknown")
            else:
                key = "default"
            
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(activity)
        return grouped
    
    async def _generate_summary_statistics(
        self,
        activities: list[dict[str, Any]],
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Generate summary statistics for activities."""
        return {
            "total_activities": len(activities),
            "unique_resources": len({a.get("resource", "") for a in activities}),
            "unique_devices": len({a.get("device", "") for a in activities}),
            "time_span_days": (end_date - start_date).days
        }
    
    async def _log_audit_access(self, query: GetUserActivityQuery, target_user) -> None:
        """Log the audit access for compliance."""
        # Implementation would log the audit access
    
    # Placeholder implementations for complex analysis methods
    async def _find_concurrent_sessions(self, sessions: list) -> list[dict[str, Any]]:
        return []
    
    async def _analyze_session_patterns(self, sessions: list) -> dict[str, Any]:
        return {"pattern": "regular"}
    
    async def _identify_unusual_sessions(self, sessions: list) -> list[dict[str, Any]]:
        return []
    
    async def _analyze_activity_frequency(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"frequency": "normal"}
    
    async def _analyze_time_patterns(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"pattern": "business_hours"}
    
    async def _analyze_resource_patterns(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"pattern": "typical"}
    
    async def _compare_to_baseline(self, user_id: UUID, activities: list[dict[str, Any]], start_date: datetime, end_date: datetime) -> dict[str, Any]:
        return {"deviation": "low"}
    
    async def _identify_behavior_changes(self, user_id: UUID, activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []
    
    async def _identify_risk_indicators(self, activities: list[dict[str, Any]]) -> list[str]:
        return []
    
    async def _detect_time_anomalies(self, activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []
    
    async def _detect_frequency_anomalies(self, activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []
    
    async def _detect_location_anomalies(self, activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []
    
    async def _detect_access_pattern_anomalies(self, activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return []
    
    async def _calculate_anomaly_score(self, anomalies: list[dict[str, Any]]) -> float:
        return len(anomalies) * 10.0
    
    async def _determine_anomaly_risk_level(self, score: float) -> str:
        return "low" if score < 50 else "medium" if score < 80 else "high"
    
    async def _generate_anomaly_recommendations(self, anomalies: list[dict[str, Any]]) -> list[str]:
        return ["Review unusual access patterns", "Monitor user behavior"]
    
    async def _assess_privilege_usage_risk(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"category": "privilege_usage", "score": 25, "description": "Normal privilege usage"}
    
    async def _assess_data_access_risk(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"category": "data_access", "score": 20, "description": "Standard data access patterns"}
    
    async def _assess_authentication_risk(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"category": "authentication", "score": 15, "description": "Normal authentication behavior"}
    
    async def _assess_behavioral_risk(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {"category": "behavioral", "score": 10, "description": "Consistent behavior patterns"}
    
    async def _generate_risk_recommendations(self, risk_factors: list[dict[str, Any]]) -> list[str]:
        return ["Continue monitoring", "Review access controls"]
    
    async def _generate_monitoring_suggestions(self, risk_level: RiskLevel) -> list[str]:
        return ["Standard monitoring", "Periodic reviews"]
    
    async def _analyze_device_usage(self, user_id: UUID, activities: list[dict[str, Any]], start_date: datetime, end_date: datetime) -> dict[str, Any]:
        return {"devices_used": 2, "new_devices": 0}
    
    async def _analyze_location_patterns(self, user_id: UUID, activities: list[dict[str, Any]], start_date: datetime, end_date: datetime) -> dict[str, Any]:
        return {"locations": ["Office", "Home"], "unusual_locations": []}
    
    async def _generate_trend_analysis(self, user_id: UUID, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        return {"trend": "stable"}
    
    async def _generate_comparison_analysis(self, user_id: UUID, activities: list[dict[str, Any]], start_date: datetime, end_date: datetime) -> dict[str, Any]:
        return {"peer_comparison": "similar"}
    
    async def _prepare_export_data(self, activities: list[dict[str, Any]], export_format: str, query: GetUserActivityQuery) -> dict[str, Any]:
        return {
            "format": export_format,
            "content": f"User activity data in {export_format} format",
            "filename": f"user_activity_{query.user_id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}"
        }