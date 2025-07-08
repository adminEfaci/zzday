"""Get user activity query.

This module implements the query and handler for retrieving user-specific
audit activity with analytics and insights.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_entry_dto import AuditEntryDTO

logger = get_logger(__name__)


class GetUserActivityQuery(Query):
    """
    Query to retrieve user activity from audit logs.

    Provides comprehensive user activity analysis including
    recent actions, patterns, and behavioral insights.
    """

    def __init__(
        self,
        user_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        include_sessions: bool = True,
        include_statistics: bool = True,
        include_patterns: bool = False,
        activity_limit: int | None = None,
    ):
        """
        Initialize get user activity query.

        Args:
            user_id: ID of the user to analyze
            start_date: Start of analysis period
            end_date: End of analysis period
            include_sessions: Whether to include session information
            include_statistics: Whether to include activity statistics
            include_patterns: Whether to analyze activity patterns
            activity_limit: Maximum number of activities to return
        """
        super().__init__()

        self.user_id = self._validate_user_id(user_id)
        self.start_date = start_date or (datetime.utcnow() - timedelta(days=30))
        self.end_date = end_date or datetime.utcnow()
        self.include_sessions = include_sessions
        self.include_statistics = include_statistics
        self.include_patterns = include_patterns
        self.activity_limit = self._validate_activity_limit(activity_limit)

        # Validate date range
        if self.start_date >= self.end_date:
            raise ValidationError("Start date must be before end date")

        # Set pagination
        self.page_size = activity_limit or 100

        self._freeze()

    def _validate_user_id(self, user_id: UUID) -> UUID:
        """Validate user ID."""
        if not isinstance(user_id, UUID):
            raise ValidationError("User ID must be a valid UUID")
        return user_id

    def _validate_activity_limit(self, limit: int | None) -> int | None:
        """Validate activity limit."""
        if limit is not None and (limit < 1 or limit > 10000):
            raise ValidationError("Activity limit must be between 1 and 10000")
        return limit


class GetUserActivityQueryHandler(QueryHandler[GetUserActivityQuery, dict[str, Any]]):
    """
    Handler for retrieving user activity.

    This handler analyzes user activity patterns and provides
    comprehensive insights into user behavior.
    """

    def __init__(
        self,
        audit_repository: Any,
        user_service: Any,
        analytics_service: Any,
        session_repository: Any,
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit data access
            user_service: Service for user information
            analytics_service: Service for activity analysis
            session_repository: Repository for session data
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.user_service = user_service
        self.analytics_service = analytics_service
        self.session_repository = session_repository

    async def handle(self, query: GetUserActivityQuery) -> dict[str, Any]:
        """
        Handle the get user activity query.

        Args:
            query: Query containing analysis parameters

        Returns:
            Dictionary containing user activity data and insights
        """
        logger.debug(
            "Analyzing user activity",
            user_id=query.user_id,
            date_range=f"{query.start_date} to {query.end_date}",
        )

        # Get user information
        user_info = await self.user_service.get_user_info(query.user_id)

        # Fetch user's audit entries
        filters = {
            "user_id": query.user_id,
            "created_at__gte": query.start_date,
            "created_at__lte": query.end_date,
        }

        search_result = await self.audit_repository.search_entries(
            filters=filters,
            limit=query.activity_limit or 1000,
            order_by="created_at",
            order_direction="desc",
        )

        entries = search_result["entries"]

        # Convert to DTOs
        activity_dtos = []
        for entry in entries:
            activity_dto = AuditEntryDTO.from_domain(entry, user_info)
            activity_dtos.append(activity_dto.to_dict())

        # Build base response
        response = {
            "user": {"user_id": str(query.user_id), "user_info": user_info},
            "analysis_period": {
                "start_date": query.start_date.isoformat(),
                "end_date": query.end_date.isoformat(),
                "duration_days": (query.end_date - query.start_date).days,
            },
            "activities": activity_dtos[: query.activity_limit]
            if query.activity_limit
            else activity_dtos,
        }

        # Include statistics if requested
        if query.include_statistics:
            statistics = await self._generate_activity_statistics(entries, query)
            response["statistics"] = statistics

        # Include sessions if requested
        if query.include_sessions:
            sessions = await self._get_user_sessions(
                query.user_id, query.start_date, query.end_date
            )
            response["sessions"] = sessions

        # Include patterns if requested
        if query.include_patterns:
            patterns = await self._analyze_activity_patterns(entries, query)
            response["patterns"] = patterns

        logger.debug(
            "User activity analysis completed",
            user_id=query.user_id,
            activity_count=len(activity_dtos),
        )

        return response

    async def _generate_activity_statistics(
        self, entries: list[Any], query: GetUserActivityQuery
    ) -> dict[str, Any]:
        """
        Generate activity statistics.

        Args:
            entries: User's audit entries
            query: Original query

        Returns:
            Activity statistics
        """
        if not entries:
            return {
                "total_activities": 0,
                "unique_resources": 0,
                "success_rate": 0.0,
                "avg_daily_activities": 0.0,
            }

        # Basic counts
        total_activities = len(entries)
        successful_activities = len([e for e in entries if e.outcome == "success"])
        unique_resources = len({e.resource.resource_id for e in entries})

        # Success rate
        success_rate = (successful_activities / total_activities) * 100

        # Daily activity average
        duration_days = max(1, (query.end_date - query.start_date).days)
        avg_daily_activities = total_activities / duration_days

        # Activity by category
        by_category = {}
        for entry in entries:
            category = entry.category.value
            by_category[category] = by_category.get(category, 0) + 1

        # Activity by action type
        by_action = {}
        for entry in entries:
            action_type = entry.action.action_type
            by_action[action_type] = by_action.get(action_type, 0) + 1

        # Activity by outcome
        by_outcome = {}
        for entry in entries:
            outcome = entry.outcome
            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

        # Peak activity times
        hourly_activity = {}
        for entry in entries:
            hour = entry.created_at.hour
            hourly_activity[hour] = hourly_activity.get(hour, 0) + 1

        peak_hour = (
            max(hourly_activity.items(), key=lambda x: x[1])[0]
            if hourly_activity
            else None
        )

        return {
            "total_activities": total_activities,
            "successful_activities": successful_activities,
            "unique_resources": unique_resources,
            "success_rate": round(success_rate, 2),
            "avg_daily_activities": round(avg_daily_activities, 2),
            "by_category": by_category,
            "by_action_type": by_action,
            "by_outcome": by_outcome,
            "peak_activity_hour": peak_hour,
            "hourly_distribution": hourly_activity,
        }

    async def _get_user_sessions(
        self, user_id: UUID, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """
        Get user's audit sessions.

        Args:
            user_id: User ID
            start_date: Start date
            end_date: End date

        Returns:
            Session information
        """
        sessions = await self.session_repository.find_user_sessions(
            user_id=user_id, start_date=start_date, end_date=end_date
        )

        session_data = []
        for session in sessions:
            session_data.append(
                {
                    "session_id": str(session.id),
                    "session_type": session.session_type,
                    "started_at": session.started_at.isoformat(),
                    "ended_at": session.ended_at.isoformat()
                    if session.ended_at
                    else None,
                    "duration_seconds": session.get_duration_seconds(),
                    "entry_count": len(session.entry_ids),
                    "success_rate": session.get_success_rate(),
                    "is_active": session.is_active,
                }
            )

        return {
            "total_sessions": len(sessions),
            "active_sessions": len([s for s in sessions if s.is_active]),
            "sessions": session_data,
        }

    async def _analyze_activity_patterns(
        self, entries: list[Any], query: GetUserActivityQuery
    ) -> dict[str, Any]:
        """
        Analyze user activity patterns.

        Args:
            entries: User's audit entries
            query: Original query

        Returns:
            Activity patterns analysis
        """
        if not entries:
            return {"patterns_detected": False}

        # Time-based patterns
        daily_activity = {}
        for entry in entries:
            day = entry.created_at.date().isoformat()
            daily_activity[day] = daily_activity.get(day, 0) + 1

        # Resource access patterns
        resource_frequency = {}
        for entry in entries:
            resource_key = (
                f"{entry.resource.resource_type}:{entry.resource.resource_id}"
            )
            resource_frequency[resource_key] = (
                resource_frequency.get(resource_key, 0) + 1
            )

        # Most accessed resources
        top_resources = sorted(
            resource_frequency.items(), key=lambda x: x[1], reverse=True
        )[:10]

        # Activity consistency (variation in daily activity)
        if len(daily_activity) > 1:
            activity_values = list(daily_activity.values())
            avg_activity = sum(activity_values) / len(activity_values)
            variance = sum((x - avg_activity) ** 2 for x in activity_values) / len(
                activity_values
            )
            consistency_score = (
                max(0, 100 - (variance / avg_activity * 100)) if avg_activity > 0 else 0
            )
        else:
            consistency_score = 100

        # Detect anomalies using basic threshold
        anomalies = []
        if daily_activity:
            avg_daily = sum(daily_activity.values()) / len(daily_activity)
            threshold = avg_daily * 2  # Simple threshold

            for day, count in daily_activity.items():
                if count > threshold:
                    anomalies.append(
                        {
                            "date": day,
                            "activity_count": count,
                            "threshold": threshold,
                            "type": "high_activity",
                        }
                    )

        return {
            "patterns_detected": True,
            "daily_activity_distribution": daily_activity,
            "top_accessed_resources": [
                {"resource": resource, "access_count": count}
                for resource, count in top_resources
            ],
            "activity_consistency_score": round(consistency_score, 2),
            "anomalies": anomalies,
            "analysis_insights": [
                f"User accessed {len({e.resource.resource_type for e in entries})} different resource types",
                f"Most active day had {max(daily_activity.values()) if daily_activity else 0} activities",
                f"Activity consistency score: {round(consistency_score, 1)}%",
            ],
        }

    @property
    def query_type(self) -> type[GetUserActivityQuery]:
        """Get query type this handler processes."""
        return GetUserActivityQuery


__all__ = ["GetUserActivityQuery", "GetUserActivityQueryHandler"]
