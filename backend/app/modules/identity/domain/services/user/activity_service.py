"""
User Activity Domain Service

Implements user activity tracking and analysis using existing utilities.
"""

import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.security import generate_token
from app.utils.crypto import mask_sensitive_data
from app.utils.date import format_relative_time
from app.utils.text import normalize_whitespace
from app.utils.validation import validate_uuid

from ...interfaces.contracts.audit_contract import IAuditContract
from ...interfaces.repositories.monitoring.activity_repository import (
    IActivityRepository,
)
from ...interfaces.repositories.user.user_repository import IUserRepository
from ...interfaces.services.infrastructure.cache_port import ICachePort
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort
from ...interfaces.services.monitoring.activity_service import IActivityService


@dataclass
class ActivityPattern:
    """User activity pattern analysis."""
    user_id: UUID
    most_active_hours: list[int]
    average_daily_activities: float
    activity_distribution: dict[str, int]
    peak_activity_day: str
    analysis_period: int
    generated_at: datetime


@dataclass
class SuspiciousActivity:
    """Suspicious activity indicator."""
    activity_id: str
    suspicion_type: str
    confidence: float
    description: str
    risk_score: float
    evidence: dict[str, Any]


class ActivityService(IActivityService):
    """Domain service for user activity tracking and analysis."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        activity_repository: IActivityRepository,
        audit_contract: IAuditContract,
        cache_port: ICachePort,
        configuration_port: IConfigurationPort
    ) -> None:
        self._user_repository = user_repository
        self._activity_repository = activity_repository
        self._audit_contract = audit_contract
        self._cache = cache_port
        self._config = configuration_port
        self._suspicious_patterns = self._initialize_suspicious_patterns()
    
    async def log_activity(
        self,
        user_id: UUID,
        activity_type: str,
        details: dict[str, Any],
        ip_address: str | None = None,
        user_agent: str | None = None
    ) -> str:
        """Log user activity."""
        
        # Validate inputs using utility
        if not validate_uuid(str(user_id)):
            raise ValueError("Invalid user ID format")
        
        if not activity_type:
            raise ValueError("Activity type is required")
        
        # Generate activity ID
        activity_id = generate_token(16)
        
        # Prepare activity data
        activity_data = {
            "id": activity_id,
            "user_id": str(user_id),
            "activity_type": normalize_whitespace(activity_type),
            "details": self._sanitize_activity_details(details),
            "ip_address": mask_sensitive_data(ip_address, 6) if ip_address else None,
            "user_agent": user_agent,
            "timestamp": datetime.utcnow(),
            "risk_score": await self._calculate_activity_risk(user_id, activity_type, details)
        }
        
        # Store activity
        await self._activity_repository.create_activity(activity_data)
        
        # Update activity cache
        await self._update_activity_cache(user_id, activity_data)
        
        # Log through audit contract
        await self._audit_contract.log_event(
            event_type="user_activity_logged",
            user_id=user_id,
            details={
                "activity_id": activity_id,
                "activity_type": activity_type,
                "risk_score": activity_data["risk_score"],
                "has_sensitive_data": self._contains_sensitive_data(details)
            }
        )
        
        return activity_id
    
    async def get_user_activity(
        self,
        user_id: UUID,
        activity_types: list[str] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get user activity history."""
        
        # Validate inputs
        if not validate_uuid(str(user_id)):
            return []
        
        if limit <= 0 or limit > 1000:
            limit = 100
        
        # Set default dates if not provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Get activities from repository
        activities = await self._activity_repository.get_user_activities(
            user_id=user_id,
            activity_types=activity_types,
            start_date=start_date,
            end_date=end_date,
            limit=limit
        )
        
        # Format activities for response
        formatted_activities = []
        for activity in activities:
            formatted_activities.append({
                "id": activity.get("id"),
                "activity_type": activity.get("activity_type"),
                "timestamp": activity.get("timestamp").isoformat() if activity.get("timestamp") else None,
                "details": activity.get("details", {}),
                "risk_score": activity.get("risk_score", 0.0),
                "relative_time": format_relative_time(activity.get("timestamp")) if activity.get("timestamp") else None
            })
        
        return formatted_activities
    
    async def analyze_activity_patterns(
        self,
        user_id: UUID,
        days: int = 30
    ) -> dict[str, Any]:
        """Analyze user activity patterns."""
        
        # Validate inputs
        if not validate_uuid(str(user_id)):
            return {}
        
        if days <= 0 or days > 365:
            days = 30
        
        # Check cache first
        cache_key = f"activity_patterns:{user_id}:{days}"
        cached_patterns = await self._cache.get(cache_key)
        if cached_patterns:
            return cached_patterns
        
        # Get activities for analysis period
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        activities = await self._activity_repository.get_user_activities(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=10000  # Large limit for pattern analysis
        )
        
        if not activities:
            return {"error": "No activity data available for analysis"}
        
        # Analyze patterns
        patterns = {
            "total_activities": len(activities),
            "analysis_period_days": days,
            "average_daily_activities": len(activities) / days,
            "most_active_hours": self._analyze_hourly_patterns(activities),
            "activity_distribution": self._analyze_activity_distribution(activities),
            "peak_activity_day": self._find_peak_activity_day(activities),
            "activity_trend": self._calculate_activity_trend(activities, days),
            "risk_assessment": self._assess_pattern_risk(activities),
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Cache patterns for 1 hour
        await self._cache.set(cache_key, patterns, expiry_seconds=3600)
        
        return patterns
    
    async def detect_suspicious_activity(
        self,
        user_id: UUID,
        activity_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect suspicious activity patterns."""
        
        # Validate inputs
        if not validate_uuid(str(user_id)):
            return []
        
        suspicious_indicators = []
        
        # Get recent activity for comparison
        recent_activities = await self._get_recent_activities(user_id, hours=24)
        
        # Check for unusual frequency
        frequency_suspicion = await self._check_unusual_frequency(
            user_id, recent_activities, activity_data
        )
        if frequency_suspicion:
            suspicious_indicators.append(frequency_suspicion)
        
        # Check for unusual timing
        timing_suspicion = self._check_unusual_timing(user_id, activity_data)
        if timing_suspicion:
            suspicious_indicators.append(timing_suspicion)
        
        # Check for unusual location
        location_suspicion = await self._check_unusual_location(
            user_id, activity_data
        )
        if location_suspicion:
            suspicious_indicators.append(location_suspicion)
        
        # Check for rapid succession activities
        succession_suspicion = self._check_rapid_succession(recent_activities)
        if succession_suspicion:
            suspicious_indicators.append(succession_suspicion)
        
        # Log suspicious activity detection
        if suspicious_indicators:
            await self._audit_contract.log_event(
                event_type="suspicious_activity_detected",
                user_id=user_id,
                details={
                    "indicator_count": len(suspicious_indicators),
                    "indicator_types": [s["type"] for s in suspicious_indicators],
                    "max_risk_score": max(s["risk_score"] for s in suspicious_indicators)
                }
            )
        
        return suspicious_indicators
    
    async def get_activity_summary(
        self,
        user_id: UUID,
        period: str = "week"
    ) -> dict[str, Any]:
        """Get activity summary for period."""
        
        # Validate inputs
        if not validate_uuid(str(user_id)):
            return {}
        
        # Determine date range based on period
        end_date = datetime.utcnow()
        if period == "day":
            start_date = end_date - timedelta(days=1)
        elif period == "week":
            start_date = end_date - timedelta(days=7)
        elif period == "month":
            start_date = end_date - timedelta(days=30)
        else:
            start_date = end_date - timedelta(days=7)  # Default to week
        
        # Get activities for period
        activities = await self._activity_repository.get_user_activities(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            limit=1000
        )
        
        # Generate summary
        return {
            "period": period,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "total_activities": len(activities),
            "activity_types": self._summarize_activity_types(activities),
            "daily_breakdown": self._generate_daily_breakdown(activities, start_date, end_date),
            "risk_summary": self._summarize_risk_scores(activities),
            "most_common_activity": self._find_most_common_activity(activities),
            "generated_at": datetime.utcnow().isoformat()
        }
        
    
    # Private helper methods
    
    def _sanitize_activity_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Sanitize activity details by masking sensitive data."""
        sanitized = {}
        
        for key, value in details.items():
            if key.lower() in ["password", "token", "secret", "api_key"]:
                sanitized[key] = "[REDACTED]"
            elif key.lower() in ["email", "phone"]:
                if isinstance(value, str):
                    sanitized[key] = mask_sensitive_data(value, 4)
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _contains_sensitive_data(self, details: dict[str, Any]) -> bool:
        """Check if details contain sensitive data."""
        sensitive_keys = ["password", "token", "secret", "api_key", "ssn", "credit_card"]
        return any(key.lower() in sensitive_keys for key in details)
    
    async def _calculate_activity_risk(self, user_id: UUID, activity_type: str, details: dict[str, Any]) -> float:
        """Calculate risk score for activity."""
        risk_score = 0.0
        
        # Base risk by activity type
        high_risk_activities = ["password_change", "email_change", "delete_account", "grant_permission"]
        if activity_type in high_risk_activities:
            risk_score += 0.3
        
        # Additional risk factors
        if self._contains_sensitive_data(details):
            risk_score += 0.2
        
        # Time-based risk (off-hours)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 22:
            risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    async def _update_activity_cache(self, user_id: UUID, activity_data: dict[str, Any]) -> None:
        """Update recent activity cache."""
        cache_key = f"recent_activity:{user_id}"
        recent_activities = await self._cache.get(cache_key) or []
        
        # Add new activity and keep only last 50
        recent_activities.insert(0, activity_data)
        recent_activities = recent_activities[:50]
        
        # Cache for 24 hours
        await self._cache.set(cache_key, recent_activities, expiry_seconds=86400)
    
    async def _get_recent_activities(self, user_id: UUID, hours: int = 24) -> list[dict[str, Any]]:
        """Get recent activities from cache or repository."""
        cache_key = f"recent_activity:{user_id}"
        cached_activities = await self._cache.get(cache_key)
        
        if cached_activities:
            return cached_activities
        
        # Fallback to repository
        start_date = datetime.utcnow() - timedelta(hours=hours)
        return await self._activity_repository.get_user_activities(
            user_id=user_id,
            start_date=start_date,
            limit=100
        )
        
    
    def _analyze_hourly_patterns(self, activities: list[dict[str, Any]]) -> list[int]:
        """Analyze most active hours."""
        hourly_counts = {}
        
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                hour = timestamp.hour
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        
        # Return top 3 most active hours
        sorted_hours = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)
        return [hour for hour, count in sorted_hours[:3]]
    
    def _analyze_activity_distribution(self, activities: list[dict[str, Any]]) -> dict[str, int]:
        """Analyze distribution of activity types."""
        distribution = {}
        
        for activity in activities:
            activity_type = activity.get("activity_type")
            if activity_type:
                distribution[activity_type] = distribution.get(activity_type, 0) + 1
        
        return distribution
    
    def _find_peak_activity_day(self, activities: list[dict[str, Any]]) -> str:
        """Find the day with most activity."""
        daily_counts = {}
        
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                day = timestamp.strftime("%Y-%m-%d")
                daily_counts[day] = daily_counts.get(day, 0) + 1
        
        if not daily_counts:
            return "N/A"
        
        return max(daily_counts, key=daily_counts.get)
    
    def _calculate_activity_trend(self, activities: list[dict[str, Any]], days: int) -> str:
        """Calculate activity trend (increasing/decreasing/stable)."""
        if len(activities) < 7:  # Need at least a week of data
            return "insufficient_data"
        
        # Split activities into first and second half of period
        mid_date = datetime.utcnow() - timedelta(days=days//2)
        
        first_half = [a for a in activities if a.get("timestamp") and a["timestamp"] < mid_date]
        second_half = [a for a in activities if a.get("timestamp") and a["timestamp"] >= mid_date]
        
        first_half_avg = len(first_half) / (days // 2)
        second_half_avg = len(second_half) / (days // 2)
        
        if second_half_avg > first_half_avg * 1.2:
            return "increasing"
        if second_half_avg < first_half_avg * 0.8:
            return "decreasing"
        return "stable"
    
    def _assess_pattern_risk(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        """Assess risk based on activity patterns."""
        risk_scores = [a.get("risk_score", 0.0) for a in activities if a.get("risk_score")]
        
        if not risk_scores:
            return {"average_risk": 0.0, "max_risk": 0.0, "risk_level": "low"}
        
        avg_risk = statistics.mean(risk_scores)
        max_risk = max(risk_scores)
        
        if avg_risk > 0.7:
            risk_level = "high"
        elif avg_risk > 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "average_risk": round(avg_risk, 3),
            "max_risk": round(max_risk, 3),
            "risk_level": risk_level
        }
    
    async def _check_unusual_frequency(
        self, 
        user_id: UUID, 
        recent_activities: list[dict[str, Any]], 
        activity_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check for unusual activity frequency."""
        # Count activities in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_count = len([
            a for a in recent_activities 
            if a.get("timestamp") and a["timestamp"] > one_hour_ago
        ])
        
        # Get baseline frequency from config
        config = await self._config.get_activity_settings()
        normal_hourly_limit = config.get("normal_hourly_activity_limit", 20)
        
        if recent_count > normal_hourly_limit:
            return {
                "type": "unusual_frequency",
                "description": f"High activity frequency: {recent_count} activities in last hour",
                "risk_score": min(recent_count / normal_hourly_limit, 1.0),
                "evidence": {
                    "recent_count": recent_count,
                    "normal_limit": normal_hourly_limit
                }
            }
        
        return None
    
    def _check_unusual_timing(self, user_id: UUID, activity_data: dict[str, Any]) -> dict[str, Any] | None:
        """Check for unusual activity timing."""
        current_hour = datetime.utcnow().hour
        
        # Off-hours activity (2 AM to 6 AM)
        if 2 <= current_hour <= 6:
            return {
                "type": "unusual_timing",
                "description": f"Activity during off-hours: {current_hour}:00",
                "risk_score": 0.3,
                "evidence": {
                    "hour": current_hour,
                    "is_off_hours": True
                }
            }
        
        return None
    
    async def _check_unusual_location(
        self, 
        user_id: UUID, 
        activity_data: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check for unusual location-based activity."""
        # This would implement geolocation analysis
        # For now, return None as placeholder
        return None
    
    def _check_rapid_succession(self, recent_activities: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Check for rapid succession of activities."""
        if len(recent_activities) < 3:
            return None
        
        # Check if last 3 activities happened within 1 minute
        last_three = recent_activities[:3]
        timestamps = [a.get("timestamp") for a in last_three if a.get("timestamp")]
        
        if len(timestamps) == 3:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            if time_span < 60:  # Less than 1 minute
                return {
                    "type": "rapid_succession",
                    "description": f"3 activities in {time_span:.1f} seconds",
                    "risk_score": 0.4,
                    "evidence": {
                        "activity_count": 3,
                        "time_span_seconds": time_span
                    }
                }
        
        return None
    
    def _summarize_activity_types(self, activities: list[dict[str, Any]]) -> dict[str, int]:
        """Summarize activity types with counts."""
        summary = {}
        for activity in activities:
            activity_type = activity.get("activity_type")
            if activity_type:
                summary[activity_type] = summary.get(activity_type, 0) + 1
        return summary
    
    def _generate_daily_breakdown(self, activities: list[dict[str, Any]], start_date: datetime, end_date: datetime) -> dict[str, int]:
        """Generate daily activity breakdown."""
        breakdown = {}
        current_date = start_date.date()
        end_date = end_date.date()
        
        # Initialize all days with 0
        while current_date <= end_date:
            breakdown[current_date.isoformat()] = 0
            current_date += timedelta(days=1)
        
        # Count activities by day
        for activity in activities:
            timestamp = activity.get("timestamp")
            if timestamp:
                day = timestamp.date().isoformat()
                if day in breakdown:
                    breakdown[day] += 1
        
        return breakdown
    
    def _summarize_risk_scores(self, activities: list[dict[str, Any]]) -> dict[str, Any]:
        """Summarize risk scores."""
        risk_scores = [a.get("risk_score", 0.0) for a in activities if a.get("risk_score") is not None]
        
        if not risk_scores:
            return {"average": 0.0, "max": 0.0, "min": 0.0}
        
        return {
            "average": round(statistics.mean(risk_scores), 3),
            "max": round(max(risk_scores), 3),
            "min": round(min(risk_scores), 3)
        }
    
    def _find_most_common_activity(self, activities: list[dict[str, Any]]) -> str | None:
        """Find the most common activity type."""
        activity_counts = self._summarize_activity_types(activities)
        if not activity_counts:
            return None
        return max(activity_counts, key=activity_counts.get)
    
    def _initialize_suspicious_patterns(self) -> dict[str, Any]:
        """Initialize suspicious activity patterns."""
        return {
            "high_frequency_threshold": 20,  # activities per hour
            "rapid_succession_window": 60,  # seconds
            "off_hours_start": 2,  # 2 AM
            "off_hours_end": 6,    # 6 AM
            "risk_score_threshold": 0.5
        }