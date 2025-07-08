"""
User Activity Service Interface

Port for tracking and analyzing user activity.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class IActivityService(ABC):
    """Port for user activity tracking operations."""
    
    @abstractmethod
    async def log_activity(
        self,
        user_id: UUID,
        activity_type: str,
        details: dict[str, Any],
        ip_address: str | None = None,
        user_agent: str | None = None
    ) -> str:
        """
        Log user activity.
        
        Args:
            user_id: User identifier
            activity_type: Type of activity
            details: Activity details
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Activity log ID
        """
    
    @abstractmethod
    async def get_user_activity(
        self,
        user_id: UUID,
        activity_types: list[str] | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Get user activity history.
        
        Args:
            user_id: User identifier
            activity_types: Filter by activity types
            start_date: Filter from date
            end_date: Filter to date
            limit: Maximum results
            
        Returns:
            List of activity records
        """
    
    @abstractmethod
    async def analyze_activity_patterns(
        self,
        user_id: UUID,
        days: int = 30
    ) -> dict[str, Any]:
        """
        Analyze user activity patterns.
        
        Args:
            user_id: User identifier
            days: Number of days to analyze
            
        Returns:
            Activity pattern analysis
        """
    
    @abstractmethod
    async def detect_suspicious_activity(
        self,
        user_id: UUID,
        activity_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Detect suspicious activity patterns.
        
        Args:
            user_id: User identifier
            activity_data: Recent activity data
            
        Returns:
            List of suspicious activity indicators
        """
    
    @abstractmethod
    async def get_activity_summary(
        self,
        user_id: UUID,
        period: str = "week"
    ) -> dict[str, Any]:
        """
        Get activity summary for period.
        
        Args:
            user_id: User identifier
            period: Summary period (day/week/month)
            
        Returns:
            Activity summary data
        """
