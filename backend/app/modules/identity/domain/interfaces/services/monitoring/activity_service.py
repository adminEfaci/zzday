"""
Activity Service Interface

Interface for user activity tracking and monitoring.
"""

from abc import ABC, abstractmethod
from typing import Protocol, Dict, Any, List, Optional
from datetime import datetime
from uuid import UUID


class IActivityService(Protocol):
    """
    Interface for tracking and monitoring user activities.
    
    This service handles logging, retrieval, and analysis of user activities
    within the identity system for audit and monitoring purposes.
    """
    
    @abstractmethod
    async def log_activity(
        self,
        user_id: UUID,
        activity_type: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """
        Log a user activity event.
        
        Args:
            user_id: ID of the user performing the activity
            activity_type: Type/category of the activity
            description: Human-readable description of the activity
            metadata: Additional activity metadata
            ip_address: IP address of the user
            user_agent: User agent string from the request
        """
        ...
    
    @abstractmethod
    async def get_user_activity(
        self,
        user_id: UUID,
        limit: int = 50,
        offset: int = 0,
        activity_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get user activity history.
        
        Args:
            user_id: ID of the user
            limit: Maximum number of activities to return
            offset: Number of activities to skip
            activity_type: Filter by activity type
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            
        Returns:
            List of activity records
        """
        ...
    
    @abstractmethod
    async def get_activity_summary(
        self,
        user_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get activity summary for a user over specified days.
        
        Args:
            user_id: ID of the user
            days: Number of days to include in summary
            
        Returns:
            Activity summary statistics
        """
        ...
    
    @abstractmethod
    async def get_suspicious_activities(
        self,
        user_id: Optional[UUID] = None,
        limit: int = 50,
        severity_threshold: str = "medium"
    ) -> List[Dict[str, Any]]:
        """
        Get activities flagged as suspicious.
        
        Args:
            user_id: Optional user ID to filter by
            limit: Maximum number of activities to return
            severity_threshold: Minimum severity level
            
        Returns:
            List of suspicious activity records
        """
        ...
    
    @abstractmethod
    async def delete_user_activities(
        self,
        user_id: UUID,
        older_than_days: Optional[int] = None
    ) -> int:
        """
        Delete user activities for privacy compliance.
        
        Args:
            user_id: ID of the user
            older_than_days: Delete activities older than this many days
            
        Returns:
            Number of activities deleted
        """
        ...
