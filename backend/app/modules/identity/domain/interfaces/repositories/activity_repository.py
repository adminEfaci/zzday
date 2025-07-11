"""
Activity Repository Interface

Repository interface for user activity tracking and analysis.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID


class IActivityRepository(ABC):
    """
    Repository interface for user activity operations.
    
    Provides methods for storing and retrieving user activities
    for behavior analysis and security monitoring.
    """
    
    @abstractmethod
    async def create_activity(self, activity_data: Dict[str, Any]) -> str:
        """
        Store a new user activity record.
        
        Args:
            activity_data: Activity data to store
            
        Returns:
            Activity record ID
        """
        ...
    
    @abstractmethod
    async def get_user_activities(
        self,
        user_id: UUID,
        activity_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Retrieve user activities with filtering options.
        
        Args:
            user_id: User identifier
            activity_types: Filter by activity types
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            limit: Maximum number of activities to return
            offset: Number of activities to skip
            
        Returns:
            List of user activity records
        """
        ...
    
    @abstractmethod
    async def get_activity_statistics(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        group_by: str = "activity_type"
    ) -> Dict[str, Any]:
        """
        Get activity statistics with grouping.
        
        Args:
            user_id: Filter by specific user (None for all users)
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            group_by: Field to group statistics by
            
        Returns:
            Activity statistics grouped by specified field
        """
        ...
    
    @abstractmethod
    async def get_activity_patterns(
        self,
        user_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze user activity patterns over time.
        
        Args:
            user_id: User identifier
            days: Number of days to analyze
            
        Returns:
            Activity patterns including peak hours, trends, etc.
        """
        ...
    
    @abstractmethod
    async def get_suspicious_activities(
        self,
        risk_threshold: float = 0.5,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get activities flagged as suspicious based on risk score.
        
        Args:
            risk_threshold: Minimum risk score to include
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            limit: Maximum number of activities to return
            
        Returns:
            List of suspicious activity records
        """
        ...
    
    @abstractmethod
    async def get_activity_timeline(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "hour"
    ) -> List[Dict[str, Any]]:
        """
        Get user activity timeline with specified granularity.
        
        Args:
            user_id: User identifier
            start_date: Timeline start date
            end_date: Timeline end date
            granularity: Time granularity (hour, day, week)
            
        Returns:
            Activity timeline data points
        """
        ...
    
    @abstractmethod
    async def search_activities(
        self,
        query: str,
        user_id: Optional[UUID] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search activities using text query and filters.
        
        Args:
            query: Text search query
            user_id: Filter by specific user
            filters: Additional search filters
            limit: Maximum number of results
            
        Returns:
            List of matching activity records
        """
        ...
    
    @abstractmethod
    async def get_concurrent_activities(
        self,
        user_id: UUID,
        time_window_minutes: int = 5,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[List[Dict[str, Any]]]:
        """
        Find activities that occurred within the same time window.
        
        Args:
            user_id: User identifier
            time_window_minutes: Time window for concurrency
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            
        Returns:
            List of concurrent activity groups
        """
        ...
    
    @abstractmethod
    async def get_activity_frequency(
        self,
        user_id: UUID,
        activity_type: str,
        time_period: str = "day"
    ) -> List[Dict[str, Any]]:
        """
        Get frequency of specific activity type over time.
        
        Args:
            user_id: User identifier
            activity_type: Type of activity to analyze
            time_period: Time period for frequency calculation
            
        Returns:
            Activity frequency data over time
        """
        ...
    
    @abstractmethod
    async def bulk_create_activities(
        self,
        activities: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Create multiple activity records efficiently.
        
        Args:
            activities: List of activity data to store
            
        Returns:
            List of created activity record IDs
        """
        ...
    
    @abstractmethod
    async def update_activity_risk_score(
        self,
        activity_id: str,
        new_risk_score: float,
        risk_factors: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update risk score for an activity record.
        
        Args:
            activity_id: Activity record identifier
            new_risk_score: Updated risk score
            risk_factors: Additional risk assessment factors
            
        Returns:
            True if update was successful
        """
        ...
    
    @abstractmethod
    async def delete_user_activities(
        self,
        user_id: UUID,
        older_than_days: Optional[int] = None,
        activity_types: Optional[List[str]] = None
    ) -> int:
        """
        Delete user activities for privacy compliance.
        
        Args:
            user_id: User identifier
            older_than_days: Delete activities older than this many days
            activity_types: Delete only specific activity types
            
        Returns:
            Number of activities deleted
        """
        ...
    
    @abstractmethod
    async def get_anomalous_activities(
        self,
        user_id: Optional[UUID] = None,
        anomaly_threshold: float = 2.0,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Detect anomalous activities using statistical analysis.
        
        Args:
            user_id: Filter by specific user (None for all users)
            anomaly_threshold: Standard deviations from normal
            days: Number of days to analyze
            
        Returns:
            List of anomalous activity records
        """
        ...
    
    @abstractmethod
    async def get_user_session_activities(
        self,
        session_id: str,
        include_metadata: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get all activities for a specific user session.
        
        Args:
            session_id: Session identifier
            include_metadata: Include additional metadata
            
        Returns:
            List of activities within the session
        """
        ...
    
    @abstractmethod
    async def aggregate_activities_by_location(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Aggregate activities by geographic location.
        
        Args:
            user_id: Filter by specific user
            start_date: Filter activities after this date
            end_date: Filter activities before this date
            
        Returns:
            Activities aggregated by location
        """
        ...
    
    @abstractmethod
    async def export_activity_data(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime,
        format_type: str = "json"
    ) -> Dict[str, Any]:
        """
        Export user activity data for compliance requests.
        
        Args:
            user_id: User identifier
            start_date: Export start date
            end_date: Export end date
            format_type: Export format (json, csv)
            
        Returns:
            Exported activity data
        """
        ...
    
    @abstractmethod
    async def cleanup_old_activities(
        self,
        retention_days: int,
        batch_size: int = 1000
    ) -> Dict[str, int]:
        """
        Clean up old activity records beyond retention period.
        
        Args:
            retention_days: Number of days to retain activities
            batch_size: Number of records to process per batch
            
        Returns:
            Cleanup results including counts by type
        """
        ...
