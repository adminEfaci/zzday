"""
Analytics Repository Interface

Repository interface for analytics data storage and retrieval.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ...services.monitoring.analytics_service import MetricData


class IAnalyticsRepository(ABC):
    """
    Repository interface for analytics data operations.
    
    Provides methods for storing events, metrics, and retrieving
    analytical data for reporting and insights.
    """
    
    @abstractmethod
    async def store_event(self, event_data: Dict[str, Any]) -> str:
        """
        Store an analytics event.
        
        Args:
            event_data: Event data to store
            
        Returns:
            Event ID
        """
        ...
    
    @abstractmethod
    async def store_metric(self, metric_data: MetricData) -> str:
        """
        Store a metric data point.
        
        Args:
            metric_data: Metric data to store
            
        Returns:
            Metric record ID
        """
        ...
    
    @abstractmethod
    async def get_user_analytics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Get user analytics data for date range.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            granularity: Data granularity (hour, day, week, month)
            
        Returns:
            User analytics data with time series
        """
        ...
    
    @abstractmethod
    async def get_authentication_analytics(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "day"
    ) -> Dict[str, Any]:
        """
        Get authentication analytics data.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            granularity: Data granularity
            
        Returns:
            Authentication analytics with success rates, methods, etc.
        """
        ...
    
    @abstractmethod
    async def get_security_analytics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Get security analytics data.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            
        Returns:
            Security analytics including incidents, threats, etc.
        """
        ...
    
    @abstractmethod
    async def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get current real-time metrics.
        
        Returns:
            Dictionary of current system metrics
        """
        ...
    
    @abstractmethod
    async def get_metric_history(
        self,
        metric_name: str,
        start_date: datetime,
        end_date: datetime,
        granularity: str = "hour"
    ) -> List[Dict[str, Any]]:
        """
        Get historical data for a specific metric.
        
        Args:
            metric_name: Name of the metric
            start_date: Start of period
            end_date: End of period
            granularity: Data granularity
            
        Returns:
            List of metric data points with timestamps
        """
        ...
    
    @abstractmethod
    async def get_event_counts(
        self,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        group_by: str = "event_type"
    ) -> Dict[str, int]:
        """
        Get counts of events grouped by specified field.
        
        Args:
            event_types: Filter by specific event types
            start_date: Start of counting period
            end_date: End of counting period
            group_by: Field to group by (event_type, user_id, date)
            
        Returns:
            Dictionary mapping group values to counts
        """
        ...
    
    @abstractmethod
    async def get_user_behavior_patterns(
        self,
        user_id: Optional[UUID] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze user behavior patterns.
        
        Args:
            user_id: Specific user to analyze (None for all users)
            days: Number of days to analyze
            
        Returns:
            User behavior patterns and insights
        """
        ...
    
    @abstractmethod
    async def get_funnel_analysis(
        self,
        funnel_events: List[str],
        start_date: datetime,
        end_date: datetime,
        conversion_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Perform funnel analysis on event sequence.
        
        Args:
            funnel_events: Ordered list of events in the funnel
            start_date: Analysis start date
            end_date: Analysis end date
            conversion_window_hours: Time window for conversions
            
        Returns:
            Funnel analysis results with conversion rates
        """
        ...
    
    @abstractmethod
    async def get_cohort_analysis(
        self,
        cohort_by: str,
        analyze_event: str,
        start_date: datetime,
        periods: int = 12
    ) -> Dict[str, Any]:
        """
        Perform cohort analysis.
        
        Args:
            cohort_by: Event to define cohorts (e.g., 'user_registered')
            analyze_event: Event to analyze retention (e.g., 'user_login')
            start_date: Start date for cohort definition
            periods: Number of periods to analyze
            
        Returns:
            Cohort analysis results
        """
        ...
    
    @abstractmethod
    async def get_performance_metrics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Get system performance metrics.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            
        Returns:
            Performance metrics including response times, throughput
        """
        ...
    
    @abstractmethod
    async def aggregate_metrics(
        self,
        metric_names: List[str],
        aggregation_type: str,
        start_date: datetime,
        end_date: datetime,
        group_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Aggregate metrics with specified aggregation function.
        
        Args:
            metric_names: List of metrics to aggregate
            aggregation_type: Type of aggregation (sum, avg, min, max, count)
            start_date: Start of aggregation period
            end_date: End of aggregation period
            group_by: Optional field to group results by
            
        Returns:
            Aggregated metric results
        """
        ...
    
    @abstractmethod
    async def create_custom_report(
        self,
        report_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate custom analytics report based on configuration.
        
        Args:
            report_config: Report configuration including metrics, filters, etc.
            
        Returns:
            Custom report results
        """
        ...
    
    @abstractmethod
    async def cleanup_old_data(
        self,
        retention_days: int,
        data_types: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """
        Clean up old analytics data beyond retention period.
        
        Args:
            retention_days: Number of days to retain data
            data_types: Specific data types to clean (None for all)
            
        Returns:
            Dictionary showing counts of cleaned data by type
        """
        ...
    
    @abstractmethod
    async def export_data(
        self,
        start_date: datetime,
        end_date: datetime,
        data_types: List[str],
        format_type: str = "json"
    ) -> Dict[str, Any]:
        """
        Export analytics data for external analysis.
        
        Args:
            start_date: Start of export period
            end_date: End of export period
            data_types: Types of data to export
            format_type: Export format (json, csv, parquet)
            
        Returns:
            Export result with data or download URLs
        """
        ...
