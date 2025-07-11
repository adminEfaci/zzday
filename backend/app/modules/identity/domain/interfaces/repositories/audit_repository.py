"""
Audit Repository Interface

Repository interface for audit log persistence and retrieval.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from ...value_objects.audit_entry import AuditEntry
from ...enums import RiskLevel


class IAuditRepository(ABC):
    """
    Repository interface for audit log operations.
    
    Provides methods for storing, retrieving, and managing audit entries
    for compliance and security monitoring purposes.
    """
    
    @abstractmethod
    async def create_audit_entry(self, audit_entry: AuditEntry) -> str:
        """
        Store a new audit entry.
        
        Args:
            audit_entry: The audit entry to store
            
        Returns:
            The ID of the created audit entry
        """
        ...
    
    @abstractmethod
    async def get_audit_entries(
        self,
        user_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditEntry]:
        """
        Retrieve audit entries with filtering options.
        
        Args:
            user_id: Filter by user ID
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            event_types: Filter by event types
            start_date: Filter entries after this date
            end_date: Filter entries before this date
            limit: Maximum number of entries to return
            offset: Number of entries to skip
            
        Returns:
            List of matching audit entries
        """
        ...
    
    @abstractmethod
    async def get_compliance_entries(
        self,
        start_date: datetime,
        end_date: datetime,
        compliance_frameworks: Optional[List[str]] = None
    ) -> List[AuditEntry]:
        """
        Get audit entries relevant for compliance reporting.
        
        Args:
            start_date: Start of reporting period
            end_date: End of reporting period
            compliance_frameworks: Filter by specific frameworks
            
        Returns:
            List of compliance-relevant audit entries
        """
        ...
    
    @abstractmethod
    async def search_audit_entries(
        self,
        query: str,
        filters: Dict[str, Any],
        limit: int = 100
    ) -> List[AuditEntry]:
        """
        Search audit entries using text query and filters.
        
        Args:
            query: Text search query
            filters: Additional search filters
            limit: Maximum number of results
            
        Returns:
            List of matching audit entries with relevance scores
        """
        ...
    
    @abstractmethod
    async def get_entries_before_date(self, cutoff_date: datetime) -> List[AuditEntry]:
        """
        Get audit entries older than specified date for archival.
        
        Args:
            cutoff_date: Date cutoff for old entries
            
        Returns:
            List of audit entries to be archived
        """
        ...
    
    @abstractmethod
    async def delete_entries_before_date(self, cutoff_date: datetime) -> int:
        """
        Delete audit entries older than specified date.
        
        Args:
            cutoff_date: Date cutoff for deletion
            
        Returns:
            Number of entries deleted
        """
        ...
    
    @abstractmethod
    async def get_audit_statistics(
        self,
        start_date: datetime,
        end_date: datetime,
        group_by: str = "day"
    ) -> Dict[str, Any]:
        """
        Get audit statistics for a time period.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            group_by: Grouping interval (day, week, month)
            
        Returns:
            Dictionary containing audit statistics
        """
        ...
    
    @abstractmethod
    async def get_risk_distribution(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[RiskLevel, int]:
        """
        Get distribution of audit entries by risk level.
        
        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            
        Returns:
            Dictionary mapping risk levels to counts
        """
        ...
    
    @abstractmethod
    async def get_user_audit_summary(
        self,
        user_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get audit summary for a specific user.
        
        Args:
            user_id: User identifier
            days: Number of days to analyze
            
        Returns:
            Dictionary containing user audit summary
        """
        ...
    
    @abstractmethod
    async def bulk_create_audit_entries(self, audit_entries: List[AuditEntry]) -> List[str]:
        """
        Create multiple audit entries efficiently.
        
        Args:
            audit_entries: List of audit entries to create
            
        Returns:
            List of created audit entry IDs
        """
        ...
    
    @abstractmethod
    async def update_audit_entry_retention(
        self,
        audit_id: str,
        new_retention_period: int
    ) -> bool:
        """
        Update retention period for an audit entry.
        
        Args:
            audit_id: Audit entry identifier
            new_retention_period: New retention period in days
            
        Returns:
            True if update was successful
        """
        ...
