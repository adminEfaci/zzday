"""
Audit Module Public Contract

This module defines the public interface that other modules can use to interact
with the Audit module. This contract ensures proper audit logging across the system
while maintaining module boundaries.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field


class AuditActionType(str, Enum):
    """Types of audit actions."""
    
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    PERMISSION_GRANTED = "PERMISSION_GRANTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    SECURITY_EVENT = "SECURITY_EVENT"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_IMPORT = "DATA_IMPORT"
    CUSTOM = "CUSTOM"


class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEntryDTO(BaseModel):
    """Audit entry DTO for logging events."""
    
    id: Optional[UUID] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[UUID] = None
    action: AuditActionType
    resource_type: str
    resource_id: Optional[str] = None
    severity: AuditSeverity = AuditSeverity.INFO
    description: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[UUID] = None
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class AuditSearchCriteriaDTO(BaseModel):
    """Search criteria for audit logs."""
    
    user_id: Optional[UUID] = None
    action: Optional[AuditActionType] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ip_address: Optional[str] = None
    session_id: Optional[UUID] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class AuditSummaryDTO(BaseModel):
    """Summary statistics for audit logs."""
    
    total_entries: int = 0
    entries_by_action: Dict[str, int] = Field(default_factory=dict)
    entries_by_severity: Dict[str, int] = Field(default_factory=dict)
    entries_by_user: Dict[str, int] = Field(default_factory=dict)
    date_range: Optional[Dict[str, datetime]] = None


class IAuditContract(ABC):
    """
    Public contract for Audit module.
    
    This interface defines all operations that other modules can perform
    with the Audit module for logging and retrieving audit information.
    """
    
    @abstractmethod
    async def log_event(self, entry: AuditEntryDTO) -> UUID:
        """
        Log an audit event.
        
        Args:
            entry: Audit entry to log
            
        Returns:
            UUID of the created audit entry
        """
        pass
    
    @abstractmethod
    async def log_security_event(
        self,
        user_id: Optional[UUID],
        event_type: str,
        description: str,
        severity: AuditSeverity = AuditSeverity.WARNING,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Log a security-related event.
        
        Args:
            user_id: User involved in the event
            event_type: Type of security event
            description: Event description
            severity: Event severity
            metadata: Additional event metadata
            
        Returns:
            UUID of the created audit entry
        """
        pass
    
    @abstractmethod
    async def log_data_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str,
        action: str = "READ",
        metadata: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Log data access event.
        
        Args:
            user_id: User accessing the data
            resource_type: Type of resource accessed
            resource_id: ID of resource accessed
            action: Action performed
            metadata: Additional metadata
            
        Returns:
            UUID of the created audit entry
        """
        pass
    
    @abstractmethod
    async def get_audit_entry(self, entry_id: UUID) -> Optional[AuditEntryDTO]:
        """
        Get specific audit entry by ID.
        
        Args:
            entry_id: Audit entry identifier
            
        Returns:
            AuditEntryDTO if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def search_audit_logs(
        self,
        criteria: AuditSearchCriteriaDTO
    ) -> List[AuditEntryDTO]:
        """
        Search audit logs based on criteria.
        
        Args:
            criteria: Search criteria
            
        Returns:
            List of matching audit entries
        """
        pass
    
    @abstractmethod
    async def get_user_activity(
        self,
        user_id: UUID,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEntryDTO]:
        """
        Get audit activity for specific user.
        
        Args:
            user_id: User identifier
            start_date: Start date filter
            end_date: End date filter
            limit: Maximum entries to return
            
        Returns:
            List of user's audit entries
        """
        pass
    
    @abstractmethod
    async def get_audit_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        resource_type: Optional[str] = None
    ) -> AuditSummaryDTO:
        """
        Get summary statistics for audit logs.
        
        Args:
            start_date: Start date for summary
            end_date: End date for summary
            resource_type: Optional filter by resource type
            
        Returns:
            AuditSummaryDTO with statistics
        """
        pass
    
    @abstractmethod
    async def mark_sensitive_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UUID:
        """
        Mark access to sensitive resources for compliance.
        
        Args:
            user_id: User accessing sensitive data
            resource_type: Type of sensitive resource
            resource_id: ID of sensitive resource
            reason: Reason for access
            metadata: Additional metadata
            
        Returns:
            UUID of the created audit entry
        """
        pass