"""
Audit Service Interface

Port for audit logging and activity tracking operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from ...value_objects.audit_export import AuditExport


class IAuditService(ABC):
    """Port for audit operations."""
    
    @abstractmethod
    async def log_event(
        self,
        user_id: UUID | None,
        actor_id: UUID | None,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        session_id: UUID | None = None
    ) -> UUID:
        """
        Log audit event.
        
        Args:
            user_id: Affected user
            actor_id: User performing action
            action: Action performed
            resource_type: Type of resource
            resource_id: Resource identifier
            details: Additional details
            ip_address: Client IP
            user_agent: Client user agent
            session_id: Session identifier
            
        Returns:
            Audit log entry ID
        """
    
    @abstractmethod
    async def create_audit_trail(
        self,
        entity_type: str,
        entity_id: str,
        changes: dict[str, Any],
        actor_id: UUID | None = None
    ) -> UUID:
        """
        Create audit trail for entity changes.
        
        Args:
            entity_type: Type of entity
            entity_id: Entity identifier
            changes: Field changes
            actor_id: User making changes
            
        Returns:
            Audit trail ID
        """
    
    @abstractmethod
    async def query_audit_logs(
        self,
        filters: dict[str, Any],
        page: int = 1,
        page_size: int = 50
    ) -> dict[str, Any]:
        """
        Query audit logs.
        
        Args:
            filters: Query filters
            page: Page number
            page_size: Items per page
            
        Returns:
            Paginated audit logs
        """
    
    @abstractmethod
    async def get_user_activity_summary(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """
        Get user activity summary.
        
        Args:
            user_id: User identifier
            start_date: Period start
            end_date: Period end
            
        Returns:
            Activity summary statistics
        """
    
    @abstractmethod
    async def export_audit_logs(
        self,
        filters: dict[str, Any],
        export_format: str = "csv"
    ) -> "AuditExport":
        """
        Export audit logs.
        
        Args:
            filters: Export filters
            export_format: Export format (csv/json/xlsx)
            
        Returns:
            AuditExport value object containing export metadata
        """
