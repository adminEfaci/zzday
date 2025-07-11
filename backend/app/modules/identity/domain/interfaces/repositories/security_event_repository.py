"""Security Event Repository Interface

Domain contract for security event data access that must be implemented by the infrastructure layer.
"""

from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.core.enums import EventType


class ISecurityEventRepository(Protocol):
    """Repository interface for security event logging."""
    
    async def create(self, event_data: dict) -> UUID:
        """Create new security event.
        
        Args:
            event_data: Security event data including:
                - user_id (optional): User identifier
                - event_type: EventType enum value
                - description: Event description
                - ip_address (optional): Source IP address
                - user_agent (optional): User agent string
                - metadata (optional): Additional event metadata
                - created_at: Event timestamp
                
        Returns:
            Created event ID
        """
        ...
    
    async def find_by_user(
        self, 
        user_id: UUID, 
        limit: int = 100,
        offset: int = 0
    ) -> list[dict]:
        """Find security events for a user.
        
        Args:
            user_id: User identifier
            limit: Maximum number of events to return
            offset: Number of events to skip
            
        Returns:
            List of security events
        """
        ...
    
    async def find_by_type(
        self, 
        event_type: EventType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100
    ) -> list[dict]:
        """Find security events by type.
        
        Args:
            event_type: Event type to filter by
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        ...
    
    async def find_by_ip(
        self, 
        ip_address: str,
        limit: int = 100
    ) -> list[dict]:
        """Find security events by IP address.
        
        Args:
            ip_address: IP address to filter by
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        ...
    
    async def count_by_user_and_type(
        self, 
        user_id: UUID, 
        event_type: EventType,
        since: datetime | None = None
    ) -> int:
        """Count security events for a user by type.
        
        Args:
            user_id: User identifier
            event_type: Event type to count
            since: Optional start date filter
            
        Returns:
            Number of matching events
        """
        ...
    
    async def cleanup_old_events(self, older_than: datetime) -> int:
        """Remove old security events.
        
        Args:
            older_than: Remove events older than this date
            
        Returns:
            Number of events removed
        """
        ...