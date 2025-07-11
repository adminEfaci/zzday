"""
OutboxRepository Interface

Repository interface for outbox event persistence following DDD principles.
"""

from abc import ABC, abstractmethod
from typing import List
from uuid import UUID

from app.models.outbox_event import OutboxEvent
from typing import List, Optional, Dict, Any


class OutboxRepository(ABC):
    """
    Repository interface for outbox events.
    
    This interface defines the contract for storing and retrieving outbox events
    in the outbox pattern implementation. It ensures atomic storage of events
    within the same transaction as domain data.
    """
    
    @abstractmethod
    async def store_events(
        self, 
        events: List[OutboxEvent], 
        aggregate_id: UUID
    ) -> None:
        """
        Store events in outbox within same transaction.
        
        This method MUST be called within the same database transaction
        as the domain data changes to ensure atomicity.
        
        Args:
            events: List of domain events to store
            aggregate_id: ID of the aggregate that generated the events
            
        Raises:
            InfrastructureError: If storage fails
        """
        pass
    
    @abstractmethod
    async def get_unprocessed_events(
        self, 
        limit: int = 100
    ) -> List[OutboxEvent]:
        """
        Get unprocessed events for background processor.
        
        Retrieves events that haven't been processed yet and can be retried.
        Events are ordered by creation time (oldest first).
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of unprocessed outbox events
            
        Raises:
            InfrastructureError: If retrieval fails
        """
        pass
    
    @abstractmethod
    async def mark_processed(
        self, 
        event_id: UUID
    ) -> None:
        """
        Mark event as successfully processed.
        
        Updates the event's processed_at timestamp and clears any error message.
        
        Args:
            event_id: ID of the event to mark as processed
            
        Raises:
            InfrastructureError: If update fails
            NotFoundError: If event not found
        """
        pass
    
    @abstractmethod
    async def increment_retry(
        self, 
        event_id: UUID, 
        error_message: str
    ) -> None:
        """
        Increment retry count for failed event.
        
        Updates the event's retry count and error message when processing fails.
        
        Args:
            event_id: ID of the event to update
            error_message: Error message from failed processing
            
        Raises:
            InfrastructureError: If update fails
            NotFoundError: If event not found
        """
        pass
    
    @abstractmethod
    async def get_failed_events(
        self, 
        limit: int = 100
    ) -> List[OutboxEvent]:
        """
        Get events that have exhausted retries.
        
        Retrieves events that have reached their maximum retry count
        and are no longer eligible for processing.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of failed outbox events
            
        Raises:
            InfrastructureError: If retrieval fails
        """
        pass
    
    @abstractmethod
    async def cleanup_processed_events(
        self, 
        older_than_days: int = 30
    ) -> int:
        """
        Clean up processed events older than specified days.
        
        Removes processed events that are older than the specified number
        of days to prevent unlimited growth of the outbox table.
        
        Args:
            older_than_days: Remove events processed more than this many days ago
            
        Returns:
            Number of events deleted
            
        Raises:
            InfrastructureError: If cleanup fails
        """
        pass
    
    @abstractmethod
    async def get_events_by_aggregate(
        self, 
        aggregate_id: UUID,
        limit: int = 100
    ) -> List[OutboxEvent]:
        """
        Get events for a specific aggregate.
        
        Useful for debugging and audit purposes.
        
        Args:
            aggregate_id: ID of the aggregate
            limit: Maximum number of events to return
            
        Returns:
            List of events for the aggregate
            
        Raises:
            InfrastructureError: If retrieval fails
        """
        pass