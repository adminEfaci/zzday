"""
Notification Batch Service Interface

Port for notification batch operations including batch creation,
processing, and bulk delivery management.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.notification.domain.aggregates.notification_batch import NotificationBatch
    from app.modules.notification.domain.enums import BatchStatus, NotificationChannel


class INotificationBatchService(ABC):
    """Port for notification batch operations."""
    
    @abstractmethod
    async def create_batch(
        self,
        name: str,
        template_id: UUID,
        recipient_criteria: dict[str, Any] | None = None,
        recipient_ids: list[UUID] | None = None,
        data: dict[str, Any] | None = None,
        scheduled_for: datetime | None = None
    ) -> "NotificationBatch":
        """
        Create a notification batch.
        
        Args:
            name: Batch name for identification
            template_id: ID of template to use
            recipient_criteria: Criteria to select recipients
            recipient_ids: Explicit list of recipient IDs
            data: Common data for all notifications
            scheduled_for: Optional scheduled delivery time
            
        Returns:
            Created NotificationBatch aggregate
            
        Raises:
            TemplateNotFoundError: If template doesn't exist
            InvalidRecipientCriteriaError: If criteria is invalid
            EmptyBatchError: If no recipients selected
        """
        ...
    
    @abstractmethod
    async def process_batch(
        self,
        batch_id: UUID,
        chunk_size: int = 100
    ) -> None:
        """
        Process a batch for delivery.
        
        Args:
            batch_id: ID of batch to process
            chunk_size: Size of chunks for processing
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
            BatchAlreadyProcessedError: If batch was already processed
            BatchCancelledError: If batch was cancelled
        """
        ...
    
    @abstractmethod
    async def cancel_batch(
        self,
        batch_id: UUID,
        reason: str,
        cancelled_by: UUID
    ) -> int:
        """
        Cancel a batch and all pending notifications.
        
        Args:
            batch_id: ID of batch to cancel
            reason: Cancellation reason
            cancelled_by: ID of user cancelling
            
        Returns:
            Number of notifications cancelled
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
            BatchAlreadyCompletedError: If batch is already completed
        """
        ...
    
    @abstractmethod
    async def pause_batch(
        self,
        batch_id: UUID,
        reason: str | None = None
    ) -> None:
        """
        Pause batch processing.
        
        Args:
            batch_id: ID of batch to pause
            reason: Optional pause reason
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
            BatchNotActiveError: If batch is not active
        """
        ...
    
    @abstractmethod
    async def resume_batch(
        self,
        batch_id: UUID
    ) -> None:
        """
        Resume paused batch processing.
        
        Args:
            batch_id: ID of batch to resume
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
            BatchNotPausedError: If batch is not paused
        """
        ...
    
    @abstractmethod
    async def get_batch_progress(
        self,
        batch_id: UUID
    ) -> dict[str, Any]:
        """
        Get progress information for a batch.
        
        Args:
            batch_id: ID of batch
            
        Returns:
            Dictionary with progress metrics
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
        """
        ...
    
    @abstractmethod
    async def split_batch(
        self,
        batch_id: UUID,
        split_criteria: dict[str, Any]
    ) -> list[UUID]:
        """
        Split a batch into multiple smaller batches.
        
        Args:
            batch_id: ID of batch to split
            split_criteria: Criteria for splitting
            
        Returns:
            List of new batch IDs
            
        Raises:
            BatchNotFoundError: If batch doesn't exist
            BatchAlreadyProcessingError: If batch is being processed
        """
        ...
    
    @abstractmethod
    async def merge_batches(
        self,
        batch_ids: list[UUID],
        new_name: str
    ) -> UUID:
        """
        Merge multiple batches into one.
        
        Args:
            batch_ids: IDs of batches to merge
            new_name: Name for merged batch
            
        Returns:
            ID of merged batch
            
        Raises:
            BatchNotFoundError: If any batch doesn't exist
            IncompatibleBatchesError: If batches can't be merged
        """
        ...
    
    @abstractmethod
    async def validate_batch(
        self,
        batch_id: UUID
    ) -> tuple[bool, list[str]]:
        """
        Validate batch before processing.
        
        Args:
            batch_id: ID of batch to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        ...
    
    @abstractmethod
    async def estimate_batch_cost(
        self,
        batch_id: UUID,
        channels: list["NotificationChannel"] | None = None
    ) -> dict[str, float]:
        """
        Estimate cost of sending a batch.
        
        Args:
            batch_id: ID of batch
            channels: Optional specific channels to estimate
            
        Returns:
            Dictionary with cost estimates by channel
        """
        ...
    
    @abstractmethod
    async def apply_throttling(
        self,
        batch_id: UUID,
        max_per_second: int,
        max_per_minute: int | None = None
    ) -> None:
        """
        Apply rate limiting to batch processing.
        
        Args:
            batch_id: ID of batch
            max_per_second: Maximum notifications per second
            max_per_minute: Optional max per minute
        """
        ...