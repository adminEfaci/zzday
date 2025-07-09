"""
OutboxEvent Model

Domain entity representing an outbox event for the outbox pattern.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class OutboxEvent(BaseModel):
    """Domain entity for outbox events."""
    
    id: UUID = Field(default_factory=uuid4)
    aggregate_id: UUID
    event_type: str
    event_data: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    processed_at: datetime | None = None
    retry_count: int = 0
    max_retries: int = 3
    error_message: str | None = None
    
    class Config:
        """Pydantic configuration."""
        frozen = True
        
    def is_processed(self) -> bool:
        """Check if event has been processed."""
        return self.processed_at is not None
    
    def can_retry(self) -> bool:
        """Check if event can be retried."""
        return not self.is_processed() and self.retry_count < self.max_retries
    
    def should_retry(self) -> bool:
        """Check if event should be retried (not processed and can retry)."""
        return not self.is_processed() and self.can_retry()
    
    def mark_processed(self) -> "OutboxEvent":
        """Mark event as processed."""
        return self.model_copy(
            update={
                "processed_at": datetime.now(UTC),
                "error_message": None
            }
        )
    
    def increment_retry(self, error_message: str) -> "OutboxEvent":
        """Increment retry count and set error message."""
        return self.model_copy(
            update={
                "retry_count": self.retry_count + 1,
                "error_message": error_message
            }
        )
    
    def to_domain_event(self) -> dict[str, Any]:
        """Convert to domain event format for publishing."""
        return {
            "id": str(self.id),
            "aggregate_id": str(self.aggregate_id),
            "event_type": self.event_type,
            "event_data": self.event_data,
            "created_at": self.created_at.isoformat(),
            "retry_count": self.retry_count
        }