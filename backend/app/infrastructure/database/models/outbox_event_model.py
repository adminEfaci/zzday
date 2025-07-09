"""
OutboxEvent SQLModel

SQLModel definition for outbox event persistence.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlmodel import JSON, Column, Field, SQLModel

from app.models.outbox_event import OutboxEvent


class OutboxEventModel(SQLModel, table=True):
    """OutboxEvent persistence model."""
    
    __tablename__ = "outbox_events"
    
    # Core fields
    id: UUID = Field(primary_key=True)
    aggregate_id: UUID = Field(index=True)
    event_type: str = Field(max_length=100, index=True)
    event_data: dict[str, Any] = Field(sa_column=Column(JSON))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    processed_at: datetime | None = Field(default=None, index=True)
    
    # Retry management
    retry_count: int = Field(default=0, index=True)
    max_retries: int = Field(default=3)
    error_message: str | None = Field(default=None)
    
    @classmethod
    def from_domain(cls, event: OutboxEvent) -> "OutboxEventModel":
        """Create model from domain entity."""
        return cls(
            id=event.id,
            aggregate_id=event.aggregate_id,
            event_type=event.event_type,
            event_data=event.event_data,
            created_at=event.created_at,
            processed_at=event.processed_at,
            retry_count=event.retry_count,
            max_retries=event.max_retries,
            error_message=event.error_message
        )
    
    def to_domain(self) -> OutboxEvent:
        """Convert to domain entity."""
        return OutboxEvent(
            id=self.id,
            aggregate_id=self.aggregate_id,
            event_type=self.event_type,
            event_data=self.event_data,
            created_at=self.created_at,
            processed_at=self.processed_at,
            retry_count=self.retry_count,
            max_retries=self.max_retries,
            error_message=self.error_message
        )