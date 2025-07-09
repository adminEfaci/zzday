"""
OutboxRepository SQLAlchemy Adapter

SQLAlchemy implementation of the OutboxRepository interface.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlmodel import Session, and_, delete, select

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.infrastructure.database.models.outbox_event_model import OutboxEventModel
from app.models.outbox_event import OutboxEvent
from app.repositories.outbox_repository import OutboxRepository

logger = get_logger(__name__)


class OutboxRepositoryAdapter(OutboxRepository):
    """
    SQLAlchemy implementation of OutboxRepository.
    
    This adapter provides concrete implementation for outbox event persistence
    using SQLAlchemy, following the outbox pattern for atomic event storage.
    """
    
    def __init__(self, session: Session):
        """
        Initialize repository with database session.
        
        Args:
            session: SQLAlchemy session for database operations
        """
        self._session = session
    
    async def store_events(
        self, 
        events: list[OutboxEvent], 
        aggregate_id: UUID
    ) -> None:
        """
        Store events in outbox within same transaction.
        
        This method stores events in the database within the current transaction,
        ensuring atomicity with domain data changes.
        
        Args:
            events: List of domain events to store
            aggregate_id: ID of the aggregate that generated the events
            
        Raises:
            InfrastructureError: If storage fails
        """
        try:
            logger.debug(
                "Storing outbox events",
                aggregate_id=str(aggregate_id),
                event_count=len(events)
            )
            
            # Convert domain events to database models
            models = []
            for event in events:
                # Ensure aggregate_id matches
                if event.aggregate_id != aggregate_id:
                    event = event.model_copy(update={"aggregate_id": aggregate_id})
                
                model = OutboxEventModel.from_domain(event)
                models.append(model)
            
            # Add all models to session
            for model in models:
                self._session.add(model)
            
            # Note: Session commit is handled by Unit of Work
            # to ensure atomicity with domain data changes
            
            logger.debug(
                "Stored outbox events successfully",
                aggregate_id=str(aggregate_id),
                event_count=len(events)
            )
            
        except Exception as e:
            logger.exception(
                "Failed to store outbox events",
                aggregate_id=str(aggregate_id),
                event_count=len(events),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to store outbox events: {e}")
    
    async def get_unprocessed_events(
        self, 
        limit: int = 100
    ) -> list[OutboxEvent]:
        """
        Get unprocessed events for background processor.
        
        Retrieves events that haven't been processed yet and can be retried,
        ordered by creation time (oldest first).
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of unprocessed outbox events
            
        Raises:
            InfrastructureError: If retrieval fails
        """
        try:
            logger.debug(
                "Getting unprocessed events",
                limit=limit
            )
            
            # Query for unprocessed events that can be retried
            stmt = (
                select(OutboxEventModel)
                .where(
                    and_(
                        OutboxEventModel.processed_at.is_(None),
                        OutboxEventModel.retry_count < OutboxEventModel.max_retries
                    )
                )
                .order_by(OutboxEventModel.created_at.asc())
                .limit(limit)
            )
            
            result = self._session.exec(stmt)
            models = result.all()
            
            # Convert to domain entities
            events = [model.to_domain() for model in models]
            
            logger.debug(
                "Retrieved unprocessed events",
                event_count=len(events)
            )
            
            return events
            
        except Exception as e:
            logger.exception(
                "Failed to get unprocessed events",
                limit=limit,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get unprocessed events: {e}")
    
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
        try:
            logger.debug(
                "Marking event as processed",
                event_id=str(event_id)
            )
            
            # Find the event
            stmt = select(OutboxEventModel).where(OutboxEventModel.id == event_id)
            result = self._session.exec(stmt)
            model = result.first()
            
            if not model:
                raise InfrastructureError(f"Event not found: {event_id}")
            
            # Update processed timestamp and clear error
            model.processed_at = datetime.now(UTC)
            model.error_message = None
            
            # Add to session for commit
            self._session.add(model)
            self._session.commit()
            
            logger.debug(
                "Marked event as processed",
                event_id=str(event_id)
            )
            
        except Exception as e:
            logger.exception(
                "Failed to mark event as processed",
                event_id=str(event_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to mark event as processed: {e}")
    
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
        try:
            logger.debug(
                "Incrementing retry count for event",
                event_id=str(event_id),
                error_message=error_message
            )
            
            # Find the event
            stmt = select(OutboxEventModel).where(OutboxEventModel.id == event_id)
            result = self._session.exec(stmt)
            model = result.first()
            
            if not model:
                raise InfrastructureError(f"Event not found: {event_id}")
            
            # Increment retry count and set error message
            model.retry_count += 1
            model.error_message = error_message[:1000]  # Truncate long error messages
            
            # Add to session for commit
            self._session.add(model)
            self._session.commit()
            
            logger.debug(
                "Incremented retry count for event",
                event_id=str(event_id),
                retry_count=model.retry_count
            )
            
        except Exception as e:
            logger.exception(
                "Failed to increment retry count",
                event_id=str(event_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to increment retry count: {e}")
    
    async def get_failed_events(
        self, 
        limit: int = 100
    ) -> list[OutboxEvent]:
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
        try:
            logger.debug(
                "Getting failed events",
                limit=limit
            )
            
            # Query for events that have exhausted retries
            stmt = (
                select(OutboxEventModel)
                .where(
                    and_(
                        OutboxEventModel.processed_at.is_(None),
                        OutboxEventModel.retry_count >= OutboxEventModel.max_retries
                    )
                )
                .order_by(OutboxEventModel.created_at.asc())
                .limit(limit)
            )
            
            result = self._session.exec(stmt)
            models = result.all()
            
            # Convert to domain entities
            events = [model.to_domain() for model in models]
            
            logger.debug(
                "Retrieved failed events",
                event_count=len(events)
            )
            
            return events
            
        except Exception as e:
            logger.exception(
                "Failed to get failed events",
                limit=limit,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get failed events: {e}")
    
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
        try:
            logger.debug(
                "Cleaning up processed events",
                older_than_days=older_than_days
            )
            
            # Calculate cutoff date
            cutoff_date = datetime.now(UTC) - timedelta(days=older_than_days)
            
            # Delete processed events older than cutoff
            stmt = delete(OutboxEventModel).where(
                and_(
                    OutboxEventModel.processed_at.is_not(None),
                    OutboxEventModel.processed_at < cutoff_date
                )
            )
            
            result = self._session.exec(stmt)
            deleted_count = result.rowcount
            self._session.commit()
            
            logger.info(
                "Cleaned up processed events",
                deleted_count=deleted_count,
                older_than_days=older_than_days
            )
            
            return deleted_count
            
        except Exception as e:
            logger.exception(
                "Failed to cleanup processed events",
                older_than_days=older_than_days,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to cleanup processed events: {e}")
    
    async def get_events_by_aggregate(
        self, 
        aggregate_id: UUID,
        limit: int = 100
    ) -> list[OutboxEvent]:
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
        try:
            logger.debug(
                "Getting events by aggregate",
                aggregate_id=str(aggregate_id),
                limit=limit
            )
            
            # Query for events by aggregate
            stmt = (
                select(OutboxEventModel)
                .where(OutboxEventModel.aggregate_id == aggregate_id)
                .order_by(OutboxEventModel.created_at.asc())
                .limit(limit)
            )
            
            result = self._session.exec(stmt)
            models = result.all()
            
            # Convert to domain entities
            events = [model.to_domain() for model in models]
            
            logger.debug(
                "Retrieved events by aggregate",
                aggregate_id=str(aggregate_id),
                event_count=len(events)
            )
            
            return events
            
        except Exception as e:
            logger.exception(
                "Failed to get events by aggregate",
                aggregate_id=str(aggregate_id),
                limit=limit,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get events by aggregate: {e}")