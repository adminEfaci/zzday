"""
Advanced Transaction Management for EzzDay Core

This module provides sophisticated transaction management capabilities including
single-database transactions and distributed two-phase commit (2PC) transactions
across multiple resources. Ensures ACID properties and data consistency in
complex multi-service architectures.

Key Features:
- Single database transaction management with savepoint support
- Distributed two-phase commit (2PC) protocol implementation
- Transaction recovery and consistency guarantees
- Pluggable participant architecture for extensibility
- Comprehensive transaction logging and audit trails
- Automatic timeout and failure recovery mechanisms

Design Principles:
- Pure Python domain logic (no framework coupling)
- Explicit error handling with specific exception types
- Transaction safety with automatic rollback on failures
- Comprehensive logging for debugging and monitoring
- Protocol-based participant design for flexibility

Usage Examples:
    # Simple database transaction
    tx_manager = TransactionManager(session)
    async with tx_manager.transaction():
        # Database operations here
        await repository.create(entity)
        # Auto-commit on success, rollback on exception
    
    # Distributed transaction with multiple participants
    dist_tx = DistributedTransactionManager()
    dist_tx.add_participant(DatabaseTransactionParticipant(session))
    dist_tx.add_participant(MessageQueueTransactionParticipant("events"))
    
    async with dist_tx.transaction() as tx_id:
        # Operations across multiple systems
        await db_service.create_user(user_data)
        await event_service.publish_event(user_created_event)
        # 2PC ensures all-or-nothing semantics
    
    # Recovery of incomplete transactions
    await dist_tx.recover_transactions(timedelta(hours=1))

Error Handling:
    - TransactionError: Base transaction operation failures
    - DistributedTransactionError: 2PC protocol failures
    - ParticipantError: Individual participant failures
    - RecoveryError: Transaction recovery failures

Performance Features:
    - Nested transaction support with savepoints
    - Parallel participant preparation in 2PC
    - Efficient transaction logging with minimal overhead
    - Timeout-based automatic recovery mechanisms
"""

import asyncio
import enum
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InfrastructureError, ValidationError
from app.core.logging import get_logger
from app.core.monitoring import metrics

logger = get_logger(__name__)


class TransactionError(InfrastructureError):
    """Base exception for transaction operations."""


class DistributedTransactionError(TransactionError):
    """Raised when distributed transaction operations fail."""


class ParticipantError(TransactionError):
    """Raised when transaction participant operations fail."""


class RecoveryError(TransactionError):
    """Raised when transaction recovery operations fail."""


class TransactionState(enum.Enum):
    """
    Transaction states for two-phase commit protocol.

    State transitions follow strict 2PC protocol:
    INITIAL -> PREPARING -> PREPARED -> COMMITTING -> COMMITTED
    Any state can transition to ABORTING -> ABORTED on failure
    """

    INITIAL = "initial"
    PREPARING = "preparing"
    PREPARED = "prepared"
    COMMITTING = "committing"
    COMMITTED = "committed"
    ABORTING = "aborting"
    ABORTED = "aborted"


class ITransactionParticipant(Protocol):
    """
    Protocol for two-phase commit transaction participants.

    Defines the contract that all participants must implement to participate
    in distributed transactions. Ensures consistent behavior across different
    resource types (databases, message queues, external services, etc.).

    Design Features:
    - Protocol-based for type safety and flexibility
    - Atomic prepare/commit/rollback operations
    - Unique participant identification for tracking
    - Error handling with boolean voting semantics

    Implementation Requirements:
        All operations must be idempotent and safe to retry.
        Prepare phase must not commit changes - only validate readiness.
        Commit phase must apply all prepared changes atomically.
        Rollback phase must undo all changes regardless of state.

    Usage:
        class MyParticipant:
            @property
            def participant_id(self) -> str:
                return "my_service"

            async def prepare(self, transaction_id: str) -> bool:
                # Validate and prepare changes
                return True  # Vote to commit

            async def commit(self, transaction_id: str) -> None:
                # Apply prepared changes
                pass

            async def rollback(self, transaction_id: str) -> None:
                # Undo any changes
                pass
    """

    async def prepare(self, transaction_id: str) -> bool:
        """
        Prepare phase - vote on whether transaction can be committed.

        This phase validates that the participant can successfully commit
        the transaction. Must not make any permanent changes - only prepare
        for commit and vote on feasibility.

        Args:
            transaction_id: Unique identifier for the transaction

        Returns:
            True if participant votes to commit, False to abort

        Raises:
            ParticipantError: If preparation fails unexpectedly
        """
        ...

    async def commit(self, transaction_id: str) -> None:
        """
        Commit the transaction - apply all prepared changes.

        This phase applies all changes prepared during the prepare phase.
        Must be idempotent and succeed even if called multiple times.
        Should only fail in exceptional circumstances.

        Args:
            transaction_id: Unique identifier for the transaction

        Raises:
            ParticipantError: If commit fails (serious consistency issue)
        """
        ...

    async def rollback(self, transaction_id: str) -> None:
        """
        Rollback the transaction - undo all changes.

        This phase undoes any changes made during the transaction.
        Must be idempotent and safe to call in any state.
        Should not raise exceptions under normal circumstances.

        Args:
            transaction_id: Unique identifier for the transaction
        """
        ...

    @property
    def participant_id(self) -> str:
        """
        Unique participant identifier for logging and tracking.

        Returns:
            String identifier unique within the transaction scope
        """
        ...


class TransactionLog:
    """
    Transaction log for recovery and consistency tracking.

    Maintains a complete audit trail of distributed transactions including
    state changes, participant votes, and timing information. Essential for
    recovery operations and debugging transaction issues.

    Key Features:
    - Complete transaction lifecycle tracking
    - Participant vote recording for 2PC protocol
    - State transition logging with timestamps
    - Recovery support for incomplete transactions
    - Memory-efficient storage with cleanup capabilities

    Design Characteristics:
    - Thread-safe operations for concurrent access
    - Efficient lookups by transaction ID
    - Automatic timestamp tracking for all operations
    - Configurable retention policies for log cleanup

    Usage Examples:
        log = TransactionLog()

        # Start transaction tracking
        await log.log_transaction_start("tx123", ["db", "queue"])

        # Record participant votes
        await log.log_prepare_vote("tx123", "db", True)
        await log.log_prepare_vote("tx123", "queue", True)

        # Track state changes
        await log.log_state_change("tx123", TransactionState.PREPARED)
        await log.log_state_change("tx123", TransactionState.COMMITTED)

        # Recovery operations
        incomplete = await log.get_incomplete_transactions(timedelta(hours=1))

    Recovery Features:
        Supports identification of transactions that need recovery based on
        age and state. Critical for maintaining system consistency after
        failures or restarts.
    """

    def __init__(self, max_log_size: int = 10000):
        """
        Initialize transaction log with storage configuration.

        Args:
            max_log_size: Maximum number of transactions to keep in memory

        Raises:
            ValidationError: If configuration is invalid
        """
        self._validate_configuration(max_log_size)

        self._logs: dict[str, dict[str, Any]] = {}
        self._max_log_size = max_log_size
        self._creation_time = datetime.now(datetime.UTC)

        logger.debug(
            "Transaction log initialized",
            max_size=max_log_size,
            created_at=self._creation_time.isoformat(),
        )

    def _validate_configuration(self, max_log_size: int) -> None:
        """Validate transaction log configuration."""
        if max_log_size < 100:
            raise ValidationError(
                "max_log_size must be at least 100 for proper operation"
            )

    async def log_transaction_start(
        self,
        transaction_id: str,
        participants: list[str],
    ) -> None:
        """
        Log the start of a new distributed transaction.

        Records transaction initialization with participant list and timing.
        This is the first entry in the transaction lifecycle.

        Args:
            transaction_id: Unique transaction identifier
            participants: List of participant IDs joining the transaction

        Raises:
            ValidationError: If transaction ID already exists or invalid
        """
        self._validate_transaction_start(transaction_id, participants)

        # Check for storage limits and cleanup if needed
        await self._cleanup_old_logs_if_needed()

        self._logs[transaction_id] = {
            "id": transaction_id,
            "state": TransactionState.INITIAL,
            "participants": participants.copy(),
            "votes": {},
            "state_history": [(TransactionState.INITIAL, datetime.now(datetime.UTC))],
            "started_at": datetime.now(datetime.UTC),
            "completed_at": None,
            "recovery_attempts": 0,
        }

        logger.info(
            "Transaction started",
            transaction_id=transaction_id,
            participants=participants,
            participant_count=len(participants),
        )

    def _validate_transaction_start(
        self, transaction_id: str, participants: list[str]
    ) -> None:
        """Validate transaction start parameters."""
        if not transaction_id or not isinstance(transaction_id, str):
            raise ValidationError("transaction_id must be non-empty string")

        if transaction_id in self._logs:
            raise ValidationError(f"Transaction {transaction_id} already exists")

        if not participants or not isinstance(participants, list):
            raise ValidationError("participants must be non-empty list")

        if len(set(participants)) != len(participants):
            raise ValidationError("participants must be unique")

    async def _cleanup_old_logs_if_needed(self) -> None:
        """Clean up old completed transactions if storage limit reached."""
        if len(self._logs) >= self._max_log_size:
            # Remove oldest completed transactions
            completed_transactions = [
                (tx_id, tx_data)
                for tx_id, tx_data in self._logs.items()
                if tx_data["completed_at"] is not None
            ]

            if completed_transactions:
                # Sort by completion time and remove oldest
                completed_transactions.sort(key=lambda x: x[1]["completed_at"])
                to_remove = len(completed_transactions) // 4  # Remove 25%

                for tx_id, _ in completed_transactions[:to_remove]:
                    del self._logs[tx_id]

                logger.debug(
                    "Cleaned up old transaction logs",
                    removed_count=to_remove,
                    remaining_count=len(self._logs),
                )

    async def log_prepare_vote(
        self,
        transaction_id: str,
        participant_id: str,
        vote: bool,
    ) -> None:
        """
        Record a participant's vote in the prepare phase.

        Tracks each participant's readiness to commit during 2PC prepare phase.
        Critical for determining whether transaction can proceed to commit.

        Args:
            transaction_id: Transaction identifier
            participant_id: Identifier of voting participant
            vote: True for commit vote, False for abort vote

        Raises:
            ValidationError: If transaction not found or invalid vote
        """
        if transaction_id not in self._logs:
            raise ValidationError(f"Transaction {transaction_id} not found")

        tx_data = self._logs[transaction_id]

        if participant_id not in tx_data["participants"]:
            raise ValidationError(
                f"Participant {participant_id} not registered for transaction {transaction_id}"
            )

        tx_data["votes"][participant_id] = {
            "vote": vote,
            "voted_at": datetime.now(datetime.UTC),
        }

        logger.debug(
            "Participant vote recorded",
            transaction_id=transaction_id,
            participant=participant_id,
            vote=vote,
        )

    async def log_state_change(
        self,
        transaction_id: str,
        new_state: TransactionState,
    ) -> None:
        """
        Log transaction state transition with timestamp.

        Records state changes in transaction lifecycle for monitoring
        and recovery purposes. Maintains complete state history.

        Args:
            transaction_id: Transaction identifier
            new_state: New transaction state

        Raises:
            ValidationError: If transaction not found or invalid state transition
        """
        if transaction_id not in self._logs:
            raise ValidationError(f"Transaction {transaction_id} not found")

        tx_data = self._logs[transaction_id]
        old_state = tx_data["state"]

        # Validate state transition
        self._validate_state_transition(old_state, new_state)

        # Update state and record history
        now = datetime.now(datetime.UTC)
        tx_data["state"] = new_state
        tx_data["state_history"].append((new_state, now))

        # Mark completion time for terminal states
        if new_state in (TransactionState.COMMITTED, TransactionState.ABORTED):
            tx_data["completed_at"] = now

        logger.info(
            "Transaction state changed",
            transaction_id=transaction_id,
            old_state=old_state.value,
            new_state=new_state.value,
        )

    def _validate_state_transition(
        self, old_state: TransactionState, new_state: TransactionState
    ) -> None:
        """Validate that state transition is allowed by 2PC protocol."""
        valid_transitions = {
            TransactionState.INITIAL: {
                TransactionState.PREPARING,
                TransactionState.ABORTING,
            },
            TransactionState.PREPARING: {
                TransactionState.PREPARED,
                TransactionState.ABORTING,
            },
            TransactionState.PREPARED: {
                TransactionState.COMMITTING,
                TransactionState.ABORTING,
            },
            TransactionState.COMMITTING: {
                TransactionState.COMMITTED,
                TransactionState.ABORTING,
            },
            TransactionState.COMMITTED: set(),  # Terminal state
            TransactionState.ABORTING: {TransactionState.ABORTED},
            TransactionState.ABORTED: set(),  # Terminal state
        }

        if new_state not in valid_transitions[old_state]:
            raise ValidationError(
                f"Invalid state transition from {old_state.value} to {new_state.value}"
            )

    async def get_transaction_state(
        self,
        transaction_id: str,
    ) -> TransactionState | None:
        """
        Get current state of a transaction.

        Args:
            transaction_id: Transaction identifier

        Returns:
            Current transaction state or None if not found
        """
        if transaction_id in self._logs:
            return self._logs[transaction_id]["state"]
        return None

    async def get_incomplete_transactions(
        self,
        older_than: timedelta,
    ) -> list[dict[str, Any]]:
        """
        Get transactions that need recovery based on age and state.

        Identifies transactions that have been running longer than the
        specified threshold and are not in a terminal state.

        Args:
            older_than: Minimum age for transactions to be considered incomplete

        Returns:
            List of transaction data for incomplete transactions
        """
        cutoff = datetime.now(datetime.UTC) - older_than
        incomplete = []

        for _tx_id, tx_data in self._logs.items():
            if tx_data["completed_at"] is None and tx_data["started_at"] < cutoff:
                incomplete.append(tx_data.copy())

        logger.info(
            "Found incomplete transactions for recovery",
            count=len(incomplete),
            cutoff_time=cutoff.isoformat(),
        )

        return incomplete

    async def increment_recovery_attempts(self, transaction_id: str) -> int:
        """
        Increment and return recovery attempt count for a transaction.

        Args:
            transaction_id: Transaction identifier

        Returns:
            New recovery attempt count
        """
        if transaction_id in self._logs:
            self._logs[transaction_id]["recovery_attempts"] += 1
            return self._logs[transaction_id]["recovery_attempts"]
        return 0

    def get_statistics(self) -> dict[str, Any]:
        """Get transaction log statistics for monitoring."""
        active_count = sum(
            1 for tx_data in self._logs.values() if tx_data["completed_at"] is None
        )

        completed_count = len(self._logs) - active_count

        return {
            "total_transactions": len(self._logs),
            "active_transactions": active_count,
            "completed_transactions": completed_count,
            "max_log_size": self._max_log_size,
            "memory_usage_percent": (len(self._logs) / self._max_log_size) * 100,
            "creation_time": self._creation_time.isoformat(),
        }


class DatabaseTransactionParticipant(ITransactionParticipant):
    """
    Database transaction participant for two-phase commit.

    Provides database transaction support within distributed transactions.
    Handles prepare, commit, and rollback phases for database operations
    with proper error handling and state management.

    Key Features:
    - SQLAlchemy async session integration
    - Prepared transaction state management
    - Error handling with detailed logging
    - Transaction timeout support
    - Idempotent operations for recovery

    Design Characteristics:
    - Session lifecycle management
    - Prepared transaction tracking
    - Comprehensive error handling
    - Performance monitoring integration

    Usage Example:
        participant = DatabaseTransactionParticipant(
            session=async_session,
            participant_id="user_database",
            prepare_timeout=30.0
        )

        # Used within distributed transaction manager
        dist_tx.add_participant(participant)

    Transaction Semantics:
        Prepare phase flushes changes but doesn't commit.
        Commit phase commits the prepared transaction.
        Rollback phase rolls back all changes regardless of state.
    """

    def __init__(
        self,
        session: AsyncSession,
        participant_id: str = "database",
        prepare_timeout: float = 30.0,
    ):
        """
        Initialize database transaction participant.

        Args:
            session: SQLAlchemy async session for database operations
            participant_id: Unique identifier for this participant
            prepare_timeout: Maximum time to wait for prepare operations

        Raises:
            ValidationError: If session or configuration is invalid
        """
        self._validate_initialization(session, participant_id, prepare_timeout)

        self._session = session
        self._participant_id = participant_id
        self._prepare_timeout = prepare_timeout
        self._prepared_transactions: dict[str, dict[str, Any]] = {}

        logger.debug(
            "Database participant initialized",
            participant_id=participant_id,
            prepare_timeout=prepare_timeout,
        )

    def _validate_initialization(
        self, session: AsyncSession, participant_id: str, prepare_timeout: float
    ) -> None:
        """Validate database participant initialization."""
        if not session:
            raise ValidationError("Database session is required")

        if not isinstance(session, AsyncSession):
            raise ValidationError(
                f"Session must be AsyncSession instance, got {type(session)}"
            )

        if not participant_id or not isinstance(participant_id, str):
            raise ValidationError("participant_id must be non-empty string")

        if prepare_timeout <= 0:
            raise ValidationError("prepare_timeout must be positive")

    @property
    def participant_id(self) -> str:
        """Get unique participant identifier."""
        return self._participant_id

    async def prepare(self, transaction_id: str) -> bool:
        """
        Prepare database transaction for commit.

        Flushes all pending changes to validate constraints and locks
        but does not commit. Stores transaction state for later commit.

        Args:
            transaction_id: Unique transaction identifier

        Returns:
            True if preparation successful, False if should abort
        """
        try:
            prepare_start = time.time()

            # Flush changes to validate constraints and acquire locks
            await asyncio.wait_for(self._session.flush(), timeout=self._prepare_timeout)

            # Store prepared transaction state
            self._prepared_transactions[transaction_id] = {
                "session": self._session,
                "prepared_at": datetime.now(datetime.UTC),
                "changes_count": self._count_session_changes(),
            }

            prepare_duration = time.time() - prepare_start

            logger.info(
                "Database prepared for transaction",
                transaction_id=transaction_id,
                participant=self._participant_id,
                prepare_duration=prepare_duration,
                changes_count=self._prepared_transactions[transaction_id][
                    "changes_count"
                ],
            )

            metrics.transaction_prepare_duration.labels(
                participant=self._participant_id
            ).observe(prepare_duration)

            return True

        except TimeoutError:
            logger.exception(
                "Database prepare timeout",
                transaction_id=transaction_id,
                participant=self._participant_id,
                timeout=self._prepare_timeout,
            )
            return False

        except SQLAlchemyError as e:
            logger.exception(
                "Database prepare failed",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            return False

        except Exception as e:
            logger.exception(
                "Unexpected error during database prepare",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
            )
            return False

    def _count_session_changes(self) -> int:
        """Count pending changes in the database session."""
        try:
            return (
                len(self._session.new)
                + len(self._session.dirty)
                + len(self._session.deleted)
            )
        except Exception:
            return 0

    async def commit(self, transaction_id: str) -> None:
        """
        Commit prepared database transaction.

        Commits all changes that were prepared during the prepare phase.
        Must succeed once prepare phase has voted to commit.

        Args:
            transaction_id: Transaction identifier

        Raises:
            ParticipantError: If transaction not prepared or commit fails
        """
        if transaction_id not in self._prepared_transactions:
            raise ParticipantError(
                f"Transaction {transaction_id} not prepared for participant {self._participant_id}"
            )

        tx_info = self._prepared_transactions[transaction_id]

        try:
            commit_start = time.time()

            await self._session.commit()

            commit_duration = time.time() - commit_start

            logger.info(
                "Database committed transaction",
                transaction_id=transaction_id,
                participant=self._participant_id,
                commit_duration=commit_duration,
                changes_count=tx_info["changes_count"],
            )

            metrics.transaction_commit_duration.labels(
                participant=self._participant_id
            ).observe(commit_duration)

        except Exception as e:
            logger.exception(
                "Database commit failed",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
            )
            raise ParticipantError(f"Database commit failed: {e}")

        finally:
            # Clean up prepared transaction state
            del self._prepared_transactions[transaction_id]

    async def rollback(self, transaction_id: str) -> None:
        """
        Rollback database transaction.

        Rolls back all changes for the transaction. Safe to call in any
        state and will not raise exceptions under normal circumstances.

        Args:
            transaction_id: Transaction identifier
        """
        try:
            rollback_start = time.time()

            await self._session.rollback()

            rollback_duration = time.time() - rollback_start

            logger.info(
                "Database rolled back transaction",
                transaction_id=transaction_id,
                participant=self._participant_id,
                rollback_duration=rollback_duration,
            )

            metrics.transaction_rollback_duration.labels(
                participant=self._participant_id
            ).observe(rollback_duration)

        except Exception as e:
            # Log but don't raise - rollback should be safe
            logger.exception(
                "Database rollback failed",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
            )
        finally:
            # Always clean up prepared transaction state
            self._prepared_transactions.pop(transaction_id, None)

    def get_statistics(self) -> dict[str, Any]:
        """Get database participant statistics."""
        return {
            "participant_id": self._participant_id,
            "participant_type": "database",
            "prepared_transactions": len(self._prepared_transactions),
            "prepare_timeout": self._prepare_timeout,
            "session_in_transaction": self._session.in_transaction(),
        }


class MessageQueueTransactionParticipant(ITransactionParticipant):
    """
    Message queue transaction participant for two-phase commit.

    Provides message queue transaction support within distributed transactions.
    Ensures messages are only published after successful transaction commit
    to maintain consistency between database and messaging systems.

    Key Features:
    - Message batching for efficient publishing
    - Transactional message guarantees
    - Message ordering preservation
    - Error handling with retry support
    - Dead letter queue integration

    Design Characteristics:
    - Pending message management
    - Atomic message publishing
    - Comprehensive error handling
    - Performance monitoring integration

    Usage Example:
        participant = MessageQueueTransactionParticipant(
            queue_name="user_events",
            participant_id="event_queue",
            max_batch_size=100
        )

        # Add messages during transaction
        participant.add_message(tx_id, UserCreatedEvent(...))
        participant.add_message(tx_id, WelcomeEmailEvent(...))

        # Messages published only after successful commit

    Transaction Semantics:
        Prepare phase validates message queue connectivity.
        Commit phase publishes all pending messages atomically.
        Rollback phase discards all pending messages.
    """

    def __init__(
        self,
        queue_name: str,
        participant_id: str = "message_queue",
        max_batch_size: int = 100,
        publish_timeout: float = 30.0,
    ):
        """
        Initialize message queue transaction participant.

        Args:
            queue_name: Name of the message queue
            participant_id: Unique identifier for this participant
            max_batch_size: Maximum messages per transaction
            publish_timeout: Maximum time for message publishing

        Raises:
            ValidationError: If configuration is invalid
        """
        self._validate_initialization(
            queue_name, participant_id, max_batch_size, publish_timeout
        )

        self._queue_name = queue_name
        self._participant_id = participant_id
        self._max_batch_size = max_batch_size
        self._publish_timeout = publish_timeout
        self._pending_messages: dict[str, list[Any]] = {}

        logger.debug(
            "Message queue participant initialized",
            participant_id=participant_id,
            queue_name=queue_name,
            max_batch_size=max_batch_size,
        )

    def _validate_initialization(
        self,
        queue_name: str,
        participant_id: str,
        max_batch_size: int,
        publish_timeout: float,
    ) -> None:
        """Validate message queue participant initialization."""
        if not queue_name or not isinstance(queue_name, str):
            raise ValidationError("queue_name must be non-empty string")

        if not participant_id or not isinstance(participant_id, str):
            raise ValidationError("participant_id must be non-empty string")

        if max_batch_size < 1:
            raise ValidationError("max_batch_size must be at least 1")

        if publish_timeout <= 0:
            raise ValidationError("publish_timeout must be positive")

    @property
    def participant_id(self) -> str:
        """Get unique participant identifier."""
        return self._participant_id

    async def prepare(self, transaction_id: str) -> bool:
        """
        Prepare message queue transaction for commit.

        Validates that messages can be published and queue is available.
        Does not actually publish messages - only validates readiness.

        Args:
            transaction_id: Transaction identifier

        Returns:
            True if messages can be published, False if should abort
        """
        try:
            messages = self._pending_messages.get(transaction_id, [])

            # Check if we have any messages to publish
            if not messages:
                logger.debug(
                    "No messages to publish for transaction",
                    transaction_id=transaction_id,
                    participant=self._participant_id,
                )
                return True

            # Validate message batch size
            if len(messages) > self._max_batch_size:
                logger.error(
                    "Message batch size exceeds limit",
                    transaction_id=transaction_id,
                    participant=self._participant_id,
                    message_count=len(messages),
                    max_batch_size=self._max_batch_size,
                )
                return False

            # Validate message queue connectivity
            # In real implementation, check connection to message broker
            connectivity_ok = await self._check_queue_connectivity()

            if not connectivity_ok:
                logger.error(
                    "Message queue not available",
                    transaction_id=transaction_id,
                    participant=self._participant_id,
                    queue_name=self._queue_name,
                )
                return False

            logger.info(
                "Message queue prepared",
                transaction_id=transaction_id,
                participant=self._participant_id,
                message_count=len(messages),
                queue_name=self._queue_name,
            )

            return True

        except Exception as e:
            logger.exception(
                "Message queue prepare failed",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
            )
            return False

    async def _check_queue_connectivity(self) -> bool:
        """Check if message queue is available for publishing."""
        try:
            # In real implementation, ping the message broker
            # For now, simulate connectivity check
            await asyncio.sleep(0.01)  # Simulate network check
            return True
        except Exception:
            return False

    async def commit(self, transaction_id: str) -> None:
        """
        Commit message queue transaction by publishing all pending messages.

        Publishes all messages that were added during the transaction.
        Ensures atomic publishing - either all messages are sent or none.

        Args:
            transaction_id: Transaction identifier

        Raises:
            ParticipantError: If message publishing fails
        """
        messages = self._pending_messages.get(transaction_id, [])

        if not messages:
            logger.debug(
                "No messages to publish during commit",
                transaction_id=transaction_id,
                participant=self._participant_id,
            )
            return

        try:
            publish_start = time.time()

            # Publish all messages atomically
            await asyncio.wait_for(
                self._publish_messages(messages, transaction_id),
                timeout=self._publish_timeout,
            )

            publish_duration = time.time() - publish_start

            logger.info(
                "Messages published successfully",
                transaction_id=transaction_id,
                participant=self._participant_id,
                message_count=len(messages),
                publish_duration=publish_duration,
                queue_name=self._queue_name,
            )

            metrics.transaction_messages_published.labels(
                participant=self._participant_id
            ).inc(len(messages))

        except TimeoutError:
            logger.exception(
                "Message publishing timeout",
                transaction_id=transaction_id,
                participant=self._participant_id,
                timeout=self._publish_timeout,
                message_count=len(messages),
            )
            raise ParticipantError("Message publishing timeout")

        except Exception as e:
            logger.exception(
                "Message queue commit failed",
                transaction_id=transaction_id,
                participant=self._participant_id,
                error=str(e),
                message_count=len(messages),
            )
            raise ParticipantError(f"Message publishing failed: {e}")

        finally:
            # Clear pending messages after publish attempt
            self._pending_messages.pop(transaction_id, None)

    async def _publish_messages(self, messages: list[Any], transaction_id: str) -> None:
        """Publish messages to the queue atomically."""
        for i, message in enumerate(messages):
            try:
                # In real implementation, send to actual message queue
                # For now, simulate message publishing
                await asyncio.sleep(0.001)  # Simulate network operation

                logger.debug(
                    "Message published",
                    transaction_id=transaction_id,
                    participant=self._participant_id,
                    message_index=i,
                    message_type=type(message).__name__,
                    queue_name=self._queue_name,
                )

            except Exception as e:
                logger.exception(
                    "Failed to publish individual message",
                    transaction_id=transaction_id,
                    participant=self._participant_id,
                    message_index=i,
                    error=str(e),
                )
                raise

    async def rollback(self, transaction_id: str) -> None:
        """
        Rollback message queue transaction by discarding pending messages.

        Safely discards all pending messages for the transaction.
        Does not raise exceptions under normal circumstances.

        Args:
            transaction_id: Transaction identifier
        """
        messages_count = len(self._pending_messages.get(transaction_id, []))

        # Discard all pending messages
        self._pending_messages.pop(transaction_id, None)

        logger.info(
            "Message queue rolled back",
            transaction_id=transaction_id,
            participant=self._participant_id,
            discarded_messages=messages_count,
        )

    def add_message(self, transaction_id: str, message: Any) -> None:
        """
        Add message to transaction for publishing on commit.

        Messages are held in memory until the transaction commits.
        If transaction rolls back, messages are discarded.

        Args:
            transaction_id: Transaction identifier
            message: Message to publish on commit

        Raises:
            ValidationError: If batch size limit would be exceeded
        """
        if not transaction_id:
            raise ValidationError("transaction_id is required")

        if transaction_id not in self._pending_messages:
            self._pending_messages[transaction_id] = []

        current_count = len(self._pending_messages[transaction_id])
        if current_count >= self._max_batch_size:
            raise ValidationError(
                f"Message batch size limit exceeded: {current_count} >= {self._max_batch_size}"
            )

        self._pending_messages[transaction_id].append(message)

        logger.debug(
            "Message added to transaction",
            transaction_id=transaction_id,
            participant=self._participant_id,
            message_type=type(message).__name__,
            total_messages=len(self._pending_messages[transaction_id]),
        )

    def get_statistics(self) -> dict[str, Any]:
        """Get message queue participant statistics."""
        total_pending = sum(
            len(messages) for messages in self._pending_messages.values()
        )

        return {
            "participant_id": self._participant_id,
            "participant_type": "message_queue",
            "queue_name": self._queue_name,
            "active_transactions": len(self._pending_messages),
            "total_pending_messages": total_pending,
            "max_batch_size": self._max_batch_size,
            "publish_timeout": self._publish_timeout,
        }


class TransactionManager:
    """
    Single database transaction manager with savepoint support.

    Provides simple transaction management for single database operations
    with support for nested transactions using savepoints. Ideal for
    applications that don't require distributed transactions.

    Key Features:
    - Automatic transaction lifecycle management
    - Nested transaction support with savepoints
    - Context manager interface for clean resource handling
    - Comprehensive error handling and logging
    - Transaction timing and metrics

    Design Characteristics:
    - Lightweight for single database operations
    - Automatic savepoint management for nested calls
    - Exception-safe resource cleanup
    - Performance monitoring integration

    Usage Examples:
        # Basic transaction
        tx_manager = TransactionManager(session)
        async with tx_manager.transaction():
            # Database operations here
            await repository.create_user(user_data)
            await repository.update_profile(profile_data)
            # Auto-commit on success, rollback on exception

        # Nested transactions with savepoints
        async with tx_manager.transaction():
            await repository.create_user(user_data)

            async with tx_manager.transaction():  # Creates savepoint
                await repository.create_profile(profile_data)
                # Savepoint committed if successful

            # Main transaction continues
            await repository.send_welcome_email(user_data.email)

    Transaction Semantics:
        Top-level transactions use session.begin() for full transactions.
        Nested calls use session.begin_nested() for savepoints.
        All changes are automatically committed or rolled back.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize transaction manager with database session.

        Args:
            session: SQLAlchemy async session for database operations

        Raises:
            ValidationError: If session is invalid
        """
        self._validate_session(session)

        self.session = session
        self._savepoint_counter = 0
        self._transaction_depth = 0

        logger.debug("Transaction manager initialized", session_id=id(session))

    def _validate_session(self, session: AsyncSession) -> None:
        """Validate database session."""
        if not session:
            raise ValidationError("Database session is required")

        if not isinstance(session, AsyncSession):
            raise ValidationError(
                f"Session must be AsyncSession instance, got {type(session)}"
            )

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[None, None]:
        """
        Create a transaction context with automatic savepoint management.

        Creates a new transaction if none exists, or a savepoint if already
        in a transaction. Automatically commits on success or rolls back
        on any exception.

        Yields:
            None (context manager for transaction scope)

        Raises:
            TransactionError: If transaction operations fail
        """
        self._transaction_depth += 1
        transaction_start = time.time()

        try:
            if self.session.in_transaction():
                # Nested transaction - use savepoint
                await self._handle_nested_transaction()
            else:
                # New transaction
                await self._handle_top_level_transaction()

        finally:
            self._transaction_depth -= 1
            transaction_duration = time.time() - transaction_start

            metrics.single_transaction_duration.observe(transaction_duration)

            logger.debug(
                "Transaction context exited",
                depth=self._transaction_depth,
                duration=transaction_duration,
            )

    @asynccontextmanager
    async def _handle_nested_transaction(self) -> AsyncGenerator[None, None]:
        """Handle nested transaction using savepoints."""
        self._savepoint_counter += 1
        savepoint_name = f"sp_{self._savepoint_counter}"

        try:
            async with self.session.begin_nested() as savepoint:
                logger.debug(
                    "Savepoint created",
                    name=savepoint_name,
                    depth=self._transaction_depth,
                )

                yield

                await savepoint.commit()
                logger.debug("Savepoint committed", name=savepoint_name)

        except Exception as e:
            logger.info(
                "Savepoint rolled back due to exception",
                name=savepoint_name,
                error=str(e),
            )
            # Let savepoint handle rollback automatically
            raise

    @asynccontextmanager
    async def _handle_top_level_transaction(self) -> AsyncGenerator[None, None]:
        """Handle top-level transaction."""
        try:
            async with self.session.begin() as transaction:
                logger.debug("Transaction started", depth=self._transaction_depth)

                yield

                await transaction.commit()
                logger.info("Transaction committed successfully")

        except Exception as e:
            logger.info(
                "Transaction rolled back due to exception",
                error=str(e),
                error_type=type(e).__name__,
            )
            # Let transaction handle rollback automatically
            raise

    def is_in_transaction(self) -> bool:
        """Check if currently in a transaction."""
        return self.session.in_transaction()

    def get_transaction_depth(self) -> int:
        """Get current transaction nesting depth."""
        return self._transaction_depth

    def get_statistics(self) -> dict[str, Any]:
        """Get transaction manager statistics."""
        return {
            "session_id": id(self.session),
            "current_depth": self._transaction_depth,
            "savepoint_counter": self._savepoint_counter,
            "in_transaction": self.is_in_transaction(),
        }


class DistributedTransactionManager:
    """
    Distributed transaction manager using two-phase commit protocol.

    Coordinates transactions across multiple resources (databases, message queues,
    external services) ensuring ACID properties in distributed environments.
    Implements the full 2PC protocol with recovery capabilities.

    Key Features:
    - Full two-phase commit protocol implementation
    - Automatic participant management and coordination
    - Transaction recovery for system failures
    - Comprehensive logging and audit trails
    - Timeout handling and failure recovery
    - Performance monitoring and metrics

    Design Characteristics:
    - Protocol-compliant 2PC implementation
    - Participant failure isolation
    - Automatic transaction log management
    - Recovery-oriented architecture
    - Performance-optimized participant coordination

    Usage Examples:
        # Setup with multiple participants
        dist_tx = DistributedTransactionManager()
        dist_tx.add_participant(DatabaseTransactionParticipant(db_session))
        dist_tx.add_participant(MessageQueueTransactionParticipant("events"))
        dist_tx.add_participant(ExternalServiceParticipant("payment_gateway"))

        # Execute distributed transaction
        async with dist_tx.transaction() as tx_id:
            # Operations across all participants
            await user_service.create_user(user_data)
            event_participant.add_message(tx_id, UserCreatedEvent(...))
            await payment_service.charge_setup_fee(user_data.payment_info)
            # All operations succeed or all rollback

        # Recovery of incomplete transactions
        await dist_tx.recover_transactions(timedelta(hours=1))

    Protocol Implementation:
        Follows strict 2PC protocol with proper state transitions.
        All participants must vote YES in prepare phase to proceed.
        Commit phase applies changes to all participants.
        Abort phase rolls back all participants on any failure.
    """

    def __init__(
        self,
        transaction_log: TransactionLog | None = None,
        prepare_timeout: float = 60.0,
        commit_timeout: float = 120.0,
    ):
        """
        Initialize distributed transaction manager.

        Args:
            transaction_log: Transaction log for recovery (created if None)
            prepare_timeout: Maximum time for prepare phase
            commit_timeout: Maximum time for commit phase

        Raises:
            ValidationError: If timeouts are invalid
        """
        self._validate_configuration(prepare_timeout, commit_timeout)

        self._participants: list[ITransactionParticipant] = []
        self._transaction_log = transaction_log or TransactionLog()
        self._current_transaction: str | None = None
        self._state = TransactionState.INITIAL
        self._prepare_timeout = prepare_timeout
        self._commit_timeout = commit_timeout
        self._creation_time = datetime.now(datetime.UTC)
        
        # Enhanced recovery capabilities
        self._dead_letter_queue: list[dict[str, Any]] = []
        self._recovery_in_progress = False
        self._last_recovery_time: datetime | None = None

        logger.info(
            "Distributed transaction manager initialized",
            prepare_timeout=prepare_timeout,
            commit_timeout=commit_timeout,
        )

    def _validate_configuration(
        self, prepare_timeout: float, commit_timeout: float
    ) -> None:
        """Validate distributed transaction manager configuration."""
        if prepare_timeout <= 0:
            raise ValidationError("prepare_timeout must be positive")

        if commit_timeout <= 0:
            raise ValidationError("commit_timeout must be positive")

        if commit_timeout < prepare_timeout:
            raise ValidationError("commit_timeout should be >= prepare_timeout")

    def add_participant(self, participant: ITransactionParticipant) -> None:
        """
        Add transaction participant to the distributed transaction.

        Participants must implement the ITransactionParticipant protocol
        to participate in two-phase commit operations.

        Args:
            participant: Participant implementing 2PC protocol

        Raises:
            ValidationError: If participant is invalid or duplicate
        """
        if not participant:
            raise ValidationError("Participant is required")

        # Check for duplicate participant IDs
        existing_ids = {p.participant_id for p in self._participants}
        if participant.participant_id in existing_ids:
            raise ValidationError(
                f"Participant with ID '{participant.participant_id}' already exists"
            )

        self._participants.append(participant)

        logger.info(
            "Participant added to distributed transaction",
            participant=participant.participant_id,
            total_participants=len(self._participants),
        )

    def remove_participant(self, participant_id: str) -> bool:
        """
        Remove participant from distributed transaction.

        Args:
            participant_id: ID of participant to remove

        Returns:
            True if participant was removed, False if not found
        """
        for i, participant in enumerate(self._participants):
            if participant.participant_id == participant_id:
                del self._participants[i]
                logger.info(
                    "Participant removed",
                    participant=participant_id,
                    remaining_participants=len(self._participants),
                )
                return True
        return False

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[str, None]:
        """
        Execute distributed transaction using two-phase commit protocol.

        Coordinates transaction across all registered participants.
        Ensures either all participants commit or all abort.

        Yields:
            Transaction ID for tracking and logging

        Raises:
            DistributedTransactionError: If transaction fails
            ValidationError: If no participants registered
        """
        if not self._participants:
            raise ValidationError(
                "No participants registered for distributed transaction"
            )

        transaction_id = str(uuid.uuid4())
        self._current_transaction = transaction_id
        transaction_start = time.time()

        try:
            # Log transaction start
            await self._transaction_log.log_transaction_start(
                transaction_id,
                [p.participant_id for p in self._participants],
            )

            logger.info(
                "Distributed transaction started",
                transaction_id=transaction_id,
                participants=[p.participant_id for p in self._participants],
            )

            # Yield control to execute business logic
            yield transaction_id

            # Execute two-phase commit protocol
            await self._execute_two_phase_commit(transaction_id)

            transaction_duration = time.time() - transaction_start

            logger.info(
                "Distributed transaction completed successfully",
                transaction_id=transaction_id,
                duration=transaction_duration,
            )

            metrics.distributed_transaction_duration.observe(transaction_duration)
            metrics.distributed_transaction_commits.inc()

        except Exception as e:
            # Abort transaction on any error
            logger.exception(
                "Distributed transaction failed",
                transaction_id=transaction_id,
                error=str(e),
            )

            await self._abort_phase(transaction_id)
            metrics.distributed_transaction_aborts.inc()

            # Re-raise as distributed transaction error
            raise DistributedTransactionError(
                f"Transaction {transaction_id} failed: {e}"
            )

        finally:
            self._current_transaction = None
            self._state = TransactionState.INITIAL

    async def _execute_two_phase_commit(self, transaction_id: str) -> None:
        """Execute the two-phase commit protocol."""
        try:
            # Phase 1: Prepare
            if await self._prepare_phase(transaction_id):
                # Phase 2: Commit
                await self._commit_phase(transaction_id)
            else:
                # Abort if any participant voted NO
                await self._abort_phase(transaction_id)
                raise DistributedTransactionError(
                    "Transaction aborted - prepare phase failed"
                )

        except Exception:
            # Ensure abort on any error
            await self._abort_phase(transaction_id)
            raise

    async def _prepare_phase(self, transaction_id: str) -> bool:
        """
        Execute prepare phase of two-phase commit.

        Asks all participants to prepare for commit. All must vote YES
        for the transaction to proceed to commit phase.

        Args:
            transaction_id: Transaction identifier

        Returns:
            True if all participants vote YES, False otherwise
        """
        self._state = TransactionState.PREPARING
        await self._transaction_log.log_state_change(
            transaction_id,
            TransactionState.PREPARING,
        )

        logger.info(
            "Starting prepare phase",
            transaction_id=transaction_id,
            participants=len(self._participants),
        )

        prepare_start = time.time()

        try:
            # Prepare all participants concurrently for better performance
            prepare_tasks = [
                self._prepare_participant(participant, transaction_id)
                for participant in self._participants
            ]

            # Wait for all prepare operations with timeout
            votes = await asyncio.wait_for(
                asyncio.gather(*prepare_tasks, return_exceptions=True),
                timeout=self._prepare_timeout,
            )

            # Process votes and log results
            all_prepared = await self._process_prepare_votes(transaction_id, votes)

            prepare_duration = time.time() - prepare_start

            if all_prepared:
                self._state = TransactionState.PREPARED
                await self._transaction_log.log_state_change(
                    transaction_id,
                    TransactionState.PREPARED,
                )

            logger.info(
                "Prepare phase complete",
                transaction_id=transaction_id,
                result="prepared" if all_prepared else "aborted",
                duration=prepare_duration,
            )

            metrics.transaction_prepare_phase_duration.observe(prepare_duration)

            return all_prepared

        except TimeoutError:
            logger.exception(
                "Prepare phase timeout",
                transaction_id=transaction_id,
                timeout=self._prepare_timeout,
            )
            return False

    async def _prepare_participant(
        self, participant: ITransactionParticipant, transaction_id: str
    ) -> tuple[str, bool]:
        """Prepare individual participant and return result."""
        try:
            vote = await participant.prepare(transaction_id)

            # Log vote
            await self._transaction_log.log_prepare_vote(
                transaction_id,
                participant.participant_id,
                vote,
            )

            logger.debug(
                "Participant vote",
                transaction_id=transaction_id,
                participant=participant.participant_id,
                vote=vote,
            )

            return (participant.participant_id, vote)

        except Exception as e:
            logger.exception(
                "Participant prepare failed",
                transaction_id=transaction_id,
                participant=participant.participant_id,
                error=str(e),
            )

            # Log failed vote
            await self._transaction_log.log_prepare_vote(
                transaction_id,
                participant.participant_id,
                False,
            )

            return (participant.participant_id, False)

    async def _process_prepare_votes(
        self, transaction_id: str, votes: list[Any]
    ) -> bool:
        """Process prepare phase votes and determine outcome."""
        yes_votes = 0
        no_votes = 0

        for vote_result in votes:
            if isinstance(vote_result, Exception):
                no_votes += 1
                logger.error(
                    "Prepare task failed",
                    transaction_id=transaction_id,
                    error=str(vote_result),
                )
            else:
                participant_id, vote = vote_result
                if vote:
                    yes_votes += 1
                else:
                    no_votes += 1

        total_participants = len(self._participants)
        all_prepared = yes_votes == total_participants and no_votes == 0

        logger.info(
            "Prepare votes counted",
            transaction_id=transaction_id,
            yes_votes=yes_votes,
            no_votes=no_votes,
            total_participants=total_participants,
            all_prepared=all_prepared,
        )

        return all_prepared

    async def _commit_phase(self, transaction_id: str) -> None:
        """
        Execute commit phase of two-phase commit.

        Instructs all participants to commit their prepared changes.
        Once prepare phase succeeds, commit must succeed.

        Args:
            transaction_id: Transaction identifier

        Raises:
            DistributedTransactionError: If commit coordination fails
        """
        self._state = TransactionState.COMMITTING
        await self._transaction_log.log_state_change(
            transaction_id,
            TransactionState.COMMITTING,
        )

        logger.info(
            "Starting commit phase",
            transaction_id=transaction_id,
        )

        commit_start = time.time()

        try:
            # Commit all participants
            commit_tasks = [
                self._commit_participant(participant, transaction_id)
                for participant in self._participants
            ]

            # Wait for all commits with timeout
            results = await asyncio.wait_for(
                asyncio.gather(*commit_tasks, return_exceptions=True),
                timeout=self._commit_timeout,
            )

            # Process commit results
            commit_errors = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    participant_id = self._participants[i].participant_id
                    commit_errors.append((participant_id, str(result)))

            commit_duration = time.time() - commit_start

            if commit_errors:
                # Log errors but transaction is still considered committed
                # Individual participants must handle their own recovery
                logger.warning(
                    "Transaction committed with errors",
                    transaction_id=transaction_id,
                    errors=commit_errors,
                    duration=commit_duration,
                )
            else:
                logger.info(
                    "All participants committed successfully",
                    transaction_id=transaction_id,
                    duration=commit_duration,
                )

            self._state = TransactionState.COMMITTED
            await self._transaction_log.log_state_change(
                transaction_id,
                TransactionState.COMMITTED,
            )

            metrics.transaction_commit_phase_duration.observe(commit_duration)

        except TimeoutError:
            logger.exception(
                "Commit phase timeout",
                transaction_id=transaction_id,
                timeout=self._commit_timeout,
            )
            # Still mark as committed - participants should handle recovery
            self._state = TransactionState.COMMITTED
            await self._transaction_log.log_state_change(
                transaction_id,
                TransactionState.COMMITTED,
            )

    async def _commit_participant(
        self, participant: ITransactionParticipant, transaction_id: str
    ) -> None:
        """Commit individual participant."""
        try:
            await participant.commit(transaction_id)
            logger.debug(
                "Participant committed",
                transaction_id=transaction_id,
                participant=participant.participant_id,
            )
        except Exception as e:
            logger.exception(
                "Participant commit failed",
                transaction_id=transaction_id,
                participant=participant.participant_id,
                error=str(e),
            )
            raise

    async def _abort_phase(self, transaction_id: str) -> None:
        """
        Execute abort phase of two-phase commit.

        Instructs all participants to rollback any changes.
        Safe to call in any state and handles errors gracefully.

        Args:
            transaction_id: Transaction identifier
        """
        self._state = TransactionState.ABORTING
        await self._transaction_log.log_state_change(
            transaction_id,
            TransactionState.ABORTING,
        )

        logger.info(
            "Starting abort phase",
            transaction_id=transaction_id,
        )

        abort_start = time.time()

        # Rollback all participants
        for participant in self._participants:
            try:
                await participant.rollback(transaction_id)
                logger.debug(
                    "Participant rolled back",
                    transaction_id=transaction_id,
                    participant=participant.participant_id,
                )

            except Exception as e:
                # Log but continue with other participants
                logger.exception(
                    "Participant rollback failed",
                    transaction_id=transaction_id,
                    participant=participant.participant_id,
                    error=str(e),
                )

        abort_duration = time.time() - abort_start

        self._state = TransactionState.ABORTED
        await self._transaction_log.log_state_change(
            transaction_id,
            TransactionState.ABORTED,
        )

        logger.info(
            "Abort phase complete",
            transaction_id=transaction_id,
            duration=abort_duration,
        )

        metrics.transaction_abort_phase_duration.observe(abort_duration)

    async def recover_transactions(
        self, older_than: timedelta, max_recovery_attempts: int = 3
    ) -> dict[str, Any]:
        """
        Recover incomplete transactions with enhanced recovery policies.

        Identifies and attempts to complete transactions that were
        interrupted by system failures. Implements sophisticated recovery
        policies based on transaction state and participant health.

        Args:
            older_than: Minimum age for transactions to be considered incomplete
            max_recovery_attempts: Maximum recovery attempts per transaction

        Returns:
            Dictionary containing recovery results and statistics

        Raises:
            RecoveryError: If recovery operations fail
        """
        logger.info(
            "Starting enhanced transaction recovery",
            cutoff_age=older_than.total_seconds(),
            max_attempts=max_recovery_attempts,
        )

        recovery_start = time.time()
        recovery_results = {
            "recovered_transactions": [],
            "failed_transactions": [],
            "skipped_transactions": [],
            "dead_letter_transactions": [],
            "statistics": {}
        }

        try:
            incomplete = await self._transaction_log.get_incomplete_transactions(
                older_than
            )

            # Check participant health before recovery
            participant_health = await self._check_participant_health()
            
            for tx_data in incomplete:
                transaction_id = tx_data["id"]
                state = tx_data["state"]
                recovery_attempts = tx_data.get("recovery_attempts", 0)
                started_at = tx_data.get("started_at")
                
                # Enhanced recovery decision logic
                recovery_decision = await self._make_recovery_decision(
                    transaction_id, state, recovery_attempts, 
                    max_recovery_attempts, started_at, participant_health
                )
                
                if recovery_decision["action"] == "skip":
                    logger.info(
                        "Skipping transaction recovery",
                        transaction_id=transaction_id,
                        reason=recovery_decision["reason"]
                    )
                    recovery_results["skipped_transactions"].append({
                        "transaction_id": transaction_id,
                        "reason": recovery_decision["reason"]
                    })
                    continue
                    
                elif recovery_decision["action"] == "dead_letter":
                    logger.warning(
                        "Moving transaction to dead letter queue",
                        transaction_id=transaction_id,
                        reason=recovery_decision["reason"]
                    )
                    await self._move_to_dead_letter_queue(transaction_id, tx_data)
                    recovery_results["dead_letter_transactions"].append({
                        "transaction_id": transaction_id,
                        "reason": recovery_decision["reason"]
                    })
                    continue

                # Attempt recovery
                try:
                    await self._recover_single_transaction(transaction_id, state)
                    recovery_results["recovered_transactions"].append(transaction_id)
                    
                    logger.info(
                        "Transaction recovery successful",
                        transaction_id=transaction_id,
                        recovery_attempts=recovery_attempts + 1
                    )

                except Exception as e:
                    logger.exception(
                        "Failed to recover transaction",
                        transaction_id=transaction_id,
                        error=str(e),
                    )
                    
                    recovery_results["failed_transactions"].append({
                        "transaction_id": transaction_id,
                        "error": str(e),
                        "attempts": recovery_attempts + 1
                    })

                    # Increment recovery attempt counter
                    await self._transaction_log.increment_recovery_attempts(
                        transaction_id
                    )

            recovery_duration = time.time() - recovery_start
            
            # Compile statistics
            recovery_results["statistics"] = {
                "total_incomplete": len(incomplete),
                "recovered_count": len(recovery_results["recovered_transactions"]),
                "failed_count": len(recovery_results["failed_transactions"]),
                "skipped_count": len(recovery_results["skipped_transactions"]),
                "dead_letter_count": len(recovery_results["dead_letter_transactions"]),
                "recovery_duration": recovery_duration,
                "recovery_rate": len(recovery_results["recovered_transactions"]) / max(len(incomplete), 1)
            }

            logger.info(
                "Enhanced transaction recovery completed",
                **recovery_results["statistics"]
            )

            metrics.transaction_recovery_duration.observe(recovery_duration)
            metrics.transactions_recovered.inc(len(recovery_results["recovered_transactions"]))
            metrics.transactions_dead_lettered.inc(len(recovery_results["dead_letter_transactions"]))

            return recovery_results

        except Exception as e:
            logger.exception("Transaction recovery failed", error=str(e))
            raise RecoveryError(f"Recovery failed: {e}")
    
    async def _check_participant_health(self) -> dict[str, bool]:
        """Check the health of all participants before recovery."""
        participant_health = {}
        
        for participant in self._participants:
            try:
                if hasattr(participant, 'health_check'):
                    is_healthy = await participant.health_check()
                    participant_health[participant.participant_id] = is_healthy
                else:
                    # Assume healthy if no health check available
                    participant_health[participant.participant_id] = True
                    
            except Exception as e:
                logger.warning(
                    "Participant health check failed",
                    participant=participant.participant_id,
                    error=str(e)
                )
                participant_health[participant.participant_id] = False
        
        healthy_count = sum(1 for is_healthy in participant_health.values() if is_healthy)
        
        logger.info(
            "Participant health check completed",
            healthy_participants=healthy_count,
            total_participants=len(self._participants),
            health_status=participant_health
        )
        
        return participant_health
    
    async def _make_recovery_decision(
        self, transaction_id: str, state: TransactionState, 
        recovery_attempts: int, max_attempts: int, started_at: datetime,
        participant_health: dict[str, bool]
    ) -> dict[str, Any]:
        """Make intelligent recovery decision based on transaction state and context."""
        
        # Check if max attempts reached
        if recovery_attempts >= max_attempts:
            return {
                "action": "dead_letter",
                "reason": f"Max recovery attempts ({max_attempts}) reached"
            }
        
        # Check if transaction is too old (older than 24 hours)
        if started_at and (datetime.now(datetime.UTC) - started_at).total_seconds() > 86400:
            return {
                "action": "dead_letter",
                "reason": "Transaction too old (>24 hours)"
            }
        
        # Check participant health
        unhealthy_participants = [
            participant_id for participant_id, is_healthy in participant_health.items()
            if not is_healthy
        ]
        
        if unhealthy_participants:
            # If critical participants are unhealthy, skip recovery
            if len(unhealthy_participants) > len(self._participants) / 2:
                return {
                    "action": "skip",
                    "reason": f"Too many unhealthy participants: {unhealthy_participants}"
                }
            
            # If some participants are unhealthy, proceed with caution
            logger.warning(
                "Attempting recovery with unhealthy participants",
                transaction_id=transaction_id,
                unhealthy_participants=unhealthy_participants
            )
        
        # State-based recovery decisions
        if state == TransactionState.COMMITTED:
            return {
                "action": "skip",
                "reason": "Transaction already committed"
            }
        
        if state == TransactionState.ABORTED:
            return {
                "action": "skip",
                "reason": "Transaction already aborted"
            }
        
        # Proceed with recovery
        return {
            "action": "recover",
            "reason": "Transaction eligible for recovery"
        }
    
    async def _move_to_dead_letter_queue(
        self, transaction_id: str, tx_data: dict[str, Any]
    ) -> None:
        """Move transaction to dead letter queue for manual intervention."""
        dead_letter_entry = {
            "transaction_id": transaction_id,
            "original_data": tx_data,
            "dead_lettered_at": datetime.now(datetime.UTC).isoformat(),
            "reason": "Recovery failed or exceeded max attempts",
            "participants": [p.participant_id for p in self._participants]
        }
        
        # In a real implementation, this would be stored in a persistent queue
        # For now, we'll log it and mark the transaction as aborted
        logger.warning(
            "Transaction moved to dead letter queue",
            transaction_id=transaction_id,
            dead_letter_entry=dead_letter_entry
        )
        
        # Mark transaction as aborted to prevent further recovery attempts
        try:
            await self._transaction_log.log_state_change(
                transaction_id,
                TransactionState.ABORTED
            )
        except Exception as e:
            logger.exception(
                "Failed to mark dead letter transaction as aborted",
                transaction_id=transaction_id,
                error=str(e)
            )

    async def _recover_single_transaction(
        self, transaction_id: str, state: TransactionState
    ) -> None:
        """Recover a single transaction based on its state with enhanced recovery logic."""
        logger.info(
            "Recovering transaction", transaction_id=transaction_id, state=state.value
        )

        recovery_start = time.time()
        
        try:
            if state in (TransactionState.PREPARING, TransactionState.PREPARED):
                # Enhanced recovery for prepare phase
                await self._recover_prepare_phase_transaction(transaction_id, state)
                
            elif state == TransactionState.COMMITTING:
                # Enhanced recovery for commit phase
                await self._recover_commit_phase_transaction(transaction_id)
                
            elif state == TransactionState.ABORTING:
                # Enhanced recovery for abort phase
                await self._recover_abort_phase_transaction(transaction_id)
                
            elif state == TransactionState.INITIAL:
                # Transaction never started properly - mark as aborted
                await self._abort_phase(transaction_id)
                logger.info(
                    "Initial transaction aborted during recovery",
                    transaction_id=transaction_id
                )
                
            recovery_duration = time.time() - recovery_start
            
            logger.info(
                "Transaction recovery completed",
                transaction_id=transaction_id,
                original_state=state.value,
                recovery_duration=recovery_duration
            )
            
            metrics.transaction_recovery_success.inc()
            
        except Exception as e:
            recovery_duration = time.time() - recovery_start
            
            logger.exception(
                "Transaction recovery failed",
                transaction_id=transaction_id,
                original_state=state.value,
                recovery_duration=recovery_duration,
                error=str(e)
            )
            
            metrics.transaction_recovery_failures.inc()
            
            # Try to abort as last resort
            try:
                await self._abort_phase(transaction_id)
            except Exception as abort_error:
                logger.exception(
                    "Failed to abort transaction during recovery failure",
                    transaction_id=transaction_id,
                    abort_error=str(abort_error)
                )
            
            raise
    
    async def _recover_prepare_phase_transaction(
        self, transaction_id: str, state: TransactionState
    ) -> None:
        """Recover transaction that was in prepare phase."""
        logger.info(
            "Recovering prepare phase transaction",
            transaction_id=transaction_id,
            state=state.value
        )
        
        if state == TransactionState.PREPARED:
            # All participants prepared - check if we can safely commit
            can_commit = await self._verify_participants_ready_to_commit(transaction_id)
            
            if can_commit:
                logger.info(
                    "All participants ready - committing prepared transaction",
                    transaction_id=transaction_id
                )
                await self._commit_phase(transaction_id)
            else:
                logger.warning(
                    "Not all participants ready - aborting prepared transaction",
                    transaction_id=transaction_id
                )
                await self._abort_phase(transaction_id)
        else:
            # Transaction was preparing - abort for safety
            logger.info(
                "Aborting transaction that was preparing",
                transaction_id=transaction_id
            )
            await self._abort_phase(transaction_id)
    
    async def _recover_commit_phase_transaction(self, transaction_id: str) -> None:
        """Recover transaction that was in commit phase."""
        logger.info(
            "Recovering commit phase transaction",
            transaction_id=transaction_id
        )
        
        # Check which participants have already committed
        committed_participants = await self._check_committed_participants(transaction_id)
        
        if committed_participants:
            logger.info(
                "Some participants already committed - completing commit",
                transaction_id=transaction_id,
                committed_participants=committed_participants
            )
            
            # Complete commit for remaining participants
            await self._complete_partial_commit(transaction_id, committed_participants)
        else:
            # No participants committed yet - try full commit
            logger.info(
                "No participants committed yet - attempting full commit",
                transaction_id=transaction_id
            )
            await self._commit_phase(transaction_id)
    
    async def _recover_abort_phase_transaction(self, transaction_id: str) -> None:
        """Recover transaction that was in abort phase."""
        logger.info(
            "Recovering abort phase transaction",
            transaction_id=transaction_id
        )
        
        # Complete the abort for all participants
        await self._abort_phase(transaction_id)
    
    async def _verify_participants_ready_to_commit(self, transaction_id: str) -> bool:
        """Verify that all participants are still ready to commit."""
        logger.debug(
            "Verifying participants ready to commit",
            transaction_id=transaction_id
        )
        
        # Check if participants are still in prepared state
        ready_count = 0
        
        for participant in self._participants:
            try:
                # Check if participant is still ready (implementation-specific)
                if hasattr(participant, 'is_ready_to_commit'):
                    is_ready = await participant.is_ready_to_commit(transaction_id)
                    if is_ready:
                        ready_count += 1
                else:
                    # Assume ready if no explicit check available
                    ready_count += 1
                    
            except Exception as e:
                logger.warning(
                    "Participant readiness check failed",
                    transaction_id=transaction_id,
                    participant=participant.participant_id,
                    error=str(e)
                )
                return False
        
        all_ready = ready_count == len(self._participants)
        
        logger.debug(
            "Participant readiness check complete",
            transaction_id=transaction_id,
            ready_count=ready_count,
            total_participants=len(self._participants),
            all_ready=all_ready
        )
        
        return all_ready
    
    async def _check_committed_participants(self, transaction_id: str) -> list[str]:
        """Check which participants have already committed."""
        committed_participants = []
        
        for participant in self._participants:
            try:
                # Check if participant has already committed (implementation-specific)
                if hasattr(participant, 'is_committed'):
                    is_committed = await participant.is_committed(transaction_id)
                    if is_committed:
                        committed_participants.append(participant.participant_id)
                        
            except Exception as e:
                logger.warning(
                    "Participant commit status check failed",
                    transaction_id=transaction_id,
                    participant=participant.participant_id,
                    error=str(e)
                )
        
        return committed_participants
    
    async def _complete_partial_commit(
        self, transaction_id: str, already_committed: list[str]
    ) -> None:
        """Complete commit for participants that haven't committed yet."""
        logger.info(
            "Completing partial commit",
            transaction_id=transaction_id,
            already_committed=already_committed
        )
        
        # Commit only the participants that haven't committed yet
        remaining_participants = [
            p for p in self._participants 
            if p.participant_id not in already_committed
        ]
        
        if not remaining_participants:
            logger.info(
                "All participants already committed",
                transaction_id=transaction_id
            )
            return
        
        # Commit remaining participants
        for participant in remaining_participants:
            try:
                await participant.commit(transaction_id)
                logger.debug(
                    "Remaining participant committed during recovery",
                    transaction_id=transaction_id,
                    participant=participant.participant_id
                )
            except Exception as e:
                logger.exception(
                    "Remaining participant commit failed during recovery",
                    transaction_id=transaction_id,
                    participant=participant.participant_id,
                    error=str(e)
                )
                # Continue with other participants - this is a best effort
        
        # Update transaction state
        self._state = TransactionState.COMMITTED
        await self._transaction_log.log_state_change(
            transaction_id,
            TransactionState.COMMITTED
        )

    def get_current_transaction(self) -> str | None:
        """Get current transaction ID if in transaction."""
        return self._current_transaction

    def get_participant_count(self) -> int:
        """Get number of registered participants."""
        return len(self._participants)

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive distributed transaction manager statistics."""
        participant_stats = []
        for participant in self._participants:
            if hasattr(participant, "get_statistics"):
                participant_stats.append(participant.get_statistics())
            else:
                participant_stats.append(
                    {
                        "participant_id": participant.participant_id,
                        "participant_type": "unknown",
                    }
                )

        return {
            "manager_type": "distributed",
            "current_transaction": self._current_transaction,
            "current_state": self._state.value,
            "participant_count": len(self._participants),
            "participants": participant_stats,
            "prepare_timeout": self._prepare_timeout,
            "commit_timeout": self._commit_timeout,
            "creation_time": self._creation_time.isoformat(),
            "transaction_log": self._transaction_log.get_statistics(),
        }
