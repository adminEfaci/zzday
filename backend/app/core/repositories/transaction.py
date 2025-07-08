"""Transaction management for repositories.

Provides transaction management, unit of work pattern, and transactional
context managers for repository operations.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, TypeVar
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.core.errors import TransactionError
from app.core.logging import get_logger
from app.core.repositories.base import IRepository, IRepositoryFactory, IUnitOfWork

logger = get_logger(__name__)

TEntity = TypeVar("TEntity", bound=Entity)


class ITransactionManager(ABC):
    """Interface for transaction management."""

    @abstractmethod
    async def begin_transaction(self) -> "TransactionScope":
        """Begin a new transaction."""

    @abstractmethod
    async def commit_transaction(self, transaction_id: UUID) -> None:
        """Commit a transaction."""

    @abstractmethod
    async def rollback_transaction(self, transaction_id: UUID) -> None:
        """Rollback a transaction."""

    @abstractmethod
    async def is_transaction_active(self, transaction_id: UUID) -> bool:
        """Check if transaction is active."""


class TransactionScope:
    """Represents a transaction scope."""

    def __init__(
        self, transaction_id: UUID, session: Any, manager: "TransactionManager"
    ):
        """Initialize transaction scope."""
        self.transaction_id = transaction_id
        self.session = session
        self.manager = manager
        self.is_committed = False
        self.is_rolled_back = False
        self.created_at = datetime.utcnow()
        self._repositories: dict[type[TEntity], IRepository] = {}

    @property
    def is_active(self) -> bool:
        """Check if transaction is active."""
        return not (self.is_committed or self.is_rolled_back)

    async def commit(self) -> None:
        """Commit the transaction."""
        if not self.is_active:
            raise TransactionError(f"Transaction {self.transaction_id} is not active")

        await self.manager.commit_transaction(self.transaction_id)
        self.is_committed = True

    async def rollback(self) -> None:
        """Rollback the transaction."""
        if not self.is_active:
            return  # Already rolled back or committed

        await self.manager.rollback_transaction(self.transaction_id)
        self.is_rolled_back = True

    def get_repository(self, entity_type: type[TEntity]) -> IRepository[TEntity, Any]:
        """Get repository for entity type within this transaction."""
        if entity_type not in self._repositories:
            # Create repository with this transaction's session
            repository = self.manager.factory.create_repository(entity_type)
            # In real implementation, would inject the transaction session
            self._repositories[entity_type] = repository

        return self._repositories[entity_type]


class TransactionManager(ITransactionManager):
    """Transaction manager implementation."""

    def __init__(self, session_factory: Callable, factory: IRepositoryFactory):
        """Initialize transaction manager."""
        self.session_factory = session_factory
        self.factory = factory
        self._active_transactions: dict[UUID, TransactionScope] = {}
        self._transaction_stats = {
            "total_transactions": 0,
            "committed_transactions": 0,
            "rolled_back_transactions": 0,
            "failed_transactions": 0,
        }

    async def begin_transaction(self) -> TransactionScope:
        """Begin a new transaction."""
        transaction_id = uuid4()

        try:
            # Create database session with transaction
            session = self.session_factory()

            # Begin transaction at database level
            if hasattr(session, "begin"):
                await session.begin()

            # Create transaction scope
            scope = TransactionScope(transaction_id, session, self)
            self._active_transactions[transaction_id] = scope
            self._transaction_stats["total_transactions"] += 1

            logger.debug("Transaction started", transaction_id=str(transaction_id))

            return scope

        except Exception as e:
            self._transaction_stats["failed_transactions"] += 1
            logger.exception("Failed to begin transaction", error=str(e))
            raise TransactionError(f"Failed to begin transaction: {e!s}")

    async def commit_transaction(self, transaction_id: UUID) -> None:
        """Commit a transaction."""
        if transaction_id not in self._active_transactions:
            raise TransactionError(f"Transaction {transaction_id} not found")

        scope = self._active_transactions[transaction_id]

        try:
            # Commit at database level
            if hasattr(scope.session, "commit"):
                await scope.session.commit()

            self._transaction_stats["committed_transactions"] += 1

            logger.debug("Transaction committed", transaction_id=str(transaction_id))

        except Exception as e:
            # Attempt rollback on commit failure
            try:
                await self.rollback_transaction(transaction_id)
            except:
                pass  # Rollback failure is logged separately

            self._transaction_stats["failed_transactions"] += 1
            logger.exception(
                "Transaction commit failed",
                transaction_id=str(transaction_id),
                error=str(e),
            )
            raise TransactionError(f"Transaction commit failed: {e!s}")

        finally:
            # Clean up
            await self._cleanup_transaction(transaction_id)

    async def rollback_transaction(self, transaction_id: UUID) -> None:
        """Rollback a transaction."""
        if transaction_id not in self._active_transactions:
            return  # Already cleaned up

        scope = self._active_transactions[transaction_id]

        try:
            # Rollback at database level
            if hasattr(scope.session, "rollback"):
                await scope.session.rollback()

            self._transaction_stats["rolled_back_transactions"] += 1

            logger.debug("Transaction rolled back", transaction_id=str(transaction_id))

        except Exception as e:
            logger.exception(
                "Transaction rollback failed",
                transaction_id=str(transaction_id),
                error=str(e),
            )
            # Don't raise on rollback failure - we're already in error state

        finally:
            # Clean up
            await self._cleanup_transaction(transaction_id)

    async def is_transaction_active(self, transaction_id: UUID) -> bool:
        """Check if transaction is active."""
        if transaction_id not in self._active_transactions:
            return False

        scope = self._active_transactions[transaction_id]
        return scope.is_active

    async def _cleanup_transaction(self, transaction_id: UUID) -> None:
        """Clean up transaction resources."""
        if transaction_id not in self._active_transactions:
            return

        scope = self._active_transactions[transaction_id]

        try:
            # Close session
            if hasattr(scope.session, "close"):
                await scope.session.close()
        except Exception as e:
            logger.warning(
                "Failed to close transaction session",
                transaction_id=str(transaction_id),
                error=str(e),
            )

        # Remove from active transactions
        del self._active_transactions[transaction_id]

    def get_statistics(self) -> dict[str, Any]:
        """Get transaction statistics."""
        return {
            **self._transaction_stats,
            "active_transactions": len(self._active_transactions),
            "active_transaction_ids": [str(tid) for tid in self._active_transactions],
        }

    async def cleanup_stale_transactions(self, max_age_minutes: int = 60) -> int:
        """Clean up stale transactions."""
        current_time = datetime.utcnow()
        stale_transactions = []

        for transaction_id, scope in self._active_transactions.items():
            age_minutes = (current_time - scope.created_at).total_seconds() / 60
            if age_minutes > max_age_minutes:
                stale_transactions.append(transaction_id)

        # Clean up stale transactions
        for transaction_id in stale_transactions:
            logger.warning(
                "Cleaning up stale transaction", transaction_id=str(transaction_id)
            )
            await self.rollback_transaction(transaction_id)

        return len(stale_transactions)


class UnitOfWork(IUnitOfWork):
    """Unit of Work implementation."""

    def __init__(self, factory: IRepositoryFactory):
        """Initialize unit of work."""
        self.factory = factory
        self._transaction_scope: TransactionScope | None = None
        self._repositories: dict[type[TEntity], IRepository] = {}

    async def __aenter__(self) -> "UnitOfWork":
        """Enter context - begin transaction."""
        if hasattr(self.factory, "_transaction_manager"):
            manager = self.factory._transaction_manager
            self._transaction_scope = await manager.begin_transaction()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context - commit or rollback."""
        if self._transaction_scope:
            if exc_type is None:
                await self.commit()
            else:
                await self.rollback()

    async def commit(self) -> None:
        """Commit changes."""
        if self._transaction_scope:
            await self._transaction_scope.commit()

    async def rollback(self) -> None:
        """Rollback changes."""
        if self._transaction_scope:
            await self._transaction_scope.rollback()

    def get_repository(self, entity_type: type[TEntity]) -> IRepository[TEntity, Any]:
        """Get repository for entity type."""
        if entity_type not in self._repositories:
            if self._transaction_scope:
                repository = self._transaction_scope.get_repository(entity_type)
            else:
                repository = self.factory.create_repository(entity_type)

            self._repositories[entity_type] = repository

        return self._repositories[entity_type]


@asynccontextmanager
async def transaction_scope(manager: ITransactionManager):
    """Context manager for transactional operations."""
    scope = await manager.begin_transaction()
    try:
        yield scope
        await scope.commit()
    except Exception:
        await scope.rollback()
        raise


@asynccontextmanager
async def unit_of_work(factory: IRepositoryFactory):
    """Context manager for unit of work pattern."""
    uow = UnitOfWork(factory)
    async with uow:
        yield uow


__all__ = [
    "ITransactionManager",
    "TransactionError",
    "TransactionManager",
    "TransactionScope",
    "UnitOfWork",
    "transaction_scope",
    "unit_of_work",
]
