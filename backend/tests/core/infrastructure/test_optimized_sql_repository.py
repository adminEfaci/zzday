"""
Tests for Optimized SQL Repository Implementation.

This module provides comprehensive tests for the OptimizedSQLRepository
including performance optimizations, caching, batch operations, and more.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, String, Integer, DateTime, Boolean, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.errors import ConflictError, InfrastructureError
from app.core.infrastructure.cache_coordinator import CacheCoordinator
from app.core.infrastructure.optimized_sql_repository import (
    OptimizedSQLRepository,
    QueryCache,
    EagerLoadStrategy,
    BatchOperationManager,
)

Base = declarative_base()


# Test Models
class UserModel(Base):
    """Test SQL model."""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_domain(self) -> "User":
        """Convert to domain entity."""
        return User(
            id=UUID(self.id),
            username=self.username,
            email=self.email,
            is_active=self.is_active,
            version=self.version,
            created_at=self.created_at,
            updated_at=self.updated_at
        )
    
    @classmethod
    def from_domain(cls, entity: "User") -> "UserModel":
        """Create from domain entity."""
        return cls(
            id=str(entity.id),
            username=entity.username,
            email=entity.email,
            is_active=entity.is_active,
            version=entity.version,
            created_at=entity.created_at,
            updated_at=entity.updated_at
        )


class User(Entity):
    """Test domain entity."""
    
    def __init__(
        self,
        id: UUID,
        username: str,
        email: str,
        is_active: bool = True,
        version: int = 1,
        created_at: Optional[datetime] = None,
        updated_at: Optional[datetime] = None
    ):
        super().__init__(id)
        self.username = username
        self.email = email
        self.is_active = is_active
        self.version = version
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = updated_at or datetime.utcnow()


class ActiveUserSpecification(Specification[User]):
    """Specification for active users."""
    
    def is_satisfied_by(self, entity: User) -> bool:
        """Check if user is active."""
        return entity.is_active
    
    def to_sql_expression(self, model_type):
        """Convert to SQL expression."""
        return model_type.is_active == True


class TestQueryCache:
    """Test cases for QueryCache."""
    
    @pytest.mark.asyncio
    async def test_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = QueryCache(max_size=5, ttl_seconds=60)
        
        # Test set and get
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Test cache miss
        assert await cache.get("nonexistent") is None
        
        # Test stats
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["size"] == 1
    
    @pytest.mark.asyncio
    async def test_cache_lru_eviction(self):
        """Test LRU eviction policy."""
        cache = QueryCache(max_size=3, ttl_seconds=60)
        
        # Fill cache
        for i in range(4):
            await cache.set(f"key{i}", f"value{i}")
        
        # First key should be evicted
        assert await cache.get("key0") is None
        assert await cache.get("key3") == "value3"
    
    @pytest.mark.asyncio
    async def test_cache_ttl_expiration(self):
        """Test TTL expiration."""
        cache = QueryCache(max_size=5, ttl_seconds=0.1)
        
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Wait for expiration
        await asyncio.sleep(0.2)
        assert await cache.get("key1") is None
    
    @pytest.mark.asyncio
    async def test_cache_invalidation(self):
        """Test cache invalidation."""
        cache = QueryCache(max_size=5, ttl_seconds=60)
        
        # Set multiple keys
        await cache.set("user:1", "user1")
        await cache.set("user:2", "user2")
        await cache.set("order:1", "order1")
        
        # Invalidate by pattern
        await cache.invalidate("user:")
        
        assert await cache.get("user:1") is None
        assert await cache.get("user:2") is None
        assert await cache.get("order:1") == "order1"
        
        # Invalidate all
        await cache.invalidate()
        assert await cache.get("order:1") is None


class TestEagerLoadStrategy:
    """Test cases for EagerLoadStrategy."""
    
    def test_register_strategies(self):
        """Test registering eager load strategies."""
        strategy = EagerLoadStrategy()
        
        # Register strategies
        strategy.register(User, ["orders", "profile"], "selectin")
        strategy.register(User, ["permissions"], "joined")
        
        # Get options
        options = strategy.get_options(User)
        assert len(options) == 1  # Only latest registration
        
        # Unknown entity type
        assert strategy.get_options(Entity) == []
    
    def test_invalid_strategy(self):
        """Test invalid strategy raises error."""
        strategy = EagerLoadStrategy()
        
        with pytest.raises(ValueError, match="Unknown loading strategy"):
            strategy.register(User, ["orders"], "invalid")


class TestBatchOperationManager:
    """Test cases for BatchOperationManager."""
    
    @pytest.mark.asyncio
    async def test_batch_insert(self):
        """Test batch insert operations."""
        manager = BatchOperationManager(batch_size=2)
        session = AsyncMock(spec=AsyncSession)
        
        # Mock bulk_insert_mappings
        session.bulk_insert_mappings = AsyncMock()
        
        models = [
            UserModel(id=str(uuid4()), username=f"user{i}", email=f"user{i}@test.com")
            for i in range(5)
        ]
        
        result = await manager.batch_insert(session, models)
        
        # Should be called 3 times (5 models / batch_size 2)
        assert session.bulk_insert_mappings.call_count == 3
        assert len(result) == 5
    
    @pytest.mark.asyncio
    async def test_batch_update(self):
        """Test batch update operations."""
        manager = BatchOperationManager(batch_size=2)
        session = AsyncMock(spec=AsyncSession)
        
        # Mock bulk_update_mappings
        session.bulk_update_mappings = AsyncMock()
        
        updates = [
            {"id": str(uuid4()), "username": f"updated{i}"}
            for i in range(5)
        ]
        
        result = await manager.batch_update(session, UserModel, updates)
        
        # Should be called 3 times
        assert session.bulk_update_mappings.call_count == 3
        assert result == 5


class TestOptimizedSQLRepository:
    """Test cases for OptimizedSQLRepository."""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock session."""
        session = AsyncMock(spec=AsyncSession)
        session.execute = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.add_all = MagicMock()
        session.delete = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_cache_coordinator(self):
        """Create mock cache coordinator."""
        cache = AsyncMock(spec=CacheCoordinator)
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock()
        cache.delete = AsyncMock()
        return cache
    
    @pytest.fixture
    def repository(self, mock_session, mock_cache_coordinator):
        """Create repository instance."""
        def session_factory():
            return mock_session
        
        repo = OptimizedSQLRepository(
            entity_type=User,
            model_type=UserModel,
            session_factory=session_factory,
            cache_coordinator=mock_cache_coordinator,
            query_cache_size=10,
            enable_query_logging=True
        )
        return repo
    
    @pytest.mark.asyncio
    async def test_find_by_id_with_cache_hit(self, repository, mock_cache_coordinator):
        """Test find by ID with cache hit."""
        user_id = uuid4()
        cached_user = User(id=user_id, username="cached", email="cached@test.com")
        
        mock_cache_coordinator.get.return_value = cached_user
        
        result = await repository.find_by_id(user_id)
        
        assert result == cached_user
        mock_cache_coordinator.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_find_by_id_with_cache_miss(self, repository, mock_session, mock_cache_coordinator):
        """Test find by ID with cache miss."""
        user_id = uuid4()
        user_model = UserModel(
            id=str(user_id),
            username="test",
            email="test@test.com"
        )
        
        mock_session.execute.return_value = AsyncMock(
            scalar_one_or_none=MagicMock(return_value=user_model)
        )
        
        result = await repository.find_by_id(user_id)
        
        assert result.id == user_id
        assert result.username == "test"
        mock_cache_coordinator.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_find_all_with_pagination(self, repository, mock_session):
        """Test find all with pagination."""
        models = [
            UserModel(id=str(uuid4()), username=f"user{i}", email=f"user{i}@test.com")
            for i in range(5)
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = models
        mock_session.execute.return_value = mock_result
        
        result = await repository.find_all(limit=10, offset=5)
        
        assert len(result) == 5
        assert all(isinstance(u, User) for u in result)
    
    @pytest.mark.asyncio
    async def test_save_new_entity(self, repository, mock_session):
        """Test saving new entity."""
        user = User(
            id=uuid4(),
            username="newuser",
            email="newuser@test.com"
        )
        
        result = await repository.save(user)
        
        assert result.username == "newuser"
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_existing_entity_with_optimistic_lock(self, repository, mock_session):
        """Test saving existing entity with optimistic locking."""
        user_id = uuid4()
        user = User(
            id=user_id,
            username="existing",
            email="existing@test.com",
            version=2
        )
        
        existing_model = UserModel(
            id=str(user_id),
            username="old",
            email="old@test.com",
            version=1
        )
        
        mock_session.get.return_value = existing_model
        
        with pytest.raises(ConflictError, match="Entity has been modified"):
            await repository.save(user)
    
    @pytest.mark.asyncio
    async def test_save_batch(self, repository, mock_session):
        """Test batch save operation."""
        users = [
            User(id=uuid4(), username=f"user{i}", email=f"user{i}@test.com")
            for i in range(3)
        ]
        
        # Mock exists check
        mock_session.get.return_value = None
        
        result = await repository.save_batch(users)
        
        assert len(result) == 3
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete(self, repository, mock_session):
        """Test delete operation."""
        user_id = uuid4()
        user_model = UserModel(id=str(user_id), username="delete", email="delete@test.com")
        
        mock_session.get.return_value = user_model
        
        result = await repository.delete(user_id)
        
        assert result is True
        mock_session.delete.assert_called_once_with(user_model)
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_batch(self, repository, mock_session):
        """Test batch delete operation."""
        user_ids = [uuid4() for _ in range(3)]
        
        mock_result = AsyncMock()
        mock_result.rowcount = 3
        mock_session.execute.return_value = mock_result
        
        result = await repository.delete_batch(user_ids)
        
        assert result == 3
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_exists(self, repository, mock_session):
        """Test exists check."""
        user_id = uuid4()
        
        mock_result = AsyncMock()
        mock_result.scalar.return_value = True
        mock_session.execute.return_value = mock_result
        
        result = await repository.exists(user_id)
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_count(self, repository, mock_session):
        """Test count operation."""
        mock_result = AsyncMock()
        mock_result.scalar.return_value = 42
        mock_session.execute.return_value = mock_result
        
        result = await repository.count()
        
        assert result == 42
    
    @pytest.mark.asyncio
    async def test_find_by_specification(self, repository, mock_session):
        """Test find by specification."""
        models = [
            UserModel(id=str(uuid4()), username="active", email="active@test.com", is_active=True),
            UserModel(id=str(uuid4()), username="inactive", email="inactive@test.com", is_active=False)
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [models[0]]  # Only active
        mock_session.execute.return_value = mock_result
        
        spec = ActiveUserSpecification()
        result = await repository.find_by_specification(spec)
        
        assert len(result) == 1
        assert result[0].is_active is True
    
    @pytest.mark.asyncio
    async def test_execute_raw_query(self, repository, mock_session):
        """Test raw query execution."""
        mock_result = AsyncMock()
        mock_result.__iter__.return_value = [
            {"id": "1", "username": "user1"},
            {"id": "2", "username": "user2"}
        ]
        mock_session.execute.return_value = mock_result
        
        result = await repository.execute_raw_query(
            "SELECT id, username FROM users WHERE is_active = :active",
            {"active": True}
        )
        
        assert len(result) == 2
        assert result[0]["username"] == "user1"
    
    @pytest.mark.asyncio
    async def test_performance_report(self, repository):
        """Test performance report generation."""
        # Perform some operations to generate stats
        await repository.count()
        
        report = await repository.get_performance_report()
        
        assert "query_cache_stats" in report
        assert "connection_pool_stats" in report
        assert "query_count" in report
        assert "optimizations" in report
        assert report["optimizations"]["query_caching_enabled"] is True
    
    @pytest.mark.asyncio
    async def test_eager_loading_configuration(self, repository):
        """Test eager loading configuration."""
        repository.configure_eager_loading(["orders", "profile"], "selectin")
        
        # Verify strategy was registered
        options = repository._eager_load_strategy.get_options(User)
        assert len(options) == 2
    
    @pytest.mark.asyncio
    async def test_query_performance_tracking(self, repository, mock_session):
        """Test query performance tracking."""
        # Mock slow query
        async def slow_execute(*args):
            await asyncio.sleep(1.1)
            result = AsyncMock()
            result.scalar.return_value = 0
            return result
        
        mock_session.execute = slow_execute
        
        await repository.count()
        
        # Check slow queries were tracked
        assert len(repository._slow_queries) == 1
        assert repository._slow_queries[0]["execution_time"] > 1.0
    
    @pytest.mark.asyncio
    async def test_connection_pool_stats(self, repository, mock_session):
        """Test connection pool statistics."""
        # Perform operations
        await repository.count()
        await repository.exists(uuid4())
        
        stats = repository._connection_pool.get_pool_stats()
        
        assert stats["total_acquisitions"] == 2
        assert "average_wait_time" in stats
        assert "peak_connections" in stats


@pytest.mark.integration
class TestOptimizedSQLRepositoryIntegration:
    """Integration tests with real database."""
    
    @pytest.fixture
    async def engine(self):
        """Create test database engine."""
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False
        )
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        yield engine
        
        await engine.dispose()
    
    @pytest.fixture
    async def session_factory(self, engine):
        """Create session factory."""
        from sqlalchemy.ext.asyncio import async_sessionmaker
        
        return async_sessionmaker(engine, class_=AsyncSession)
    
    @pytest.fixture
    async def repository(self, session_factory):
        """Create repository with real database."""
        repo = OptimizedSQLRepository(
            entity_type=User,
            model_type=UserModel,
            session_factory=session_factory,
            query_cache_size=10,
            enable_query_logging=True
        )
        return repo
    
    @pytest.mark.asyncio
    async def test_full_crud_cycle(self, repository):
        """Test complete CRUD cycle."""
        # Create
        user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com"
        )
        saved_user = await repository.save(user)
        assert saved_user.id == user.id
        
        # Read
        found_user = await repository.find_by_id(user.id)
        assert found_user.username == "testuser"
        
        # Update
        found_user.email = "updated@example.com"
        updated_user = await repository.save(found_user)
        assert updated_user.email == "updated@example.com"
        
        # Delete
        deleted = await repository.delete(user.id)
        assert deleted is True
        
        # Verify deletion
        not_found = await repository.find_by_id(user.id)
        assert not_found is None
    
    @pytest.mark.asyncio
    async def test_batch_operations_performance(self, repository):
        """Test batch operations performance."""
        # Create 100 users
        users = [
            User(
                id=uuid4(),
                username=f"user{i}",
                email=f"user{i}@example.com"
            )
            for i in range(100)
        ]
        
        # Batch save
        import time
        start = time.time()
        saved_users = await repository.save_batch(users)
        batch_time = time.time() - start
        
        assert len(saved_users) == 100
        assert batch_time < 2.0  # Should be fast
        
        # Verify count
        count = await repository.count()
        assert count == 100
        
        # Batch delete
        user_ids = [u.id for u in users]
        deleted_count = await repository.delete_batch(user_ids)
        assert deleted_count == 100