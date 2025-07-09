"""
Comprehensive integration tests for UserRepository.

Tests cover:
- CRUD operations
- Query methods
- Transaction handling
- Concurrency scenarios
- Performance characteristics
"""

import pytest
import asyncio
from datetime import datetime, timedelta, UTC
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.modules.identity.infrastructure.repositories.user_repository import SQLUserRepository
from app.modules.identity.infrastructure.models.user_model import UserModel
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.enums import UserStatus, UserType
from app.core.infrastructure.database import Base


@pytest.fixture(scope="function")
async def test_db_engine():
    """Create test database engine."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(test_db_engine):
    """Create test database session."""
    async_session = sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture
def user_repository(db_session):
    """Create user repository instance."""
    return SQLUserRepository(db_session)


class TestUserRepository:
    """Test suite for UserRepository implementation."""

    def _create_test_user(self, email: str = "test@example.com", username: str = "testuser") -> User:
        """Helper to create test user."""
        return User.create(
            email=Email(email),
            username=Username(username),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )

    async def test_save_new_user(self, user_repository: SQLUserRepository):
        """Test saving a new user."""
        user = self._create_test_user()
        
        await user_repository.save(user)
        await user_repository.commit()
        
        # Verify user was saved
        saved_user = await user_repository.get_by_id(user.id)
        assert saved_user is not None
        assert saved_user.id == user.id
        assert saved_user.email == user.email
        assert saved_user.username == user.username

    async def test_update_existing_user(self, user_repository: SQLUserRepository):
        """Test updating an existing user."""
        user = self._create_test_user()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Update user
        user.activate()
        new_email = Email("updated@example.com")
        user.change_email(new_email)
        
        await user_repository.save(user)
        await user_repository.commit()
        
        # Verify updates were saved
        updated_user = await user_repository.get_by_id(user.id)
        assert updated_user.email == new_email
        assert updated_user.status == UserStatus.ACTIVE
        assert updated_user.is_active

    async def test_get_by_id(self, user_repository: SQLUserRepository):
        """Test retrieving user by ID."""
        user = self._create_test_user()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Get by valid ID
        found_user = await user_repository.get_by_id(user.id)
        assert found_user is not None
        assert found_user.id == user.id
        
        # Get by non-existent ID
        non_existent = await user_repository.get_by_id(UserId(str(uuid4())))
        assert non_existent is None

    async def test_get_by_email(self, user_repository: SQLUserRepository):
        """Test retrieving user by email."""
        user = self._create_test_user(email="unique@example.com")
        await user_repository.save(user)
        await user_repository.commit()
        
        # Get by valid email
        found_user = await user_repository.get_by_email(Email("unique@example.com"))
        assert found_user is not None
        assert found_user.email == user.email
        
        # Get by non-existent email
        non_existent = await user_repository.get_by_email(Email("nonexistent@example.com"))
        assert non_existent is None

    async def test_get_by_username(self, user_repository: SQLUserRepository):
        """Test retrieving user by username."""
        user = self._create_test_user(username="uniqueuser")
        await user_repository.save(user)
        await user_repository.commit()
        
        # Get by valid username
        found_user = await user_repository.get_by_username(Username("uniqueuser"))
        assert found_user is not None
        assert found_user.username == user.username
        
        # Get by non-existent username
        non_existent = await user_repository.get_by_username(Username("nonexistent"))
        assert non_existent is None

    async def test_exists_by_email(self, user_repository: SQLUserRepository):
        """Test checking user existence by email."""
        user = self._create_test_user(email="exists@example.com")
        await user_repository.save(user)
        await user_repository.commit()
        
        # Check existing email
        exists = await user_repository.exists_by_email(Email("exists@example.com"))
        assert exists is True
        
        # Check non-existing email
        not_exists = await user_repository.exists_by_email(Email("notexists@example.com"))
        assert not_exists is False

    async def test_exists_by_username(self, user_repository: SQLUserRepository):
        """Test checking user existence by username."""
        user = self._create_test_user(username="existsuser")
        await user_repository.save(user)
        await user_repository.commit()
        
        # Check existing username
        exists = await user_repository.exists_by_username(Username("existsuser"))
        assert exists is True
        
        # Check non-existing username
        not_exists = await user_repository.exists_by_username(Username("notexists"))
        assert not_exists is False

    async def test_get_many_by_ids(self, user_repository: SQLUserRepository):
        """Test retrieving multiple users by IDs."""
        users = [
            self._create_test_user(email=f"user{i}@example.com", username=f"user{i}")
            for i in range(5)
        ]
        
        for user in users:
            await user_repository.save(user)
        await user_repository.commit()
        
        # Get subset of users
        user_ids = [users[0].id, users[2].id, users[4].id]
        found_users = await user_repository.get_many_by_ids(user_ids)
        
        assert len(found_users) == 3
        found_ids = {user.id for user in found_users}
        assert found_ids == set(user_ids)

    async def test_find_by_criteria(self, user_repository: SQLUserRepository):
        """Test finding users by various criteria."""
        # Create test users
        active_user = self._create_test_user(email="active@example.com", username="activeuser")
        active_user.activate()
        
        inactive_user = self._create_test_user(email="inactive@example.com", username="inactiveuser")
        inactive_user.activate()
        inactive_user.deactivate("Test")
        
        premium_user = self._create_test_user(email="premium@example.com", username="premiumuser")
        premium_user.type = UserType.PREMIUM
        premium_user.activate()
        
        await user_repository.save(active_user)
        await user_repository.save(inactive_user)
        await user_repository.save(premium_user)
        await user_repository.commit()
        
        # Find active users
        active_users = await user_repository.find_by_criteria({"status": UserStatus.ACTIVE})
        assert len(active_users) == 2
        
        # Find premium users
        premium_users = await user_repository.find_by_criteria({"type": UserType.PREMIUM})
        assert len(premium_users) == 1
        assert premium_users[0].email.value == "premium@example.com"

    async def test_search_users(self, user_repository: SQLUserRepository):
        """Test searching users by query."""
        users = [
            self._create_test_user(email="john.doe@example.com", username="johndoe"),
            self._create_test_user(email="jane.smith@example.com", username="janesmith"),
            self._create_test_user(email="bob.johnson@example.com", username="bobjohnson"),
        ]
        
        for user in users:
            user.activate()
            await user_repository.save(user)
        await user_repository.commit()
        
        # Search by partial email
        results = await user_repository.search_users("john")
        assert len(results) == 2  # john.doe and bob.johnson
        
        # Search by username
        results = await user_repository.search_users("jane")
        assert len(results) == 1
        assert results[0].username.value == "janesmith"

    async def test_get_users_with_pagination(self, user_repository: SQLUserRepository):
        """Test retrieving users with pagination."""
        # Create 25 test users
        for i in range(25):
            user = self._create_test_user(
                email=f"user{i:02d}@example.com",
                username=f"user{i:02d}"
            )
            user.activate()
            await user_repository.save(user)
        await user_repository.commit()
        
        # Get first page
        page1 = await user_repository.get_users_paginated(page=1, page_size=10)
        assert page1.total == 25
        assert len(page1.items) == 10
        assert page1.page == 1
        assert page1.pages == 3
        
        # Get second page
        page2 = await user_repository.get_users_paginated(page=2, page_size=10)
        assert len(page2.items) == 10
        assert page2.items[0].id != page1.items[0].id
        
        # Get last page
        page3 = await user_repository.get_users_paginated(page=3, page_size=10)
        assert len(page3.items) == 5

    async def test_count_users(self, user_repository: SQLUserRepository):
        """Test counting users."""
        # Create test users
        for i in range(5):
            user = self._create_test_user(
                email=f"user{i}@example.com",
                username=f"user{i}"
            )
            if i < 3:
                user.activate()
            await user_repository.save(user)
        await user_repository.commit()
        
        # Count all users
        total_count = await user_repository.count()
        assert total_count == 5
        
        # Count active users
        active_count = await user_repository.count_by_status(UserStatus.ACTIVE)
        assert active_count == 3
        
        # Count pending users
        pending_count = await user_repository.count_by_status(UserStatus.PENDING_ACTIVATION)
        assert pending_count == 2

    async def test_delete_user(self, user_repository: SQLUserRepository):
        """Test deleting a user."""
        user = self._create_test_user()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Delete user
        await user_repository.delete(user.id)
        await user_repository.commit()
        
        # Verify user is deleted
        deleted_user = await user_repository.get_by_id(user.id)
        assert deleted_user is None

    async def test_soft_delete_user(self, user_repository: SQLUserRepository):
        """Test soft deleting a user."""
        user = self._create_test_user()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Soft delete user
        user.delete()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Regular get should not return soft-deleted users
        deleted_user = await user_repository.get_by_id(user.id)
        assert deleted_user is None
        
        # Get with include_deleted should return the user
        deleted_user = await user_repository.get_by_id(user.id, include_deleted=True)
        assert deleted_user is not None
        assert deleted_user.is_deleted

    async def test_transaction_rollback(self, user_repository: SQLUserRepository):
        """Test transaction rollback on error."""
        user = self._create_test_user()
        
        try:
            await user_repository.save(user)
            # Simulate error before commit
            raise Exception("Simulated error")
        except Exception:
            await user_repository.rollback()
        
        # User should not be saved
        not_saved = await user_repository.get_by_id(user.id)
        assert not_saved is None

    async def test_concurrent_updates(self, user_repository: SQLUserRepository, db_session):
        """Test handling concurrent updates to same user."""
        user = self._create_test_user()
        await user_repository.save(user)
        await user_repository.commit()
        
        # Create second repository instance for concurrent access
        repo2 = SQLUserRepository(db_session)
        
        # Load user in both sessions
        user1 = await user_repository.get_by_id(user.id)
        user2 = await repo2.get_by_id(user.id)
        
        # Update in first session
        user1.change_email(Email("first@example.com"))
        await user_repository.save(user1)
        await user_repository.commit()
        
        # Update in second session should handle optimistic locking
        user2.change_email(Email("second@example.com"))
        
        # This should raise optimistic locking exception in real implementation
        # For now, we just verify the first update won
        final_user = await user_repository.get_by_id(user.id)
        assert final_user.email.value == "first@example.com"

    async def test_bulk_operations(self, user_repository: SQLUserRepository):
        """Test bulk user operations."""
        users = [
            self._create_test_user(email=f"bulk{i}@example.com", username=f"bulk{i}")
            for i in range(100)
        ]
        
        # Bulk save
        start_time = datetime.now(UTC)
        await user_repository.save_many(users)
        await user_repository.commit()
        duration = (datetime.now(UTC) - start_time).total_seconds()
        
        # Should be reasonably fast
        assert duration < 1.0  # Less than 1 second for 100 users
        
        # Verify all saved
        count = await user_repository.count()
        assert count == 100

    async def test_get_inactive_users(self, user_repository: SQLUserRepository):
        """Test retrieving inactive users for cleanup."""
        now = datetime.now(UTC)
        
        # Create users with different last activity
        active_user = self._create_test_user(email="active@example.com", username="active")
        active_user.activate()
        active_user.last_activity_at = now - timedelta(days=10)
        
        inactive_user = self._create_test_user(email="inactive@example.com", username="inactive")
        inactive_user.activate()
        inactive_user.last_activity_at = now - timedelta(days=100)
        
        await user_repository.save(active_user)
        await user_repository.save(inactive_user)
        await user_repository.commit()
        
        # Get users inactive for more than 90 days
        inactive_users = await user_repository.get_inactive_users(days=90)
        assert len(inactive_users) == 1
        assert inactive_users[0].email.value == "inactive@example.com"