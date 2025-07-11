"""
Tests for GraphQL DataLoader implementation.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from typing import List, Optional

from app.presentation.graphql.dataloaders import (
    BaseDataLoader,
    RepositoryDataLoader,
    OneToManyDataLoader,
    ManyToManyDataLoader,
    CachedDataLoader,
    DataLoaderRegistry,
)


class User:
    """Mock user class for testing."""
    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name


class Post:
    """Mock post class for testing."""
    def __init__(self, id: str, user_id: str, title: str):
        self.id = id
        self.user_id = user_id
        self.title = title


class Role:
    """Mock role class for testing."""
    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name


class UserRoleMapping:
    """Mock user-role mapping for testing."""
    def __init__(self, user_id: str, role_id: str):
        self.user_id = user_id
        self.role_id = role_id


class TestRepositoryDataLoader:
    """Test RepositoryDataLoader class."""
    
    @pytest.mark.asyncio
    async def test_repository_dataloader_basic(self):
        """Test basic repository dataloader functionality."""
        # Mock repository
        mock_repo = Mock()
        users = [
            User("1", "Alice"),
            User("2", "Bob"),
            User("3", "Charlie")
        ]
        mock_repo.get_by_ids = AsyncMock(return_value=users)
        
        # Create loader
        loader = RepositoryDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, ids: repo.get_by_ids(ids)
        )
        
        # Load single item
        user = await loader.load("2")
        assert user.id == "2"
        assert user.name == "Bob"
        
        # Load multiple items
        results = await loader.load_many(["1", "3", "4"])
        assert len(results) == 3
        assert results[0].id == "1"
        assert results[1].id == "3"
        assert results[2] is None  # Non-existent
    
    @pytest.mark.asyncio
    async def test_repository_dataloader_custom_key(self):
        """Test repository dataloader with custom key function."""
        mock_repo = Mock()
        users = [User("uuid-1", "Alice"), User("uuid-2", "Bob")]
        mock_repo.get_by_usernames = AsyncMock(return_value=users)
        
        loader = RepositoryDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, names: repo.get_by_usernames(names),
            key_fn=lambda user: user.name
        )
        
        # Load by username
        user = await loader.load("Alice")
        assert user.id == "uuid-1"
        assert user.name == "Alice"


class TestOneToManyDataLoader:
    """Test OneToManyDataLoader class."""
    
    @pytest.mark.asyncio
    async def test_one_to_many_dataloader(self):
        """Test one-to-many relationship loading."""
        # Mock repository
        mock_repo = Mock()
        posts = [
            Post("1", "user1", "Post 1"),
            Post("2", "user1", "Post 2"),
            Post("3", "user2", "Post 3"),
            Post("4", "user3", "Post 4"),
        ]
        mock_repo.get_by_user_ids = AsyncMock(return_value=posts)
        
        # Create loader
        loader = OneToManyDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, user_ids: repo.get_by_user_ids(user_ids),
            group_by_fn=lambda post: post.user_id
        )
        
        # Load posts for users
        results = await loader.load_many(["user1", "user2", "user4"])
        
        assert len(results) == 3
        assert len(results[0]) == 2  # user1 has 2 posts
        assert len(results[1]) == 1  # user2 has 1 post
        assert len(results[2]) == 0  # user4 has no posts
        
        assert results[0][0].title == "Post 1"
        assert results[0][1].title == "Post 2"
        assert results[1][0].title == "Post 3"


class TestManyToManyDataLoader:
    """Test ManyToManyDataLoader class."""
    
    @pytest.mark.asyncio
    async def test_many_to_many_dataloader(self):
        """Test many-to-many relationship loading."""
        # Mock repository
        mock_repo = Mock()
        roles = [
            Role("role1", "Admin"),
            Role("role2", "User"),
            Role("role3", "Guest")
        ]
        mappings = [
            UserRoleMapping("user1", "role1"),
            UserRoleMapping("user1", "role2"),
            UserRoleMapping("user2", "role2"),
            UserRoleMapping("user3", "role3"),
        ]
        mock_repo.get_roles_for_users = AsyncMock(return_value=(roles, mappings))
        
        # Create loader
        loader = ManyToManyDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, user_ids: repo.get_roles_for_users(user_ids),
            key_fn=lambda role: role.id,
            relationship_fn=lambda mapping: (mapping.user_id, mapping.role_id)
        )
        
        # Load roles for users
        results = await loader.load_many(["user1", "user2", "user3", "user4"])
        
        assert len(results) == 4
        assert len(results[0]) == 2  # user1 has 2 roles
        assert len(results[1]) == 1  # user2 has 1 role
        assert len(results[2]) == 1  # user3 has 1 role
        assert len(results[3]) == 0  # user4 has no roles
        
        assert results[0][0].name == "Admin"
        assert results[0][1].name == "User"
        assert results[1][0].name == "User"
        assert results[2][0].name == "Guest"


class TestCachedDataLoader:
    """Test CachedDataLoader class."""
    
    @pytest.mark.asyncio
    async def test_cached_dataloader_basic(self):
        """Test basic caching functionality."""
        # Create base loader with spy
        mock_repo = Mock()
        users = [User("1", "Alice"), User("2", "Bob")]
        mock_repo.get_by_ids = AsyncMock(return_value=users)
        
        base_loader = RepositoryDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, ids: repo.get_by_ids(ids)
        )
        
        # Wrap with cache
        cached_loader = CachedDataLoader(
            base_loader=base_loader,
            cache_ttl=60,
            max_cache_size=100
        )
        
        # First load - should hit repository
        user1 = await cached_loader.load("1")
        assert user1.name == "Alice"
        assert mock_repo.get_by_ids.call_count == 1
        
        # Second load - should use cache
        user1_cached = await cached_loader.load("1")
        assert user1_cached.name == "Alice"
        assert mock_repo.get_by_ids.call_count == 1  # Still 1
        
        # Load different item
        user2 = await cached_loader.load("2")
        assert user2.name == "Bob"
        assert mock_repo.get_by_ids.call_count == 2
    
    @pytest.mark.asyncio
    async def test_cached_dataloader_invalidation(self):
        """Test cache invalidation."""
        mock_repo = Mock()
        users = [User("1", "Alice")]
        mock_repo.get_by_ids = AsyncMock(return_value=users)
        
        base_loader = RepositoryDataLoader(
            repository=mock_repo,
            batch_load_fn=lambda repo, ids: repo.get_by_ids(ids)
        )
        
        cached_loader = CachedDataLoader(base_loader=base_loader)
        
        # Load and cache
        await cached_loader.load("1")
        assert mock_repo.get_by_ids.call_count == 1
        
        # Invalidate
        cached_loader.invalidate("1")
        
        # Load again - should hit repository
        await cached_loader.load("1")
        assert mock_repo.get_by_ids.call_count == 2
        
        # Test invalidate all
        cached_loader.invalidate_all()
        await cached_loader.load("1")
        assert mock_repo.get_by_ids.call_count == 3


class TestDataLoaderRegistry:
    """Test DataLoaderRegistry class."""
    
    def test_registry_basic(self):
        """Test basic registry functionality."""
        registry = DataLoaderRegistry()
        
        # Create mock loaders
        user_loader = Mock()
        role_loader = Mock()
        
        # Register loaders
        registry.register("user", user_loader)
        registry.register("role", role_loader)
        
        # Get by name
        assert registry.get("user") is user_loader
        assert registry.get("role") is role_loader
        assert registry.get("nonexistent") is None
        
        # Access via attribute
        assert registry.user is user_loader
        assert registry.role is role_loader
    
    def test_registry_metrics(self):
        """Test registry metrics collection."""
        registry = DataLoaderRegistry()
        
        # Create loader with metrics
        loader1 = Mock()
        loader1.metrics = {"load_count": 10, "batch_count": 2}
        
        loader2 = Mock()
        loader2.metrics = {"load_count": 5, "batch_count": 1}
        
        # Loader without metrics
        loader3 = Mock(spec=[])
        
        registry.register("users", loader1)
        registry.register("roles", loader2)
        registry.register("posts", loader3)
        
        metrics = registry.get_metrics()
        
        assert "users" in metrics
        assert metrics["users"]["load_count"] == 10
        assert "roles" in metrics
        assert metrics["roles"]["load_count"] == 5
        assert "posts" not in metrics  # No metrics attribute
    
    def test_registry_clear_all(self):
        """Test clearing all loader caches."""
        registry = DataLoaderRegistry()
        
        # Create loaders with clear method
        loader1 = Mock()
        loader2 = Mock()
        loader3 = Mock(spec=[])  # No clear method
        
        registry.register("users", loader1)
        registry.register("roles", loader2)
        registry.register("posts", loader3)
        
        registry.clear_all()
        
        loader1.clear.assert_called_once()
        loader2.clear.assert_called_once()
        # loader3 has no clear method, so no error


class TestBaseDataLoader:
    """Test BaseDataLoader abstract class."""
    
    @pytest.mark.asyncio
    async def test_base_dataloader_error_handling(self):
        """Test error handling in base dataloader."""
        class ErrorDataLoader(BaseDataLoader[str, User]):
            async def batch_load(self, keys: List[str]) -> List[Optional[User]]:
                raise Exception("Database error")
        
        loader = ErrorDataLoader()
        
        # Should return None for all keys on error
        results = await loader.load_many(["1", "2", "3"])
        assert len(results) == 3
        assert all(r is None for r in results)
    
    def test_base_dataloader_metrics(self):
        """Test metrics tracking in base dataloader."""
        class TestLoader(BaseDataLoader[str, str]):
            async def batch_load(self, keys: List[str]) -> List[Optional[str]]:
                return [f"value_{k}" for k in keys]
        
        loader = TestLoader()
        
        # Initial metrics
        metrics = loader.metrics
        assert metrics["load_count"] == 0
        assert metrics["batch_count"] == 0
        assert metrics["avg_batch_size"] == 0