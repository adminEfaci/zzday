"""
Comprehensive unit tests for User Query handlers.

Tests cover:
- Get user by ID
- Search users
- List users with pagination
- Filter users by criteria
- User profile queries
"""

import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime, UTC
from uuid import uuid4

from app.modules.identity.application.queries.user_queries import (
    GetUserByIdQuery,
    GetUserByIdQueryHandler,
    SearchUsersQuery,
    SearchUsersQueryHandler,
    ListUsersQuery,
    ListUsersQueryHandler,
    GetUserProfileQuery,
    GetUserProfileQueryHandler,
    GetUsersByRoleQuery,
    GetUsersByRoleQueryHandler,
)
from app.modules.identity.application.dtos.response.user_dtos import (
    UserDTO,
    UserListDTO,
    UserProfileDTO,
    PaginatedUsersDTO,
)
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.value_objects.role_id import RoleId
from app.modules.identity.domain.enums import UserStatus, UserType
from app.modules.identity.application.errors import NotFoundError, ValidationError


class TestGetUserByIdQuery:
    """Test suite for GetUserByIdQuery and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_cache_service(self):
        """Create mock cache service."""
        service = AsyncMock()
        service.get.return_value = None
        return service

    @pytest.fixture
    def query_handler(self, mock_user_repository, mock_cache_service):
        """Create query handler with dependencies."""
        return GetUserByIdQueryHandler(
            user_repository=mock_user_repository,
            cache_service=mock_cache_service,
        )

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user = User.create(
            email=Email("user@example.com"),
            username=Username("testuser"),
            password_hash=PasswordHash.from_password("TestPass123!"),
        )
        user.activate()
        user.profile.first_name = "John"
        user.profile.last_name = "Doe"
        return user

    def test_create_get_user_by_id_query(self):
        """Test creating GetUserByIdQuery."""
        user_id = str(uuid4())
        
        query = GetUserByIdQuery(
            user_id=user_id,
            include_deleted=False,
        )
        
        assert query.user_id == user_id
        assert query.include_deleted is False

    async def test_get_user_by_id_success(self, query_handler, test_user):
        """Test successfully getting user by ID."""
        query_handler.user_repository.get_by_id.return_value = test_user
        
        query = GetUserByIdQuery(user_id=str(test_user.id))
        
        result = await query_handler.handle(query)
        
        assert isinstance(result, UserDTO)
        assert result.id == str(test_user.id)
        assert result.email == test_user.email.value
        assert result.username == test_user.username.value
        assert result.status == test_user.status.value
        assert result.first_name == "John"
        assert result.last_name == "Doe"
        
        # Verify repository was called
        query_handler.user_repository.get_by_id.assert_called_once_with(
            test_user.id,
            include_deleted=False,
        )

    async def test_get_user_by_id_not_found(self, query_handler):
        """Test getting non-existent user."""
        query_handler.user_repository.get_by_id.return_value = None
        
        query = GetUserByIdQuery(user_id=str(uuid4()))
        
        with pytest.raises(NotFoundError) as exc_info:
            await query_handler.handle(query)
        
        assert "User not found" in str(exc_info.value)

    async def test_get_user_by_id_with_cache_hit(self, query_handler, test_user):
        """Test getting user with cache hit."""
        cached_dto = UserDTO(
            id=str(test_user.id),
            email=test_user.email.value,
            username=test_user.username.value,
            status=test_user.status.value,
            type=test_user.type.value,
            created_at=test_user.created_at,
            updated_at=test_user.updated_at,
        )
        
        query_handler.cache_service.get.return_value = cached_dto
        
        query = GetUserByIdQuery(user_id=str(test_user.id))
        
        result = await query_handler.handle(query)
        
        assert result == cached_dto
        # Should not hit repository
        query_handler.user_repository.get_by_id.assert_not_called()

    async def test_get_user_by_id_with_cache_miss(self, query_handler, test_user):
        """Test getting user with cache miss."""
        query_handler.cache_service.get.return_value = None
        query_handler.user_repository.get_by_id.return_value = test_user
        
        query = GetUserByIdQuery(user_id=str(test_user.id))
        
        result = await query_handler.handle(query)
        
        assert result.id == str(test_user.id)
        
        # Verify cache was updated
        query_handler.cache_service.set.assert_called_once()

    async def test_get_deleted_user(self, query_handler, test_user):
        """Test getting deleted user with include_deleted flag."""
        test_user.delete()
        query_handler.user_repository.get_by_id.return_value = test_user
        
        query = GetUserByIdQuery(
            user_id=str(test_user.id),
            include_deleted=True,
        )
        
        result = await query_handler.handle(query)
        
        assert result.id == str(test_user.id)
        assert result.is_deleted is True


class TestSearchUsersQuery:
    """Test suite for SearchUsersQuery and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def query_handler(self, mock_user_repository):
        """Create query handler with dependencies."""
        return SearchUsersQueryHandler(user_repository=mock_user_repository)

    def test_create_search_users_query(self):
        """Test creating SearchUsersQuery."""
        query = SearchUsersQuery(
            search_term="john",
            include_inactive=False,
            limit=10,
        )
        
        assert query.search_term == "john"
        assert query.include_inactive is False
        assert query.limit == 10

    async def test_search_users_by_email(self, query_handler):
        """Test searching users by email."""
        users = [
            self._create_user("john.doe@example.com", "johndoe"),
            self._create_user("john.smith@example.com", "johnsmith"),
        ]
        
        query_handler.user_repository.search_users.return_value = users
        
        query = SearchUsersQuery(search_term="john")
        
        results = await query_handler.handle(query)
        
        assert len(results) == 2
        assert all(isinstance(r, UserListDTO) for r in results)
        assert results[0].email == "john.doe@example.com"
        assert results[1].email == "john.smith@example.com"

    async def test_search_users_by_username(self, query_handler):
        """Test searching users by username."""
        users = [
            self._create_user("user1@example.com", "testuser1"),
            self._create_user("user2@example.com", "testuser2"),
        ]
        
        query_handler.user_repository.search_users.return_value = users
        
        query = SearchUsersQuery(search_term="testuser")
        
        results = await query_handler.handle(query)
        
        assert len(results) == 2

    async def test_search_users_with_limit(self, query_handler):
        """Test searching users with result limit."""
        users = [self._create_user(f"user{i}@example.com", f"user{i}") for i in range(20)]
        
        query_handler.user_repository.search_users.return_value = users[:5]
        
        query = SearchUsersQuery(search_term="user", limit=5)
        
        results = await query_handler.handle(query)
        
        assert len(results) == 5

    async def test_search_empty_results(self, query_handler):
        """Test search with no results."""
        query_handler.user_repository.search_users.return_value = []
        
        query = SearchUsersQuery(search_term="nonexistent")
        
        results = await query_handler.handle(query)
        
        assert results == []

    async def test_search_validation(self):
        """Test search query validation."""
        # Empty search term
        with pytest.raises(ValidationError):
            SearchUsersQuery(search_term="")
        
        # Too short search term
        with pytest.raises(ValidationError):
            SearchUsersQuery(search_term="a")
        
        # Invalid limit
        with pytest.raises(ValidationError):
            SearchUsersQuery(search_term="test", limit=0)

    def _create_user(self, email: str, username: str) -> User:
        """Helper to create test user."""
        user = User.create(
            email=Email(email),
            username=Username(username),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        user.activate()
        return user


class TestListUsersQuery:
    """Test suite for ListUsersQuery and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def query_handler(self, mock_user_repository):
        """Create query handler with dependencies."""
        return ListUsersQueryHandler(user_repository=mock_user_repository)

    def test_create_list_users_query(self):
        """Test creating ListUsersQuery."""
        query = ListUsersQuery(
            page=2,
            page_size=20,
            sort_by="created_at",
            sort_order="desc",
            filters={
                "status": UserStatus.ACTIVE,
                "type": UserType.PREMIUM,
            }
        )
        
        assert query.page == 2
        assert query.page_size == 20
        assert query.sort_by == "created_at"
        assert query.sort_order == "desc"
        assert query.filters["status"] == UserStatus.ACTIVE

    async def test_list_users_paginated(self, query_handler):
        """Test listing users with pagination."""
        users = [
            self._create_user(f"user{i}@example.com", f"user{i}")
            for i in range(25)
        ]
        
        query_handler.user_repository.get_users_paginated.return_value = Mock(
            items=users[:10],
            total=25,
            page=1,
            page_size=10,
            pages=3,
        )
        
        query = ListUsersQuery(page=1, page_size=10)
        
        result = await query_handler.handle(query)
        
        assert isinstance(result, PaginatedUsersDTO)
        assert len(result.items) == 10
        assert result.total == 25
        assert result.page == 1
        assert result.pages == 3
        assert result.has_next is True
        assert result.has_previous is False

    async def test_list_users_with_filters(self, query_handler):
        """Test listing users with filters."""
        active_users = [
            self._create_user(f"active{i}@example.com", f"active{i}")
            for i in range(5)
        ]
        
        query_handler.user_repository.get_users_paginated.return_value = Mock(
            items=active_users,
            total=5,
            page=1,
            page_size=10,
            pages=1,
        )
        
        query = ListUsersQuery(
            page=1,
            page_size=10,
            filters={"status": UserStatus.ACTIVE}
        )
        
        result = await query_handler.handle(query)
        
        assert len(result.items) == 5
        # Verify filters were passed
        query_handler.user_repository.get_users_paginated.assert_called_with(
            page=1,
            page_size=10,
            filters={"status": UserStatus.ACTIVE},
            sort_by="created_at",
            sort_order="desc",
        )

    async def test_list_users_sorting(self, query_handler):
        """Test listing users with different sorting."""
        users = [self._create_user(f"user{i}@example.com", f"user{i}") for i in range(5)]
        
        query_handler.user_repository.get_users_paginated.return_value = Mock(
            items=users,
            total=5,
            page=1,
            page_size=10,
            pages=1,
        )
        
        query = ListUsersQuery(
            page=1,
            page_size=10,
            sort_by="username",
            sort_order="asc",
        )
        
        await query_handler.handle(query)
        
        # Verify sorting parameters
        query_handler.user_repository.get_users_paginated.assert_called_with(
            page=1,
            page_size=10,
            filters={},
            sort_by="username",
            sort_order="asc",
        )

    def _create_user(self, email: str, username: str) -> User:
        """Helper to create test user."""
        user = User.create(
            email=Email(email),
            username=Username(username),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        user.activate()
        return user


class TestGetUserProfileQuery:
    """Test suite for GetUserProfileQuery and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_role_repository(self):
        """Create mock role repository."""
        return AsyncMock()

    @pytest.fixture
    def query_handler(self, mock_user_repository, mock_role_repository):
        """Create query handler with dependencies."""
        return GetUserProfileQueryHandler(
            user_repository=mock_user_repository,
            role_repository=mock_role_repository,
        )

    @pytest.fixture
    def test_user_with_profile(self):
        """Create test user with complete profile."""
        user = User.create(
            email=Email("john.doe@example.com"),
            username=Username("johndoe"),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        user.activate()
        user.profile.first_name = "John"
        user.profile.last_name = "Doe"
        user.profile.phone = "+1234567890"
        user.profile.bio = "Software developer"
        user.profile.avatar_url = "https://example.com/avatar.jpg"
        user.profile.timezone = "America/New_York"
        user.profile.locale = "en_US"
        return user

    async def test_get_user_profile_success(self, query_handler, test_user_with_profile):
        """Test successfully getting user profile."""
        query_handler.user_repository.get_by_id.return_value = test_user_with_profile
        query_handler.role_repository.get_by_user_id.return_value = []
        
        query = GetUserProfileQuery(user_id=str(test_user_with_profile.id))
        
        result = await query_handler.handle(query)
        
        assert isinstance(result, UserProfileDTO)
        assert result.id == str(test_user_with_profile.id)
        assert result.email == "john.doe@example.com"
        assert result.username == "johndoe"
        assert result.first_name == "John"
        assert result.last_name == "Doe"
        assert result.full_name == "John Doe"
        assert result.phone == "+1234567890"
        assert result.bio == "Software developer"
        assert result.avatar_url == "https://example.com/avatar.jpg"
        assert result.timezone == "America/New_York"
        assert result.locale == "en_US"

    async def test_get_user_profile_with_roles(self, query_handler, test_user_with_profile):
        """Test getting user profile with roles."""
        from app.modules.identity.domain.entities.role import Role
        
        roles = [
            Role.create(name="Admin", description="Administrator"),
            Role.create(name="Editor", description="Content Editor"),
        ]
        
        query_handler.user_repository.get_by_id.return_value = test_user_with_profile
        query_handler.role_repository.get_by_user_id.return_value = roles
        
        query = GetUserProfileQuery(user_id=str(test_user_with_profile.id))
        
        result = await query_handler.handle(query)
        
        assert len(result.roles) == 2
        assert result.roles[0]["name"] == "Admin"
        assert result.roles[1]["name"] == "Editor"

    async def test_get_user_profile_not_found(self, query_handler):
        """Test getting profile for non-existent user."""
        query_handler.user_repository.get_by_id.return_value = None
        
        query = GetUserProfileQuery(user_id=str(uuid4()))
        
        with pytest.raises(NotFoundError):
            await query_handler.handle(query)

    async def test_get_user_profile_statistics(self, query_handler, test_user_with_profile):
        """Test user profile includes statistics."""
        test_user_with_profile.login_count = 42
        test_user_with_profile.last_login_at = datetime.now(UTC)
        
        query_handler.user_repository.get_by_id.return_value = test_user_with_profile
        query_handler.role_repository.get_by_user_id.return_value = []
        
        query = GetUserProfileQuery(user_id=str(test_user_with_profile.id))
        
        result = await query_handler.handle(query)
        
        assert result.statistics["login_count"] == 42
        assert result.statistics["last_login_at"] is not None