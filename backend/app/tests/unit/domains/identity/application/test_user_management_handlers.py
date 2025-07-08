"""
Test cases for user management command and query handlers.

Tests all user management handlers including registration, profile updates,
password management, and user queries.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.user import (
    ChangePasswordCommand,
    ChangePasswordCommandHandler,
    RegisterUserCommand,
    RegisterUserCommandHandler,
    UpdateUserProfileCommand,
    UpdateUserProfileCommandHandler,
    VerifyEmailCommand,
    VerifyEmailCommandHandler,
)
from app.modules.identity.application.queries.user import (
    GetUserProfileQuery,
    GetUserProfileQueryHandler,
    SearchUsersQuery,
    SearchUsersQueryHandler,
)
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.exceptions import (
    InvalidPasswordError,
    InvalidTokenError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.modules.identity.domain.value_objects import (
    Email,
    PersonName,
    PhoneNumber,
    Username,
)


class TestRegisterUserCommandHandler:
    """Test user registration command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_password_service = Mock()
        mock_email_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return RegisterUserCommandHandler(
            user_repository=mock_user_repo,
            password_service=mock_password_service,
            email_service=mock_email_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_user_registration(self, handler):
        """Test successful user registration."""
        # Arrange
        handler.user_repository.exists_by_email = AsyncMock(return_value=False)
        handler.user_repository.exists_by_username = AsyncMock(return_value=False)
        handler.password_service.hash_password = Mock(return_value="hashed_password")
        handler.user_repository.save = AsyncMock()
        handler.email_service.send_verification_email = AsyncMock()

        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="SecurePass123!@#",
            first_name="John",
            last_name="Doe",
            terms_accepted=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.user_id is not None
        assert result.email == "newuser@example.com"
        assert result.username == "newuser"
        assert result.verification_sent is True

        handler.user_repository.save.assert_called_once()
        handler.email_service.send_verification_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_registration_with_existing_email(self, handler):
        """Test registration with already existing email."""
        # Arrange
        handler.user_repository.exists_by_email = AsyncMock(return_value=True)

        command = RegisterUserCommand(
            email="existing@example.com",
            username="newuser",
            password="SecurePass123!@#",
            first_name="John",
            last_name="Doe",
            terms_accepted=True,
        )

        # Act & Assert
        with pytest.raises(UserAlreadyExistsError, match="email"):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_registration_with_existing_username(self, handler):
        """Test registration with already existing username."""
        # Arrange
        handler.user_repository.exists_by_email = AsyncMock(return_value=False)
        handler.user_repository.exists_by_username = AsyncMock(return_value=True)

        command = RegisterUserCommand(
            email="newuser@example.com",
            username="existinguser",
            password="SecurePass123!@#",
            first_name="John",
            last_name="Doe",
            terms_accepted=True,
        )

        # Act & Assert
        with pytest.raises(UserAlreadyExistsError, match="username"):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_registration_with_weak_password(self, handler):
        """Test registration with weak password."""
        # Arrange
        handler.user_repository.exists_by_email = AsyncMock(return_value=False)
        handler.user_repository.exists_by_username = AsyncMock(return_value=False)
        handler.password_service.validate_password_strength = Mock(
            side_effect=InvalidPasswordError("Password too weak")
        )

        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="weak",
            first_name="John",
            last_name="Doe",
            terms_accepted=True,
        )

        # Act & Assert
        with pytest.raises(InvalidPasswordError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_registration_without_accepting_terms(self, handler):
        """Test registration without accepting terms."""
        # Arrange
        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="SecurePass123!@#",
            first_name="John",
            last_name="Doe",
            terms_accepted=False,
        )

        # Act & Assert
        with pytest.raises(ValueError, match="terms"):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_registration_with_additional_details(self, handler):
        """Test registration with phone and address."""
        # Arrange
        handler.user_repository.exists_by_email = AsyncMock(return_value=False)
        handler.user_repository.exists_by_username = AsyncMock(return_value=False)
        handler.password_service.hash_password = Mock(return_value="hashed_password")
        handler.user_repository.save = AsyncMock()
        handler.email_service.send_verification_email = AsyncMock()

        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="SecurePass123!@#",
            first_name="John",
            last_name="Doe",
            phone_number="+1-555-123-4567",
            address_line1="123 Main St",
            address_city="New York",
            address_state="NY",
            address_postal_code="10001",
            address_country="US",
            terms_accepted=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.user_id is not None

        # Verify user was created with all details
        saved_user_call = handler.user_repository.save.call_args[0][0]
        assert saved_user_call.profile.phone_number is not None
        assert saved_user_call.profile.address is not None


class TestUpdateUserProfileCommandHandler:
    """Test update user profile command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return UpdateUserProfileCommandHandler(
            user_repository=mock_user_repo,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_profile_update(self, handler):
        """Test successful profile update."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.update_profile = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = UpdateUserProfileCommand(
            user_id=user.id,
            first_name="Jane",
            last_name="Smith",
            phone_number="+1-555-987-6543",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.user_id == user.id
        user.update_profile.assert_called_once()
        handler.user_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_profile_update_user_not_found(self, handler):
        """Test profile update when user not found."""
        # Arrange
        handler.user_repository.find_by_id = AsyncMock(return_value=None)

        command = UpdateUserProfileCommand(user_id=str(uuid4()), first_name="Jane")

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_profile_update_with_email_change(self, handler):
        """Test profile update with email change."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.email = Email("old@example.com")
        user.update_email = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.exists_by_email = AsyncMock(return_value=False)
        handler.user_repository.save = AsyncMock()

        command = UpdateUserProfileCommand(user_id=user.id, email="new@example.com")

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.email_verification_required is True
        user.update_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_profile_update_with_duplicate_email(self, handler):
        """Test profile update with already taken email."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.exists_by_email = AsyncMock(return_value=True)

        command = UpdateUserProfileCommand(user_id=user.id, email="taken@example.com")

        # Act & Assert
        with pytest.raises(UserAlreadyExistsError, match="email"):
            await handler.handle(command)


class TestChangePasswordCommandHandler:
    """Test change password command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_password_service = Mock()
        mock_session_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return ChangePasswordCommandHandler(
            user_repository=mock_user_repo,
            password_service=mock_password_service,
            session_service=mock_session_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_password_change(self, handler):
        """Test successful password change."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.validate_password = Mock(return_value=True)
        user.change_password = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.password_service.validate_password_strength = Mock()
        handler.password_service.hash_password = Mock(return_value="new_hashed")
        handler.user_repository.save = AsyncMock()
        handler.session_service.invalidate_all_sessions = AsyncMock()

        command = ChangePasswordCommand(
            user_id=user.id,
            current_password="CurrentPass123!",
            new_password="NewSecurePass456!@#",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.sessions_invalidated is True
        user.validate_password.assert_called_once_with("CurrentPass123!")
        user.change_password.assert_called_once()
        handler.session_service.invalidate_all_sessions.assert_called_once()

    @pytest.mark.asyncio
    async def test_password_change_with_wrong_current(self, handler):
        """Test password change with wrong current password."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.validate_password = Mock(return_value=False)
        user.record_failed_password_attempt = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = ChangePasswordCommand(
            user_id=user.id,
            current_password="WrongPassword",
            new_password="NewSecurePass456!@#",
        )

        # Act & Assert
        with pytest.raises(InvalidPasswordError, match="current"):
            await handler.handle(command)

        user.record_failed_password_attempt.assert_called_once()

    @pytest.mark.asyncio
    async def test_password_change_with_weak_new_password(self, handler):
        """Test password change with weak new password."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.validate_password = Mock(return_value=True)

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.password_service.validate_password_strength = Mock(
            side_effect=InvalidPasswordError("Password too weak")
        )

        command = ChangePasswordCommand(
            user_id=user.id, current_password="CurrentPass123!", new_password="weak"
        )

        # Act & Assert
        with pytest.raises(InvalidPasswordError, match="weak"):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_password_change_with_reused_password(self, handler):
        """Test password change with recently used password."""
        # Arrange
        user = Mock(spec=User)
        user.id = str(uuid4())
        user.validate_password = Mock(return_value=True)
        user.is_password_recently_used = Mock(return_value=True)

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.password_service.validate_password_strength = Mock()
        handler.password_service.hash_password = Mock(return_value="new_hashed")

        command = ChangePasswordCommand(
            user_id=user.id,
            current_password="CurrentPass123!",
            new_password="RecentlyUsedPass456!",
        )

        # Act & Assert
        with pytest.raises(InvalidPasswordError, match="recently used"):
            await handler.handle(command)


class TestGetUserProfileQueryHandler:
    """Test get user profile query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_cache = Mock()

        return GetUserProfileQueryHandler(
            user_repository=mock_user_repo, cache=mock_cache
        )

    @pytest.mark.asyncio
    async def test_get_user_profile_success(self, handler):
        """Test successfully getting user profile."""
        # Arrange
        user_id = str(uuid4())
        user = Mock(spec=User)
        user.id = user_id
        user.email = Email("user@example.com")
        user.username = Username("testuser")
        user.profile = Mock()
        user.profile.name = PersonName("John", "Doe")
        user.profile.phone_number = PhoneNumber("+1-555-123-4567")
        user.created_at = datetime.now(UTC)
        user.is_active = True
        user.is_email_verified = True
        user.mfa_enabled = False

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.cache.set = Mock()

        query = GetUserProfileQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.user_id == user_id
        assert result.email == "user@example.com"
        assert result.username == "testuser"
        assert result.full_name == "John Doe"
        assert result.is_active is True
        assert result.is_email_verified is True
        assert result.mfa_enabled is False

    @pytest.mark.asyncio
    async def test_get_user_profile_from_cache(self, handler):
        """Test getting user profile from cache."""
        # Arrange
        user_id = str(uuid4())
        cached_profile = {
            "user_id": user_id,
            "email": "cached@example.com",
            "username": "cacheduser",
            "full_name": "Cached User",
            "is_active": True,
        }

        handler.cache.get = Mock(return_value=cached_profile)

        query = GetUserProfileQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.email == "cached@example.com"
        handler.user_repository.find_by_id.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_user_profile_not_found(self, handler):
        """Test getting non-existent user profile."""
        # Arrange
        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=None)

        query = GetUserProfileQuery(user_id=str(uuid4()))

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(query)


class TestSearchUsersQueryHandler:
    """Test search users query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_search_service = Mock()

        return SearchUsersQueryHandler(
            user_repository=mock_user_repo, search_service=mock_search_service
        )

    @pytest.mark.asyncio
    async def test_search_users_by_name(self, handler):
        """Test searching users by name."""
        # Arrange
        users = []
        for i in range(3):
            user = Mock(spec=User)
            user.id = str(uuid4())
            user.email = Email(f"user{i}@example.com")
            user.username = Username(f"user{i}")
            user.profile = Mock()
            user.profile.name = PersonName(f"John{i}", "Doe")
            users.append(user)

        handler.search_service.search_users = AsyncMock(return_value=(users, 3))

        query = SearchUsersQuery(
            search_term="John", search_fields=["name"], page=1, page_size=10
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.users) == 3
        assert result.total_count == 3
        assert result.page == 1
        handler.search_service.search_users.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_users_with_filters(self, handler):
        """Test searching users with filters."""
        # Arrange
        active_users = []
        for _i in range(2):
            user = Mock(spec=User)
            user.id = str(uuid4())
            user.is_active = True
            user.is_email_verified = True
            active_users.append(user)

        handler.search_service.search_users = AsyncMock(return_value=(active_users, 2))

        query = SearchUsersQuery(
            search_term="test",
            filters={"is_active": True, "is_email_verified": True},
            page=1,
            page_size=10,
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.users) == 2
        assert all(u.is_active for u in result.users)

    @pytest.mark.asyncio
    async def test_search_users_with_sorting(self, handler):
        """Test searching users with sorting."""
        # Arrange
        users = []
        base_time = datetime.now(UTC)
        for i in range(3):
            user = Mock(spec=User)
            user.id = str(uuid4())
            user.created_at = base_time - timedelta(days=i)
            users.append(user)

        handler.search_service.search_users = AsyncMock(return_value=(users, 3))

        query = SearchUsersQuery(
            search_term="",
            sort_by="created_at",
            sort_order="desc",
            page=1,
            page_size=10,
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.users) == 3
        # Verify sorting was requested
        call_args = handler.search_service.search_users.call_args
        assert call_args[1]["sort_by"] == "created_at"
        assert call_args[1]["sort_order"] == "desc"


class TestVerifyEmailCommandHandler:
    """Test verify email command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_token_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return VerifyEmailCommandHandler(
            user_repository=mock_user_repo,
            token_service=mock_token_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_email_verification(self, handler):
        """Test successful email verification."""
        # Arrange
        user_id = str(uuid4())
        email = "user@example.com"

        handler.token_service.validate_email_token = Mock(
            return_value={
                "user_id": user_id,
                "email": email,
                "action": "email_verification",
            }
        )

        user = Mock(spec=User)
        user.id = user_id
        user.email = Email(email)
        user.is_email_verified = False
        user.verify_email = Mock()

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.user_repository.save = AsyncMock()

        command = VerifyEmailCommand(token="valid_verification_token")

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.email == email
        user.verify_email.assert_called_once()
        handler.user_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_email_verification_with_invalid_token(self, handler):
        """Test email verification with invalid token."""
        # Arrange
        handler.token_service.validate_email_token = Mock(
            side_effect=InvalidTokenError("Invalid token")
        )

        command = VerifyEmailCommand(token="invalid_token")

        # Act & Assert
        with pytest.raises(InvalidTokenError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_email_verification_already_verified(self, handler):
        """Test email verification when already verified."""
        # Arrange
        user_id = str(uuid4())
        email = "user@example.com"

        handler.token_service.validate_email_token = Mock(
            return_value={
                "user_id": user_id,
                "email": email,
                "action": "email_verification",
            }
        )

        user = Mock(spec=User)
        user.id = user_id
        user.is_email_verified = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)

        command = VerifyEmailCommand(token="valid_token")

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.already_verified is True
        handler.user_repository.save.assert_not_called()
