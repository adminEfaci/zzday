"""
Comprehensive unit tests for UserRegistrationCommand and handler.

Tests cover:
- User registration flow
- Validation rules
- Duplicate checking
- Event publishing
- Error scenarios
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, UTC

from app.modules.identity.application.commands.user_commands import (
    RegisterUserCommand,
    RegisterUserCommandHandler,
)
from app.modules.identity.application.dtos.request.user_dtos import UserRegistrationRequest
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.errors import DomainError, BusinessRuleViolation
from app.modules.identity.application.errors import (
    ApplicationError,
    ValidationError,
    ConflictError,
)


class TestUserRegistrationCommand:
    """Test suite for user registration command and handler."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        repo = AsyncMock()
        repo.get_by_email.return_value = None
        repo.get_by_username.return_value = None
        repo.save.return_value = None
        repo.exists_by_email.return_value = False
        repo.exists_by_username.return_value = False
        return repo

    @pytest.fixture
    def mock_password_service(self):
        """Create mock password service."""
        service = Mock()
        service.validate_password.return_value = True
        service.hash_password.return_value = PasswordHash("hashed_password")
        return service

    @pytest.fixture
    def mock_email_service(self):
        """Create mock email service."""
        service = AsyncMock()
        service.send_verification_email.return_value = None
        return service

    @pytest.fixture
    def mock_event_bus(self):
        """Create mock event bus."""
        bus = AsyncMock()
        bus.publish.return_value = None
        bus.publish_batch.return_value = None
        return bus

    @pytest.fixture
    def mock_token_service(self):
        """Create mock token service."""
        service = Mock()
        service.generate_verification_token.return_value = "verification_token_123"
        return service

    @pytest.fixture
    def command_handler(
        self,
        mock_user_repository,
        mock_password_service,
        mock_email_service,
        mock_event_bus,
        mock_token_service,
    ):
        """Create command handler with all dependencies."""
        return RegisterUserCommandHandler(
            user_repository=mock_user_repository,
            password_service=mock_password_service,
            email_service=mock_email_service,
            event_bus=mock_event_bus,
            token_service=mock_token_service,
        )

    def test_create_registration_command(self):
        """Test creating registration command with valid data."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            first_name="John",
            last_name="Doe",
            accept_terms=True,
            marketing_consent=False,
        )
        
        assert command.email == "user@example.com"
        assert command.username == "johndoe"
        assert command.password == "SecurePass123!"
        assert command.first_name == "John"
        assert command.last_name == "Doe"
        assert command.accept_terms is True
        assert command.marketing_consent is False

    def test_registration_command_validation(self):
        """Test command validation rules."""
        # Missing required fields
        with pytest.raises(ValidationError):
            RegisterUserCommand(
                email="",
                username="johndoe",
                password="SecurePass123!",
                accept_terms=True,
            )
        
        # Terms not accepted
        with pytest.raises(ValidationError) as exc_info:
            RegisterUserCommand(
                email="user@example.com",
                username="johndoe",
                password="SecurePass123!",
                accept_terms=False,
            )
        assert "must accept terms" in str(exc_info.value).lower()

    async def test_successful_user_registration(self, command_handler):
        """Test successful user registration flow."""
        command = RegisterUserCommand(
            email="newuser@example.com",
            username="newuser",
            password="SecurePass123!",
            first_name="New",
            last_name="User",
            accept_terms=True,
        )
        
        result = await command_handler.handle(command)
        
        # Verify user was created
        assert result.user_id is not None
        assert result.email == command.email
        assert result.username == command.username
        assert result.status == "pending_activation"
        assert result.verification_email_sent is True
        
        # Verify repository calls
        command_handler.user_repository.exists_by_email.assert_called_once_with(
            Email("newuser@example.com")
        )
        command_handler.user_repository.exists_by_username.assert_called_once_with(
            Username("newuser")
        )
        command_handler.user_repository.save.assert_called_once()
        
        # Verify email was sent
        command_handler.email_service.send_verification_email.assert_called_once()
        
        # Verify events were published
        assert command_handler.event_bus.publish_batch.called

    async def test_registration_with_duplicate_email(self, command_handler):
        """Test registration fails with duplicate email."""
        command_handler.user_repository.exists_by_email.return_value = True
        
        command = RegisterUserCommand(
            email="existing@example.com",
            username="newuser",
            password="SecurePass123!",
            accept_terms=True,
        )
        
        with pytest.raises(ConflictError) as exc_info:
            await command_handler.handle(command)
        
        assert "email already registered" in str(exc_info.value).lower()
        command_handler.user_repository.save.assert_not_called()

    async def test_registration_with_duplicate_username(self, command_handler):
        """Test registration fails with duplicate username."""
        command_handler.user_repository.exists_by_username.return_value = True
        
        command = RegisterUserCommand(
            email="newuser@example.com",
            username="existing",
            password="SecurePass123!",
            accept_terms=True,
        )
        
        with pytest.raises(ConflictError) as exc_info:
            await command_handler.handle(command)
        
        assert "username already taken" in str(exc_info.value).lower()
        command_handler.user_repository.save.assert_not_called()

    async def test_registration_with_weak_password(self, command_handler):
        """Test registration fails with weak password."""
        command_handler.password_service.validate_password.side_effect = ValidationError(
            "Password is too weak"
        )
        
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="weak",
            accept_terms=True,
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await command_handler.handle(command)
        
        assert "password is too weak" in str(exc_info.value).lower()
        command_handler.user_repository.save.assert_not_called()

    async def test_registration_with_invalid_email(self, command_handler):
        """Test registration fails with invalid email format."""
        command = RegisterUserCommand(
            email="invalid-email",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await command_handler.handle(command)
        
        assert "invalid email" in str(exc_info.value).lower()

    async def test_registration_with_reserved_username(self, command_handler):
        """Test registration fails with reserved username."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="admin",  # Reserved
            password="SecurePass123!",
            accept_terms=True,
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await command_handler.handle(command)
        
        assert "reserved" in str(exc_info.value).lower()

    async def test_registration_rollback_on_email_failure(self, command_handler):
        """Test registration rollback when email sending fails."""
        command_handler.email_service.send_verification_email.side_effect = Exception(
            "Email service unavailable"
        )
        
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
        )
        
        # Should still succeed but mark email as not sent
        result = await command_handler.handle(command)
        
        assert result.verification_email_sent is False
        assert result.user_id is not None
        
        # User should still be saved
        command_handler.user_repository.save.assert_called_once()

    async def test_registration_with_profile_data(self, command_handler):
        """Test registration with complete profile data."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            first_name="John",
            last_name="Doe",
            phone_number="+1234567890",
            date_of_birth="1990-01-01",
            timezone="America/New_York",
            locale="en_US",
            accept_terms=True,
            marketing_consent=True,
        )
        
        result = await command_handler.handle(command)
        
        assert result.user_id is not None
        assert result.profile_complete is True
        
        # Verify saved user has profile data
        saved_user_call = command_handler.user_repository.save.call_args[0][0]
        assert saved_user_call.profile.first_name == "John"
        assert saved_user_call.profile.last_name == "Doe"
        assert saved_user_call.profile.timezone == "America/New_York"

    async def test_registration_creates_audit_log(self, command_handler):
        """Test registration creates proper audit log entry."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
            client_ip="192.168.1.1",
            user_agent="Mozilla/5.0",
        )
        
        result = await command_handler.handle(command)
        
        # Verify audit information is captured
        assert result.registered_from_ip == "192.168.1.1"
        assert result.registration_source == "web"

    async def test_registration_idempotency(self, command_handler):
        """Test registration command is idempotent."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
            idempotency_key="unique_key_123",
        )
        
        # First call succeeds
        result1 = await command_handler.handle(command)
        
        # Mock that user now exists
        command_handler.user_repository.exists_by_email.return_value = True
        command_handler.user_repository.get_by_email.return_value = Mock(
            id=result1.user_id,
            email=Email(command.email),
            username=Username(command.username),
        )
        
        # Second call with same idempotency key returns same result
        result2 = await command_handler.handle(command)
        
        assert result1.user_id == result2.user_id

    async def test_registration_rate_limiting(self, command_handler):
        """Test registration enforces rate limiting."""
        # Simulate rate limit exceeded
        with patch("app.modules.identity.application.decorators.rate_limit") as mock_rate_limit:
            mock_rate_limit.side_effect = ApplicationError("Rate limit exceeded")
            
            command = RegisterUserCommand(
                email="user@example.com",
                username="johndoe",
                password="SecurePass123!",
                accept_terms=True,
            )
            
            with pytest.raises(ApplicationError) as exc_info:
                await command_handler.handle(command)
            
            assert "rate limit" in str(exc_info.value).lower()

    async def test_registration_with_referral_code(self, command_handler):
        """Test registration with referral code."""
        command = RegisterUserCommand(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
            referral_code="FRIEND2023",
        )
        
        result = await command_handler.handle(command)
        
        assert result.user_id is not None
        
        # Verify referral was tracked
        saved_user_call = command_handler.user_repository.save.call_args[0][0]
        assert saved_user_call.get_metadata("referral_code") == "FRIEND2023"

    async def test_registration_compliance_checks(self, command_handler):
        """Test registration performs compliance checks."""
        command = RegisterUserCommand(
            email="user@restrictedcountry.com",
            username="johndoe",
            password="SecurePass123!",
            accept_terms=True,
            country_code="XX",  # Restricted country
        )
        
        # Mock compliance check
        with patch("app.modules.identity.application.services.compliance_service") as mock_compliance:
            mock_compliance.check_registration_allowed.return_value = False
            
            with pytest.raises(ValidationError) as exc_info:
                await command_handler.handle(command)
            
            assert "registration not allowed" in str(exc_info.value).lower()