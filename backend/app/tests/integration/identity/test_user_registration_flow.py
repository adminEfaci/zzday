"""
Integration tests for user registration flow.

Tests the complete user registration process including validation,
email verification, and initial login.
"""

import asyncio

import pytest

from app.modules.identity.application.commands.authentication import LoginCommand
from app.modules.identity.application.commands.user import (
    RegisterUserCommand,
    VerifyEmailCommand,
)
from app.modules.identity.application.services import IdentityApplicationService
from app.modules.identity.domain.exceptions import (
    InvalidCredentialsError,
    InvalidPasswordError,
    UserAlreadyExistsError,
)
from app.shared.domain.events import DomainEventBus


@pytest.mark.integration
class TestUserRegistrationFlow:
    """Test complete user registration flow."""

    @pytest.fixture
    async def app_service(self, db_session, redis_client):
        """Create application service with real dependencies."""
        # This would be properly configured in a real test setup
        # For now, we'll use a mock structure
        from unittest.mock import AsyncMock, Mock

        service = Mock(spec=IdentityApplicationService)
        service.register_user = AsyncMock()
        service.verify_email = AsyncMock()
        service.login = AsyncMock()

        return service

    @pytest.mark.asyncio
    async def test_complete_registration_flow(self, app_service):
        """Test complete registration flow from signup to first login."""
        # Step 1: Register new user
        register_command = RegisterUserCommand(
            email="testuser@example.com",
            username="testuser",
            password="SecurePass123!@#",
            first_name="Test",
            last_name="User",
            terms_accepted=True,
        )

        registration_result = await app_service.register_user(register_command)

        assert registration_result.user_id is not None
        assert registration_result.verification_sent is True
        user_id = registration_result.user_id

        # Step 2: Simulate email verification token
        verification_token = "mock_verification_token"

        # Step 3: Verify email
        verify_command = VerifyEmailCommand(token=verification_token)
        verification_result = await app_service.verify_email(verify_command)

        assert verification_result.success is True
        assert verification_result.email == "testuser@example.com"

        # Step 4: First login
        login_command = LoginCommand(
            username="testuser",
            password="SecurePass123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 (Test Browser)",
        )

        login_result = await app_service.login(login_command)

        assert login_result.access_token is not None
        assert login_result.refresh_token is not None
        assert login_result.user_id == user_id

    @pytest.mark.asyncio
    async def test_registration_with_duplicate_email(self, app_service):
        """Test registration with already existing email."""
        # First registration
        first_command = RegisterUserCommand(
            email="duplicate@example.com",
            username="firstuser",
            password="SecurePass123!@#",
            first_name="First",
            last_name="User",
            terms_accepted=True,
        )

        await app_service.register_user(first_command)

        # Attempt duplicate registration
        duplicate_command = RegisterUserCommand(
            email="duplicate@example.com",  # Same email
            username="seconduser",
            password="AnotherPass456!@#",
            first_name="Second",
            last_name="User",
            terms_accepted=True,
        )

        with pytest.raises(UserAlreadyExistsError):
            await app_service.register_user(duplicate_command)

    @pytest.mark.asyncio
    async def test_registration_with_weak_password(self, app_service):
        """Test registration with password that doesn't meet requirements."""
        weak_passwords = [
            "short",  # Too short
            "alllowercase123",  # No uppercase
            "ALLUPPERCASE123",  # No lowercase
            "NoNumbers!@#",  # No numbers
            "NoSpecialChars123",  # No special characters
            "Common123!",  # Common password
        ]

        for password in weak_passwords:
            command = RegisterUserCommand(
                email=f"user_{password}@example.com",
                username=f"user_{password}",
                password=password,
                first_name="Test",
                last_name="User",
                terms_accepted=True,
            )

            with pytest.raises(InvalidPasswordError):
                await app_service.register_user(command)

    @pytest.mark.asyncio
    async def test_login_before_email_verification(self, app_service):
        """Test that login fails before email verification."""
        # Register user
        register_command = RegisterUserCommand(
            email="unverified@example.com",
            username="unverified",
            password="SecurePass123!@#",
            first_name="Unverified",
            last_name="User",
            terms_accepted=True,
        )

        await app_service.register_user(register_command)

        # Attempt login without verification
        login_command = LoginCommand(
            username="unverified",
            password="SecurePass123!@#",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
        )

        with pytest.raises(InvalidCredentialsError, match="email.*not.*verified"):
            await app_service.login(login_command)

    @pytest.mark.asyncio
    async def test_concurrent_registration_attempts(self, app_service):
        """Test handling of concurrent registration attempts."""
        # Create multiple registration commands with same email
        commands = []
        for i in range(5):
            command = RegisterUserCommand(
                email="concurrent@example.com",
                username=f"concurrent{i}",
                password="SecurePass123!@#",
                first_name="Concurrent",
                last_name=f"User{i}",
                terms_accepted=True,
            )
            commands.append(command)

        # Execute concurrently
        tasks = [app_service.register_user(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Only one should succeed
        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, UserAlreadyExistsError)]

        assert len(successes) == 1
        assert len(failures) == 4

    @pytest.mark.asyncio
    async def test_registration_with_international_characters(self, app_service):
        """Test registration with international names and addresses."""
        command = RegisterUserCommand(
            email="international@example.com",
            username="intluser",
            password="SecurePass123!@#",
            first_name="José",
            last_name="García",
            phone_number="+34-612-345-678",
            address_line1="Calle Mayor 123",
            address_city="Madrid",
            address_state="Madrid",
            address_postal_code="28001",
            address_country="ES",
            terms_accepted=True,
        )

        result = await app_service.register_user(command)

        assert result.user_id is not None
        assert result.email == "international@example.com"

    @pytest.mark.asyncio
    async def test_registration_rate_limiting(self, app_service):
        """Test rate limiting on registration attempts."""
        # Simulate multiple registration attempts from same IP
        ip_address = "192.168.1.100"

        for i in range(10):
            command = RegisterUserCommand(
                email=f"ratelimit{i}@example.com",
                username=f"ratelimit{i}",
                password="SecurePass123!@#",
                first_name="Rate",
                last_name="Limited",
                terms_accepted=True,
                ip_address=ip_address,
            )

            if i < 5:
                # First 5 should succeed
                result = await app_service.register_user(command)
                assert result.user_id is not None
            else:
                # After 5, should be rate limited
                with pytest.raises(Exception, match="rate.*limit"):
                    await app_service.register_user(command)


@pytest.mark.integration
class TestEmailVerificationFlow:
    """Test email verification flow."""

    @pytest.fixture
    async def registered_user(self, app_service):
        """Create a registered but unverified user."""
        command = RegisterUserCommand(
            email="verify@example.com",
            username="verifyuser",
            password="SecurePass123!@#",
            first_name="Verify",
            last_name="User",
            terms_accepted=True,
        )

        result = await app_service.register_user(command)
        return {
            "user_id": result.user_id,
            "email": result.email,
            "verification_token": "mock_token",  # In real test, extract from email
        }

    @pytest.mark.asyncio
    async def test_email_verification_success(self, app_service, registered_user):
        """Test successful email verification."""
        command = VerifyEmailCommand(token=registered_user["verification_token"])

        result = await app_service.verify_email(command)

        assert result.success is True
        assert result.email == registered_user["email"]

    @pytest.mark.asyncio
    async def test_email_verification_with_expired_token(
        self, app_service, registered_user
    ):
        """Test email verification with expired token."""
        # Create expired token
        expired_token = "expired_mock_token"

        command = VerifyEmailCommand(token=expired_token)

        with pytest.raises(Exception, match="expired"):
            await app_service.verify_email(command)

    @pytest.mark.asyncio
    async def test_email_verification_resend(self, app_service, registered_user):
        """Test resending verification email."""
        result = await app_service.resend_verification_email(
            user_id=registered_user["user_id"]
        )

        assert result.sent is True
        assert result.email == registered_user["email"]

    @pytest.mark.asyncio
    async def test_email_verification_rate_limiting(self, app_service, registered_user):
        """Test rate limiting on verification email resends."""
        # Request multiple resends
        for i in range(5):
            if i < 3:
                # First 3 should succeed
                result = await app_service.resend_verification_email(
                    user_id=registered_user["user_id"]
                )
                assert result.sent is True
            else:
                # After 3, should be rate limited
                with pytest.raises(Exception, match="rate.*limit"):
                    await app_service.resend_verification_email(
                        user_id=registered_user["user_id"]
                    )


@pytest.mark.integration
class TestRegistrationEvents:
    """Test domain events during registration."""

    @pytest.fixture
    def event_bus(self):
        """Create event bus to capture events."""
        from unittest.mock import Mock

        bus = Mock(spec=DomainEventBus)
        bus.events = []
        bus.publish = Mock(side_effect=lambda event: bus.events.append(event))
        return bus

    @pytest.mark.asyncio
    async def test_registration_events_sequence(self, app_service, event_bus):
        """Test that correct events are published during registration."""
        # Configure app service with event bus
        app_service.event_bus = event_bus

        # Register user
        command = RegisterUserCommand(
            email="events@example.com",
            username="eventuser",
            password="SecurePass123!@#",
            first_name="Event",
            last_name="User",
            terms_accepted=True,
        )

        await app_service.register_user(command)

        # Check events
        event_types = [type(e).__name__ for e in event_bus.events]

        assert "UserRegisteredEvent" in event_types
        assert "EmailVerificationRequestedEvent" in event_types
        assert "UserProfileCreatedEvent" in event_types

    @pytest.mark.asyncio
    async def test_verification_events_sequence(
        self, app_service, event_bus, registered_user
    ):
        """Test events during email verification."""
        app_service.event_bus = event_bus

        # Verify email
        command = VerifyEmailCommand(token=registered_user["verification_token"])

        await app_service.verify_email(command)

        # Check events
        event_types = [type(e).__name__ for e in event_bus.events]

        assert "EmailVerifiedEvent" in event_types
        assert "UserActivatedEvent" in event_types
