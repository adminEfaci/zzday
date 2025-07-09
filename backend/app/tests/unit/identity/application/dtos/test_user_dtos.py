"""
Comprehensive unit tests for User DTOs.

Tests cover:
- DTO creation and validation
- Serialization/deserialization
- Data transformation
- Validation rules
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.modules.identity.application.dtos.request.user_dtos import (
    ChangePasswordRequest,
    UserFilterRequest,
    UserRegistrationRequest,
    UserUpdateRequest,
)
from app.modules.identity.application.dtos.response.user_dtos import (
    LoginResponse,
    PaginatedUsersDTO,
    UserDTO,
    UserListDTO,
)
from app.modules.identity.domain.enums import UserStatus, UserType


class TestUserRegistrationRequest:
    """Test suite for UserRegistrationRequest DTO."""

    def test_valid_registration_request(self):
        """Test creating valid registration request."""
        request = UserRegistrationRequest(
            email="user@example.com",
            username="johndoe",
            password="SecurePass123!",
            confirm_password="SecurePass123!",
            first_name="John",
            last_name="Doe",
            accept_terms=True,
        )
        
        assert request.email == "user@example.com"
        assert request.username == "johndoe"
        assert request.password == "SecurePass123!"
        assert request.first_name == "John"
        assert request.last_name == "Doe"
        assert request.accept_terms is True

    def test_registration_email_validation(self):
        """Test email validation in registration."""
        # Invalid email format
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationRequest(
                email="invalid-email",
                username="user",
                password="Pass123!",
                confirm_password="Pass123!",
                accept_terms=True,
            )
        
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("email",) for e in errors)

    def test_registration_password_validation(self):
        """Test password validation rules."""
        # Too short
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationRequest(
                email="user@example.com",
                username="user",
                password="Short1!",
                confirm_password="Short1!",
                accept_terms=True,
            )
        
        errors = exc_info.value.errors()
        assert any("at least 8 characters" in str(e) for e in errors)
        
        # No uppercase
        with pytest.raises(ValidationError):
            UserRegistrationRequest(
                email="user@example.com",
                username="user",
                password="lowercase123!",
                confirm_password="lowercase123!",
                accept_terms=True,
            )
        
        # No number
        with pytest.raises(ValidationError):
            UserRegistrationRequest(
                email="user@example.com",
                username="user",
                password="NoNumbers!",
                confirm_password="NoNumbers!",
                accept_terms=True,
            )

    def test_registration_password_confirmation(self):
        """Test password confirmation matching."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationRequest(
                email="user@example.com",
                username="user",
                password="SecurePass123!",
                confirm_password="DifferentPass123!",
                accept_terms=True,
            )
        
        errors = exc_info.value.errors()
        assert any("passwords must match" in str(e).lower() for e in errors)

    def test_registration_username_validation(self):
        """Test username validation."""
        # Too short
        with pytest.raises(ValidationError):
            UserRegistrationRequest(
                email="user@example.com",
                username="ab",
                password="Pass123!",
                confirm_password="Pass123!",
                accept_terms=True,
            )
        
        # Invalid characters
        with pytest.raises(ValidationError):
            UserRegistrationRequest(
                email="user@example.com",
                username="user@name",
                password="Pass123!",
                confirm_password="Pass123!",
                accept_terms=True,
            )

    def test_registration_terms_acceptance_required(self):
        """Test that terms acceptance is required."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegistrationRequest(
                email="user@example.com",
                username="user",
                password="Pass123!",
                confirm_password="Pass123!",
                accept_terms=False,
            )
        
        errors = exc_info.value.errors()
        assert any("must accept terms" in str(e).lower() for e in errors)

    def test_registration_optional_fields(self):
        """Test registration with optional fields."""
        request = UserRegistrationRequest(
            email="user@example.com",
            username="user",
            password="Pass123!",
            confirm_password="Pass123!",
            accept_terms=True,
            phone_number="+1234567890",
            date_of_birth="1990-01-01",
            timezone="America/New_York",
            locale="en_US",
            marketing_consent=True,
            referral_code="FRIEND2023",
        )
        
        assert request.phone_number == "+1234567890"
        assert request.date_of_birth == "1990-01-01"
        assert request.timezone == "America/New_York"
        assert request.marketing_consent is True


class TestUserUpdateRequest:
    """Test suite for UserUpdateRequest DTO."""

    def test_valid_user_update(self):
        """Test valid user update request."""
        request = UserUpdateRequest(
            first_name="Jane",
            last_name="Smith",
            phone_number="+0987654321",
            bio="Updated bio",
            timezone="Europe/London",
        )
        
        assert request.first_name == "Jane"
        assert request.last_name == "Smith"
        assert request.phone_number == "+0987654321"
        assert request.bio == "Updated bio"
        assert request.timezone == "Europe/London"

    def test_partial_user_update(self):
        """Test partial update with only some fields."""
        request = UserUpdateRequest(
            first_name="Jane",
        )
        
        assert request.first_name == "Jane"
        assert request.last_name is None
        assert request.phone_number is None

    def test_update_validation(self):
        """Test update field validation."""
        # Invalid phone format
        with pytest.raises(ValidationError):
            UserUpdateRequest(phone_number="invalid-phone")
        
        # Bio too long
        with pytest.raises(ValidationError):
            UserUpdateRequest(bio="x" * 501)


class TestChangePasswordRequest:
    """Test suite for ChangePasswordRequest DTO."""

    def test_valid_password_change(self):
        """Test valid password change request."""
        request = ChangePasswordRequest(
            current_password="OldPass123!",
            new_password="NewPass456!",
            confirm_password="NewPass456!",
        )
        
        assert request.current_password == "OldPass123!"
        assert request.new_password == "NewPass456!"

    def test_password_change_validation(self):
        """Test password change validation."""
        # New password same as current
        with pytest.raises(ValidationError) as exc_info:
            ChangePasswordRequest(
                current_password="SamePass123!",
                new_password="SamePass123!",
                confirm_password="SamePass123!",
            )
        
        errors = exc_info.value.errors()
        assert any("different from current" in str(e).lower() for e in errors)

    def test_new_password_confirmation(self):
        """Test new password confirmation."""
        with pytest.raises(ValidationError):
            ChangePasswordRequest(
                current_password="OldPass123!",
                new_password="NewPass456!",
                confirm_password="Different456!",
            )


class TestUserDTO:
    """Test suite for UserDTO response."""

    def test_create_user_dto(self):
        """Test creating UserDTO."""
        user_dto = UserDTO(
            id=str(uuid4()),
            email="user@example.com",
            username="johndoe",
            status=UserStatus.ACTIVE.value,
            type=UserType.REGULAR.value,
            first_name="John",
            last_name="Doe",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        
        assert user_dto.email == "user@example.com"
        assert user_dto.username == "johndoe"
        assert user_dto.status == "ACTIVE"
        assert user_dto.full_name == "John Doe"

    def test_user_dto_serialization(self):
        """Test UserDTO serialization."""
        user_dto = UserDTO(
            id=str(uuid4()),
            email="user@example.com",
            username="johndoe",
            status=UserStatus.ACTIVE.value,
            type=UserType.REGULAR.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        
        # Should be JSON serializable
        json_data = user_dto.model_dump_json()
        assert json_data is not None
        
        # Can recreate from dict
        dto_dict = user_dto.model_dump()
        recreated = UserDTO(**dto_dict)
        assert recreated.id == user_dto.id

    def test_user_dto_computed_fields(self):
        """Test computed fields in UserDTO."""
        user_dto = UserDTO(
            id=str(uuid4()),
            email="user@example.com",
            username="johndoe",
            status=UserStatus.ACTIVE.value,
            type=UserType.PREMIUM.value,
            first_name="John",
            last_name="Doe",
            avatar_url=None,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        
        assert user_dto.full_name == "John Doe"
        assert user_dto.display_name == "John Doe"  # Falls back to full name
        assert user_dto.avatar_url == "/api/avatars/default.png"  # Default avatar
        assert user_dto.is_premium is True


class TestPaginatedUsersDTO:
    """Test suite for PaginatedUsersDTO."""

    def test_create_paginated_response(self):
        """Test creating paginated users response."""
        users = [
            UserListDTO(
                id=str(uuid4()),
                email=f"user{i}@example.com",
                username=f"user{i}",
                status=UserStatus.ACTIVE.value,
                created_at=datetime.now(UTC),
            )
            for i in range(5)
        ]
        
        paginated = PaginatedUsersDTO(
            items=users,
            total=50,
            page=2,
            page_size=5,
            pages=10,
        )
        
        assert len(paginated.items) == 5
        assert paginated.total == 50
        assert paginated.page == 2
        assert paginated.pages == 10
        assert paginated.has_next is True
        assert paginated.has_previous is True
        assert paginated.next_page == 3
        assert paginated.previous_page == 1

    def test_paginated_edge_cases(self):
        """Test pagination edge cases."""
        # First page
        paginated = PaginatedUsersDTO(
            items=[],
            total=10,
            page=1,
            page_size=5,
            pages=2,
        )
        
        assert paginated.has_previous is False
        assert paginated.has_next is True
        assert paginated.previous_page is None
        assert paginated.next_page == 2
        
        # Last page
        paginated = PaginatedUsersDTO(
            items=[],
            total=10,
            page=2,
            page_size=5,
            pages=2,
        )
        
        assert paginated.has_previous is True
        assert paginated.has_next is False
        assert paginated.previous_page == 1
        assert paginated.next_page is None


class TestLoginResponse:
    """Test suite for LoginResponse DTO."""

    def test_successful_login_response(self):
        """Test successful login response."""
        response = LoginResponse(
            success=True,
            access_token="access_token_123",
            refresh_token="refresh_token_123",
            expires_in=3600,
            token_type="Bearer",
            user_id=str(uuid4()),
            mfa_required=False,
        )
        
        assert response.success is True
        assert response.access_token == "access_token_123"
        assert response.token_type == "Bearer"
        assert response.mfa_required is False

    def test_mfa_required_response(self):
        """Test login response when MFA is required."""
        response = LoginResponse(
            success=True,
            mfa_required=True,
            mfa_token="mfa_token_123",
            mfa_methods=["totp", "sms"],
        )
        
        assert response.mfa_required is True
        assert response.mfa_token == "mfa_token_123"
        assert response.access_token is None
        assert "totp" in response.mfa_methods

    def test_failed_login_response(self):
        """Test failed login response."""
        response = LoginResponse(
            success=False,
            error="Invalid credentials",
            error_code="AUTH_001",
        )
        
        assert response.success is False
        assert response.error == "Invalid credentials"
        assert response.access_token is None


class TestUserFilterRequest:
    """Test suite for UserFilterRequest DTO."""

    def test_user_filter_request(self):
        """Test creating user filter request."""
        filter_request = UserFilterRequest(
            status=[UserStatus.ACTIVE, UserStatus.INACTIVE],
            type=[UserType.REGULAR],
            created_after="2023-01-01",
            created_before="2023-12-31",
            has_mfa=True,
            email_verified=True,
            role_ids=[str(uuid4())],
        )
        
        assert len(filter_request.status) == 2
        assert UserStatus.ACTIVE in filter_request.status
        assert filter_request.has_mfa is True
        assert filter_request.email_verified is True

    def test_filter_date_validation(self):
        """Test filter date validation."""
        # Invalid date range
        with pytest.raises(ValidationError) as exc_info:
            UserFilterRequest(
                created_after="2023-12-31",
                created_before="2023-01-01",
            )
        
        errors = exc_info.value.errors()
        assert any("before created_after" in str(e) for e in errors)

    def test_empty_filter(self):
        """Test empty filter (all users)."""
        filter_request = UserFilterRequest()
        
        # All fields should be None/empty
        assert filter_request.status is None
        assert filter_request.type is None
        assert filter_request.created_after is None