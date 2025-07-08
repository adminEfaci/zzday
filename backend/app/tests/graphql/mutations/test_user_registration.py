"""Test user registration mutation."""

import pytest
from httpx import AsyncClient

from app.modules.identity.domain.entities import User
from app.modules.identity.domain.value_objects import Email, UserId, Username


class TestUserRegistration:
    """Test cases for user registration mutation."""

    @pytest.mark.asyncio
    async def test_register_user_success(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_success,
        mock_user_service,
    ):
        """Test successful user registration."""
        # Arrange
        user_data = user_factory()
        mock_user = User(
            id=UserId.generate(),
            username=Username(user_data["username"]),
            email=Email(user_data["email"]),
        )
        mock_user_service.register_user.return_value = (mock_user, "mock_access_token")

        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                    "firstName": user_data["firstName"],
                    "lastName": user_data["lastName"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "register")
        assert result["data"]["register"]["user"]["username"] == user_data["username"]
        assert result["data"]["register"]["user"]["email"] == user_data["email"]
        assert result["data"]["register"]["token"]["accessToken"] is not None
        assert result["data"]["register"]["token"]["tokenType"] == "Bearer"

    @pytest.mark.asyncio
    async def test_register_user_duplicate_username(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test registration with duplicate username."""
        # Arrange
        user_data = user_factory(username="existinguser")
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Username already exists")

    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test registration with duplicate email."""
        # Arrange
        user_data = user_factory(email="existing@example.com")
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Email already registered")

    @pytest.mark.asyncio
    async def test_register_user_invalid_email(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test registration with invalid email format."""
        # Arrange
        user_data = user_factory(email="invalid-email")
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Invalid email format")

    @pytest.mark.asyncio
    async def test_register_user_weak_password(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test registration with weak password."""
        # Arrange
        user_data = user_factory(password="weak")
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Password does not meet requirements")

    @pytest.mark.asyncio
    async def test_register_user_missing_required_fields(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test registration with missing required fields."""
        # Arrange
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": "testuser",
                    # Missing email and password
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Field")  # GraphQL validation error

    @pytest.mark.asyncio
    async def test_register_user_with_profile_data(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test registration with profile data."""
        # Arrange
        user_data = user_factory(
            firstName="John",
            lastName="Doe",
        )
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                    "firstName": user_data["firstName"],
                    "lastName": user_data["lastName"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "register")
        assert result["data"]["register"]["user"]["firstName"] == "John"
        assert result["data"]["register"]["user"]["lastName"] == "Doe"

    @pytest.mark.asyncio
    async def test_register_user_creates_audit_entry(
        self,
        authenticated_graphql_client: AsyncClient,
        register_mutation: str,
        user_factory,
        make_graphql_request,
        assert_graphql_success,
        mock_audit_service,
    ):
        """Test that user registration creates an audit entry."""
        # Arrange
        user_data = user_factory()
        request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "register")
        mock_audit_service.log_event.assert_called_once()

        # Verify audit entry details
        call_args = mock_audit_service.log_event.call_args[1]
        assert call_args["action"] == "user.registered"
        assert call_args["resource_type"] == "user"
        assert call_args["resource_id"] is not None
