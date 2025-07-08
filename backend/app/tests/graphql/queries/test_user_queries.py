"""Test user-related GraphQL queries."""

import pytest
from httpx import AsyncClient

from app.modules.identity.domain.entities import User


class TestUserQueries:
    """Test cases for user queries."""

    @pytest.mark.asyncio
    async def test_get_current_user(
        self,
        authenticated_graphql_client: AsyncClient,
        current_user_query: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting current authenticated user."""
        # Arrange
        request = make_graphql_request(query=current_user_query)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "me")
        user_data = result["data"]["me"]
        assert user_data["id"] == str(test_user.id.value)
        assert user_data["username"] == test_user.username.value
        assert user_data["email"] == test_user.email.value
        assert user_data["isActive"] == test_user.is_active
        assert user_data["emailVerified"] == test_user.email_verified

    @pytest.mark.asyncio
    async def test_get_current_user_unauthenticated(
        self,
        graphql_client: AsyncClient,
        current_user_query: str,
        make_graphql_request,
        assert_graphql_error,
    ):
        """Test getting current user without authentication."""
        # Arrange
        request = make_graphql_request(query=current_user_query)

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_error(result, "Unauthorized", "UNAUTHENTICATED")

    @pytest.mark.asyncio
    async def test_get_user_by_id(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        make_graphql_query,
        assert_graphql_success,
    ):
        """Test getting user by ID."""
        # Arrange
        query = make_graphql_query(
            query_name="user",
            params="$id: ID!",
            fields="id username email firstName lastName isActive emailVerified",
        )

        request = make_graphql_request(
            query=query, variables={"id": str(test_user.id.value)}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "user")
        user_data = result["data"]["user"]
        assert user_data["id"] == str(test_user.id.value)
        assert user_data["username"] == test_user.username.value

    @pytest.mark.asyncio
    async def test_get_user_by_username(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        make_graphql_query,
        assert_graphql_success,
    ):
        """Test getting user by username."""
        # Arrange
        query = make_graphql_query(
            query_name="userByUsername",
            params="$username: String!",
            fields="id username email isActive",
        )

        request = make_graphql_request(
            query=query, variables={"username": test_user.username.value}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "userByUsername")
        user_data = result["data"]["userByUsername"]
        assert user_data["username"] == test_user.username.value

    @pytest.mark.asyncio
    async def test_list_users_with_pagination(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
        user_factory,
    ):
        """Test listing users with pagination."""
        # Arrange
        query = """
        query ListUsers($pagination: PaginationInput) {
            users(pagination: $pagination) {
                items {
                    id
                    username
                    email
                    isActive
                }
                total
                page
                pageSize
                hasNextPage
                hasPreviousPage
            }
        }
        """

        request = make_graphql_request(
            query=query, variables={"pagination": {"page": 1, "pageSize": 10}}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "users")
        users_data = result["data"]["users"]
        assert "items" in users_data
        assert users_data["page"] == 1
        assert users_data["pageSize"] == 10
        assert isinstance(users_data["total"], int)
        assert isinstance(users_data["hasNextPage"], bool)
        assert isinstance(users_data["hasPreviousPage"], bool)

    @pytest.mark.asyncio
    async def test_search_users(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test searching users by query."""
        # Arrange
        query = """
        query SearchUsers($query: String!, $filters: UserFilterInput) {
            searchUsers(query: $query, filters: $filters) {
                items {
                    id
                    username
                    email
                    firstName
                    lastName
                    score
                }
                total
            }
        }
        """

        request = make_graphql_request(
            query=query,
            variables={
                "query": "john",
                "filters": {"isActive": True, "emailVerified": True},
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "searchUsers")
        search_results = result["data"]["searchUsers"]
        assert "items" in search_results
        assert isinstance(search_results["total"], int)

        # Check that results have relevance scores
        if search_results["items"]:
            assert "score" in search_results["items"][0]

    @pytest.mark.asyncio
    async def test_get_user_with_roles(
        self,
        authenticated_graphql_client: AsyncClient,
        test_admin_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting user with roles and permissions."""
        # Arrange
        query = """
        query GetUserWithRoles($id: ID!) {
            user(id: $id) {
                id
                username
                roles {
                    id
                    name
                    description
                    permissions {
                        id
                        name
                        description
                    }
                }
            }
        }
        """

        request = make_graphql_request(
            query=query, variables={"id": str(test_admin_user.id.value)}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "user")
        user_data = result["data"]["user"]
        assert len(user_data["roles"]) > 0

        admin_role = user_data["roles"][0]
        assert admin_role["name"] == "admin"
        assert len(admin_role["permissions"]) > 0

    @pytest.mark.asyncio
    async def test_get_user_profile(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting user profile information."""
        # Arrange
        query = """
        query GetUserProfile($id: ID!) {
            user(id: $id) {
                id
                username
                profile {
                    firstName
                    lastName
                    phoneNumber
                    dateOfBirth
                    avatarUrl
                    bio
                    preferences
                }
            }
        }
        """

        request = make_graphql_request(
            query=query, variables={"id": str(test_user.id.value)}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "user")
        user_data = result["data"]["user"]
        assert "profile" in user_data

    @pytest.mark.asyncio
    async def test_get_user_sessions(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting user's active sessions."""
        # Arrange
        query = """
        query GetUserSessions {
            me {
                id
                sessions {
                    id
                    deviceName
                    deviceType
                    ipAddress
                    lastActivity
                    createdAt
                }
            }
        }
        """

        request = make_graphql_request(query=query)

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "me")
        user_data = result["data"]["me"]
        assert "sessions" in user_data
        assert isinstance(user_data["sessions"], list)

    @pytest.mark.asyncio
    async def test_check_username_availability(
        self, graphql_client: AsyncClient, make_graphql_request, assert_graphql_success
    ):
        """Test checking username availability."""
        # Arrange
        query = """
        query CheckUsername($username: String!) {
            isUsernameAvailable(username: $username)
        }
        """

        request = make_graphql_request(
            query=query, variables={"username": "newusername"}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "isUsernameAvailable")
        assert isinstance(result["data"]["isUsernameAvailable"], bool)

    @pytest.mark.asyncio
    async def test_check_email_availability(
        self, graphql_client: AsyncClient, make_graphql_request, assert_graphql_success
    ):
        """Test checking email availability."""
        # Arrange
        query = """
        query CheckEmail($email: String!) {
            isEmailAvailable(email: $email)
        }
        """

        request = make_graphql_request(
            query=query, variables={"email": "newemail@example.com"}
        )

        # Act
        response = await graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "isEmailAvailable")
        assert isinstance(result["data"]["isEmailAvailable"], bool)
