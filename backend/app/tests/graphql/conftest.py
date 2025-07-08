"""GraphQL test fixtures and utilities."""
from typing import Any
from unittest.mock import AsyncMock

import pytest
from faker import Faker
from httpx import AsyncClient

from app.modules.audit.domain.entities import AuditEntry
from app.modules.audit.domain.value_objects import (
    Action,
    ActorId,
    AuditEntryId,
    ResourceId,
    ResourceType,
)
from app.modules.identity.domain.entities import Permission, Role, User
from app.modules.identity.domain.value_objects import (
    Email,
    PasswordHash,
    PermissionName,
    RoleName,
    UserId,
    Username,
)
from app.modules.identity.infrastructure.security.jwt_handler import JWTHandler

# Initialize Faker
fake = Faker()


@pytest.fixture
def graphql_url() -> str:
    """GraphQL endpoint URL."""
    return "/graphql"


@pytest.fixture
async def graphql_client(async_client: AsyncClient, graphql_url: str) -> AsyncClient:
    """GraphQL-specific HTTP client."""
    # Set base URL to include GraphQL endpoint
    async_client.base_url = async_client.base_url.join(graphql_url)
    return async_client


@pytest.fixture
def graphql_headers() -> dict[str, str]:
    """Default GraphQL request headers."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


@pytest.fixture
async def authenticated_graphql_client(
    graphql_client: AsyncClient,
    test_user: User,
    jwt_handler: JWTHandler,
    graphql_headers: dict[str, str],
) -> AsyncClient:
    """GraphQL client with authentication headers."""
    # Generate JWT token for test user
    token_data = {
        "sub": str(test_user.id.value),
        "username": test_user.username.value,
        "email": test_user.email.value,
    }
    access_token = jwt_handler.create_access_token(token_data)

    # Add authorization header
    auth_headers = {**graphql_headers, "Authorization": f"Bearer {access_token}"}

    # Update client headers
    graphql_client.headers.update(auth_headers)
    return graphql_client


@pytest.fixture
def make_graphql_request():
    """Factory for creating GraphQL requests."""

    def _make_request(
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        request = {"query": query}
        if variables:
            request["variables"] = variables
        if operation_name:
            request["operationName"] = operation_name
        return request

    return _make_request


@pytest.fixture
def make_graphql_mutation():
    """Factory for creating GraphQL mutations."""

    def _make_mutation(
        mutation_name: str, input_type: str, fields: str, fragment: str | None = None
    ) -> str:
        mutation = f"""
        mutation {mutation_name}($input: {input_type}!) {{
            {mutation_name}(input: $input) {{
                {fields}
            }}
        }}
        """
        if fragment:
            mutation += f"\n{fragment}"
        return mutation

    return _make_mutation


@pytest.fixture
def make_graphql_query():
    """Factory for creating GraphQL queries."""

    def _make_query(
        query_name: str,
        params: str | None = None,
        fields: str = "id",
        fragment: str | None = None,
    ) -> str:
        if params:
            query = f"""
            query {query_name}({params}) {{
                {query_name}({params.split(':')[0][1:]}: {params.split(':')[0][1:]}) {{
                    {fields}
                }}
            }}
            """
        else:
            query = f"""
            query {query_name} {{
                {query_name} {{
                    {fields}
                }}
            }}
            """
        if fragment:
            query += f"\n{fragment}"
        return query

    return _make_query


# Mock data factories
@pytest.fixture
def user_factory():
    """Factory for creating test users."""

    def _create_user(**kwargs) -> dict[str, Any]:
        return {
            "username": kwargs.get("username", fake.user_name()),
            "email": kwargs.get("email", fake.email()),
            "password": kwargs.get("password", fake.password(length=12)),
            "firstName": kwargs.get("firstName", fake.first_name()),
            "lastName": kwargs.get("lastName", fake.last_name()),
            "isActive": kwargs.get("isActive", True),
            "emailVerified": kwargs.get("emailVerified", False),
        }

    return _create_user


@pytest.fixture
def role_factory():
    """Factory for creating test roles."""

    def _create_role(**kwargs) -> dict[str, Any]:
        return {
            "name": kwargs.get("name", f"role_{fake.word()}"),
            "description": kwargs.get("description", fake.sentence()),
            "permissions": kwargs.get("permissions", []),
        }

    return _create_role


@pytest.fixture
def audit_entry_factory():
    """Factory for creating test audit entries."""

    def _create_audit_entry(**kwargs) -> dict[str, Any]:
        return {
            "action": kwargs.get("action", "user.login"),
            "resourceType": kwargs.get("resourceType", "user"),
            "resourceId": kwargs.get("resourceId", str(fake.uuid4())),
            "actorId": kwargs.get("actorId", str(fake.uuid4())),
            "metadata": kwargs.get("metadata", {}),
            "ipAddress": kwargs.get("ipAddress", fake.ipv4()),
            "userAgent": kwargs.get("userAgent", fake.user_agent()),
        }

    return _create_audit_entry


# GraphQL response helpers
@pytest.fixture
def assert_graphql_success():
    """Assert GraphQL response is successful."""

    def _assert(response: dict[str, Any], data_key: str | None = None):
        assert "errors" not in response, f"GraphQL errors: {response.get('errors')}"
        assert "data" in response, "No data in GraphQL response"

        if data_key:
            assert data_key in response["data"], f"'{data_key}' not in response data"
            assert response["data"][data_key] is not None, f"'{data_key}' is None"

    return _assert


@pytest.fixture
def assert_graphql_error():
    """Assert GraphQL response contains errors."""

    def _assert(
        response: dict[str, Any],
        error_message: str | None = None,
        extensions_code: str | None = None,
    ):
        assert "errors" in response, "No errors in GraphQL response"
        assert len(response["errors"]) > 0, "Empty errors array"

        if error_message:
            messages = [error.get("message", "") for error in response["errors"]]
            assert any(
                error_message in msg for msg in messages
            ), f"Error message '{error_message}' not found in {messages}"

        if extensions_code:
            codes = [
                error.get("extensions", {}).get("code", "")
                for error in response["errors"]
            ]
            assert (
                extensions_code in codes
            ), f"Extension code '{extensions_code}' not found in {codes}"

    return _assert


# Common GraphQL fragments
@pytest.fixture
def user_fragment() -> str:
    """Common user fields fragment."""
    return """
    fragment UserFields on User {
        id
        username
        email
        firstName
        lastName
        isActive
        emailVerified
        createdAt
        updatedAt
    }
    """


@pytest.fixture
def role_fragment() -> str:
    """Common role fields fragment."""
    return """
    fragment RoleFields on Role {
        id
        name
        description
        permissions {
            id
            name
            description
        }
        createdAt
        updatedAt
    }
    """


@pytest.fixture
def audit_entry_fragment() -> str:
    """Common audit entry fields fragment."""
    return """
    fragment AuditEntryFields on AuditEntry {
        id
        action
        resourceType
        resourceId
        actorId
        metadata
        ipAddress
        userAgent
        timestamp
    }
    """


# Mock services for testing
@pytest.fixture
def mock_user_service():
    """Mock user service for testing."""
    service = AsyncMock()
    service.register_user = AsyncMock()
    service.authenticate_user = AsyncMock()
    service.get_user = AsyncMock()
    service.update_user = AsyncMock()
    service.delete_user = AsyncMock()
    return service


@pytest.fixture
def mock_audit_service():
    """Mock audit service for testing."""
    service = AsyncMock()
    service.log_event = AsyncMock()
    service.get_audit_logs = AsyncMock()
    service.search_audit_logs = AsyncMock()
    return service


@pytest.fixture
def mock_notification_service():
    """Mock notification service for testing."""
    service = AsyncMock()
    service.send_email = AsyncMock()
    service.send_sms = AsyncMock()
    service.send_push_notification = AsyncMock()
    return service


# Test data fixtures
@pytest.fixture
def test_user() -> User:
    """Create a test user."""
    return User(
        id=UserId.generate(),
        username=Username("testuser"),
        email=Email("testuser@example.com"),
        password_hash=PasswordHash.create("TestPassword123!"),
        is_active=True,
        email_verified=True,
    )


@pytest.fixture
def test_admin_user(test_user: User) -> User:
    """Create a test admin user."""
    admin_role = Role(
        id=UserId.generate(),
        name=RoleName("admin"),
        description="Administrator role",
    )
    admin_permission = Permission(
        id=UserId.generate(),
        name=PermissionName("admin.access"),
        description="Full admin access",
    )
    admin_role.add_permission(admin_permission)
    test_user.add_role(admin_role)
    return test_user


@pytest.fixture
def test_audit_entry(test_user: User) -> AuditEntry:
    """Create a test audit entry."""
    return AuditEntry(
        id=AuditEntryId.generate(),
        action=Action("user.login"),
        resource_type=ResourceType("user"),
        resource_id=ResourceId(str(test_user.id.value)),
        actor_id=ActorId(str(test_user.id.value)),
        metadata={"ip_address": "127.0.0.1"},
    )


# GraphQL query/mutation strings
@pytest.fixture
def register_mutation() -> str:
    """User registration mutation."""
    return """
    mutation Register($input: RegisterInput!) {
        register(input: $input) {
            user {
                id
                username
                email
                firstName
                lastName
                isActive
                emailVerified
            }
            token {
                accessToken
                refreshToken
                tokenType
                expiresIn
            }
        }
    }
    """


@pytest.fixture
def login_mutation() -> str:
    """User login mutation."""
    return """
    mutation Login($input: LoginInput!) {
        login(input: $input) {
            user {
                id
                username
                email
                firstName
                lastName
                isActive
            }
            token {
                accessToken
                refreshToken
                tokenType
                expiresIn
            }
        }
    }
    """


@pytest.fixture
def current_user_query() -> str:
    """Current user query."""
    return """
    query CurrentUser {
        me {
            id
            username
            email
            firstName
            lastName
            isActive
            emailVerified
            roles {
                id
                name
                permissions {
                    id
                    name
                }
            }
        }
    }
    """


@pytest.fixture
def audit_logs_query() -> str:
    """Audit logs query."""
    return """
    query AuditLogs($filter: AuditLogFilterInput, $pagination: PaginationInput) {
        auditLogs(filter: $filter, pagination: $pagination) {
            items {
                id
                action
                resourceType
                resourceId
                actorId
                metadata
                timestamp
            }
            total
            page
            pageSize
            hasNextPage
            hasPreviousPage
        }
    }
    """
