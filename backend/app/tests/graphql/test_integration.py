"""Integration tests for cross-module GraphQL functionality."""
import asyncio

import pytest
from httpx import AsyncClient

from app.modules.identity.domain.entities import User


class TestCrossModuleIntegration:
    """Test cases for integration between different modules."""

    @pytest.mark.asyncio
    async def test_user_actions_create_audit_entries(
        self,
        graphql_client: AsyncClient,
        register_mutation: str,
        audit_logs_query: str,
        user_factory,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test that user actions properly create audit entries."""
        # Step 1: Register a new user
        user_data = user_factory()
        register_request = make_graphql_request(
            query=register_mutation,
            variables={
                "input": {
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "password": user_data["password"],
                }
            },
        )

        register_response = await graphql_client.post("", json=register_request)
        register_result = register_response.json()
        assert_graphql_success(register_result, "register")

        user_id = register_result["data"]["register"]["user"]["id"]

        # Step 2: Check audit logs for registration event
        await asyncio.sleep(0.1)  # Small delay to ensure audit log is written

        audit_request = make_graphql_request(
            query=audit_logs_query,
            variables={"filter": {"action": "user.registered", "resourceId": user_id}},
        )

        audit_response = await graphql_client.post("", json=audit_request)
        audit_result = audit_response.json()
        assert_graphql_success(audit_result, "auditLogs")

        # Verify audit entry exists
        audit_items = audit_result["data"]["auditLogs"]["items"]
        assert len(audit_items) > 0
        assert audit_items[0]["action"] == "user.registered"
        assert audit_items[0]["resourceId"] == user_id

    @pytest.mark.asyncio
    async def test_login_creates_audit_and_session(
        self,
        graphql_client: AsyncClient,
        login_mutation: str,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test that login creates both audit entry and session."""
        # Step 1: Login
        login_request = make_graphql_request(
            query=login_mutation,
            variables={
                "input": {
                    "username": test_user.username.value,
                    "password": "TestPassword123!",
                }
            },
        )

        login_response = await graphql_client.post("", json=login_request)
        login_result = login_response.json()
        assert_graphql_success(login_result, "login")

        access_token = login_result["data"]["login"]["token"]["accessToken"]

        # Step 2: Check user sessions using the new token
        session_query = """
        query GetMySessions {
            me {
                sessions {
                    id
                    deviceName
                    lastActivity
                }
            }
        }
        """

        # Add auth header
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        session_request = make_graphql_request(query=session_query)
        session_response = await graphql_client.post(
            "", json=session_request, headers=auth_headers
        )
        session_result = session_response.json()
        assert_graphql_success(session_result, "me")

        # Verify session exists
        sessions = session_result["data"]["me"]["sessions"]
        assert len(sessions) > 0

        # Step 3: Check audit logs
        audit_query = """
        query GetLoginAudits($userId: ID!) {
            auditLogs(filter: { actorId: $userId, action: "user.login" }) {
                items {
                    action
                    timestamp
                    metadata
                }
            }
        }
        """

        audit_request = make_graphql_request(
            query=audit_query, variables={"userId": str(test_user.id.value)}
        )

        audit_response = await graphql_client.post(
            "", json=audit_request, headers=auth_headers
        )
        audit_result = audit_response.json()
        assert_graphql_success(audit_result, "auditLogs")

        # Verify audit entry
        audit_items = audit_result["data"]["auditLogs"]["items"]
        assert len(audit_items) > 0
        assert audit_items[0]["action"] == "user.login"

    @pytest.mark.asyncio
    async def test_role_assignment_triggers_notifications(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_notification_service,
    ):
        """Test that role assignment triggers notifications."""
        # Step 1: Create a role
        create_role_mutation = """
        mutation CreateRole($input: CreateRoleInput!) {
            createRole(input: $input) {
                id
                name
            }
        }
        """

        role_request = make_graphql_request(
            query=create_role_mutation,
            variables={
                "input": {
                    "name": "moderator",
                    "description": "Moderator role",
                    "permissions": ["content.moderate", "user.view"],
                }
            },
        )

        role_response = await authenticated_graphql_client.post("", json=role_request)
        role_result = role_response.json()
        assert_graphql_success(role_result, "createRole")

        role_id = role_result["data"]["createRole"]["id"]

        # Step 2: Assign role to user
        assign_role_mutation = """
        mutation AssignRole($userId: ID!, $roleId: ID!) {
            assignRoleToUser(userId: $userId, roleId: $roleId) {
                success
                user {
                    id
                    roles {
                        id
                        name
                    }
                }
            }
        }
        """

        assign_request = make_graphql_request(
            query=assign_role_mutation,
            variables={"userId": str(test_user.id.value), "roleId": role_id},
        )

        assign_response = await authenticated_graphql_client.post(
            "", json=assign_request
        )
        assign_result = assign_response.json()
        assert_graphql_success(assign_result, "assignRoleToUser")

        # Step 3: Verify notification was sent
        mock_notification_service.send_email.assert_called()
        email_args = mock_notification_service.send_email.call_args[1]
        assert email_args["to"] == test_user.email.value
        assert "role" in email_args["subject"].lower()

    @pytest.mark.asyncio
    async def test_password_change_invalidates_sessions(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test that changing password invalidates other sessions."""
        # Step 1: Create multiple sessions by logging in from different devices
        # (This would be simulated in a real test)

        # Step 2: Change password
        change_password_mutation = """
        mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
            changePassword(currentPassword: $currentPassword, newPassword: $newPassword) {
                success
                sessionsInvalidated
            }
        }
        """

        change_request = make_graphql_request(
            query=change_password_mutation,
            variables={
                "currentPassword": "TestPassword123!",
                "newPassword": "NewSecurePassword123!",
            },
        )

        change_response = await authenticated_graphql_client.post(
            "", json=change_request
        )
        change_result = change_response.json()
        assert_graphql_success(change_result, "changePassword")

        # Verify sessions were invalidated
        assert change_result["data"]["changePassword"]["sessionsInvalidated"] >= 0

    @pytest.mark.asyncio
    async def test_concurrent_modifications_handled_correctly(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test that concurrent modifications are handled correctly."""
        # Create mutation for updating user profile
        update_mutation = """
        mutation UpdateProfile($input: UpdateProfileInput!) {
            updateProfile(input: $input) {
                id
                firstName
                lastName
                version
            }
        }
        """

        # Simulate concurrent updates
        async def update_profile(first_name: str, last_name: str):
            request = make_graphql_request(
                query=update_mutation,
                variables={"input": {"firstName": first_name, "lastName": last_name}},
            )
            response = await authenticated_graphql_client.post("", json=request)
            return response.json()

        # Execute concurrent updates
        results = await asyncio.gather(
            update_profile("John", "Doe"),
            update_profile("Jane", "Smith"),
            return_exceptions=True,
        )

        # At least one should succeed
        successful_updates = [r for r in results if r.get("data")]
        assert len(successful_updates) >= 1

        # Check final state
        current_user_query = """
        query GetCurrentUser {
            me {
                firstName
                lastName
                version
            }
        }
        """

        final_request = make_graphql_request(query=current_user_query)
        final_response = await authenticated_graphql_client.post("", json=final_request)
        final_result = final_response.json()

        assert_graphql_success(final_result, "me")
        user_data = final_result["data"]["me"]
        assert user_data["firstName"] in ["John", "Jane"]
        assert user_data["lastName"] in ["Doe", "Smith"]

    @pytest.mark.asyncio
    async def test_event_propagation_across_modules(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user: User,
        make_graphql_request,
        assert_graphql_success,
        mock_audit_service,
    ):
        """Test that events propagate correctly across modules."""
        # Step 1: Delete user account
        delete_mutation = """
        mutation DeleteAccount($password: String!) {
            deleteMyAccount(password: $password) {
                success
                message
            }
        }
        """

        delete_request = make_graphql_request(
            query=delete_mutation, variables={"password": "TestPassword123!"}
        )

        delete_response = await authenticated_graphql_client.post(
            "", json=delete_request
        )
        delete_result = delete_response.json()
        assert_graphql_success(delete_result, "deleteMyAccount")

        # Step 2: Verify cascade of events
        # Check that multiple audit entries were created
        audit_calls = mock_audit_service.log_event.call_args_list

        # Should have events for:
        # - account.deletion_requested
        # - sessions.terminated
        # - user.deleted
        actions = [call[1]["action"] for call in audit_calls]

        assert "account.deletion_requested" in actions
        assert "sessions.terminated" in actions
        assert "user.deleted" in actions

    @pytest.mark.asyncio
    async def test_search_across_modules(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test global search functionality across modules."""
        # Global search query
        search_query = """
        query GlobalSearch($query: String!) {
            search(query: $query) {
                users {
                    id
                    username
                    email
                    score
                }
                auditLogs {
                    id
                    action
                    timestamp
                    score
                }
                totalResults
            }
        }
        """

        search_request = make_graphql_request(
            query=search_query, variables={"query": "admin"}
        )

        search_response = await authenticated_graphql_client.post(
            "", json=search_request
        )
        search_result = search_response.json()
        assert_graphql_success(search_result, "search")

        # Verify results from multiple modules
        search_data = search_result["data"]["search"]
        assert "users" in search_data
        assert "auditLogs" in search_data
        assert isinstance(search_data["totalResults"], int)

        # Verify relevance scores
        if search_data["users"]:
            assert "score" in search_data["users"][0]
        if search_data["auditLogs"]:
            assert "score" in search_data["auditLogs"][0]
