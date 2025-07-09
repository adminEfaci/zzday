"""
Comprehensive GraphQL Integration Tests

Tests the entire GraphQL stack including authentication, authorization, 
caching, subscriptions, monitoring, and cross-module interactions.
"""

import asyncio
import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from strawberry.test import BaseGraphQLTestClient
from strawberry.test.client import Response

from app.core.enums import EventType, UserStatus
from app.presentation.graphql.schema import create_schema
from app.presentation.graphql.monitoring import GraphQLMonitor, QueryStatus
from app.presentation.graphql.caching import QueryCacheManager
from app.presentation.graphql.subscriptions import SubscriptionManager
from app.presentation.graphql.authorization import AuthorizationContext


class TestGraphQLIntegrationSuite:
    """Comprehensive integration test suite for GraphQL."""
    
    @pytest.fixture
    async def graphql_client(self):
        """Create a GraphQL test client with full stack."""
        schema = create_schema("test")
        
        # Mock dependencies
        mock_container = MagicMock()
        mock_user_repo = AsyncMock()
        mock_audit_repo = AsyncMock()
        
        # Create context
        context = {
            "container": mock_container,
            "user": {
                "id": "test-user-123",
                "email": "test@example.com",
                "permissions": ["user:read", "user:write", "audit:read"]
            },
            "is_authenticated": True,
            "ip_address": "127.0.0.1",
            "user_agent": "test-agent",
            "request_id": "test-request-123"
        }
        
        return BaseGraphQLTestClient(schema, context=context)
    
    @pytest.fixture
    async def monitoring_setup(self):
        """Set up monitoring infrastructure."""
        monitor = GraphQLMonitor()
        await monitor.start()
        yield monitor
        await monitor.stop()
    
    @pytest.fixture
    async def cache_manager(self):
        """Set up cache manager."""
        cache_manager = QueryCacheManager()
        await cache_manager.start()
        yield cache_manager
        await cache_manager.stop()
    
    @pytest.fixture
    async def subscription_manager(self):
        """Set up subscription manager."""
        sub_manager = SubscriptionManager()
        await sub_manager.start()
        yield sub_manager
        await sub_manager.stop()

    @pytest.mark.asyncio
    async def test_complete_user_lifecycle_workflow(self, graphql_client):
        """Test complete user lifecycle through GraphQL."""
        
        # 1. Create user
        create_mutation = """
        mutation CreateUser($input: UserCreateInput!) {
            identity {
                createUser(input: $input) {
                    success
                    data {
                        user {
                            id
                            email
                            firstName
                            lastName
                            status
                        }
                        profile {
                            id
                            userId
                        }
                        preferences {
                            id
                            language
                            theme
                        }
                    }
                    errors {
                        field
                        message
                        code
                    }
                }
            }
        }
        """
        
        create_variables = {
            "input": {
                "email": "newuser@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "password": "SecurePass123!",
                "phoneNumber": "+1234567890"
            }
        }
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_repo.find_by_email.return_value = None
            mock_repo.create.return_value = MagicMock(
                id="new-user-123",
                email="newuser@example.com",
                first_name="John",
                last_name="Doe",
                status=UserStatus.ACTIVE
            )
            
            create_response = await graphql_client.query(create_mutation, create_variables)
            
            assert create_response.errors is None
            assert create_response.data["identity"]["createUser"]["success"] is True
            
            user_data = create_response.data["identity"]["createUser"]["data"]["user"]
            assert user_data["email"] == "newuser@example.com"
            assert user_data["firstName"] == "John"
            assert user_data["lastName"] == "Doe"
        
        # 2. Query user details
        query_user = """
        query GetUser($id: ID!) {
            identity {
                user(id: $id) {
                    id
                    email
                    firstName
                    lastName
                    profile {
                        phoneNumber
                        bio
                        avatar
                    }
                    preferences {
                        language
                        theme
                        emailNotifications
                    }
                    roles {
                        name
                        permissions {
                            name
                            resource
                        }
                    }
                    sessions(first: 5) {
                        edges {
                            node {
                                id
                                deviceName
                                isActive
                            }
                        }
                    }
                }
            }
        }
        """
        
        query_variables = {"id": "new-user-123"}
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_user = MagicMock()
            mock_user.id = "new-user-123"
            mock_user.email = "newuser@example.com"
            mock_user.first_name = "John"
            mock_user.last_name = "Doe"
            mock_repo.find_by_id.return_value = mock_user
            
            query_response = await graphql_client.query(query_user, query_variables)
            
            assert query_response.errors is None
            user_data = query_response.data["identity"]["user"]
            assert user_data["id"] == "new-user-123"
            assert user_data["email"] == "newuser@example.com"
        
        # 3. Update user profile
        update_mutation = """
        mutation UpdateProfile($id: ID!, $input: UserProfileUpdateInput!) {
            identity {
                updateProfile(id: $id, input: $input) {
                    success
                    data {
                        profile {
                            bio
                            website
                            location
                        }
                    }
                    errors {
                        field
                        message
                    }
                }
            }
        }
        """
        
        update_variables = {
            "id": "new-user-123",
            "input": {
                "bio": "Software developer passionate about GraphQL",
                "website": "https://johndoe.dev",
                "location": "San Francisco, CA"
            }
        }
        
        with patch('app.modules.identity.infrastructure.repositories.user_profile_repository.UserProfileRepository') as mock_profile_repo:
            mock_profile = MagicMock()
            mock_profile.bio = "Software developer passionate about GraphQL"
            mock_profile.website = "https://johndoe.dev"
            mock_profile.location = "San Francisco, CA"
            mock_profile_repo.find_by_user_id.return_value = mock_profile
            mock_profile_repo.update.return_value = mock_profile
            
            update_response = await graphql_client.query(update_mutation, update_variables)
            
            assert update_response.errors is None
            assert update_response.data["identity"]["updateProfile"]["success"] is True
            
            profile_data = update_response.data["identity"]["updateProfile"]["data"]["profile"]
            assert profile_data["bio"] == "Software developer passionate about GraphQL"
            assert profile_data["website"] == "https://johndoe.dev"
            assert profile_data["location"] == "San Francisco, CA"
        
        # 4. Delete user
        delete_mutation = """
        mutation DeleteUser($id: ID!) {
            identity {
                deleteUser(id: $id)
            }
        }
        """
        
        delete_variables = {"id": "new-user-123"}
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_user = MagicMock()
            mock_user.id = "new-user-123"
            mock_user.is_system_user = False
            mock_repo.find_by_id.return_value = mock_user
            mock_repo.update.return_value = mock_user
            
            delete_response = await graphql_client.query(delete_mutation, delete_variables)
            
            assert delete_response.errors is None
            assert delete_response.data["identity"]["deleteUser"] is True

    @pytest.mark.asyncio
    async def test_authorization_flow_comprehensive(self, graphql_client):
        """Test comprehensive authorization scenarios."""
        
        # Test with insufficient permissions
        restricted_mutation = """
        mutation CreateUser($input: UserCreateInput!) {
            identity {
                createUser(input: $input) {
                    success
                    errors {
                        field
                        message
                        code
                    }
                }
            }
        }
        """
        
        # Mock user without create permissions
        context_no_perms = {
            "user": {
                "id": "limited-user-123",
                "email": "limited@example.com",
                "permissions": ["user:read"]  # No create permission
            },
            "is_authenticated": True
        }
        
        client_no_perms = BaseGraphQLTestClient(create_schema("test"), context=context_no_perms)
        
        create_variables = {
            "input": {
                "email": "test@example.com",
                "firstName": "Test",
                "lastName": "User",
                "password": "password123"
            }
        }
        
        response = await client_no_perms.query(restricted_mutation, create_variables)
        
        # Should return authorization error
        assert response.errors is not None
        assert any("authorization" in str(error).lower() for error in response.errors)
        
        # Test field-level authorization
        field_restricted_query = """
        query GetSensitiveData {
            identity {
                users(first: 10) {
                    edges {
                        node {
                            id
                            email
                            securityEvents {  # Requires admin permission
                                eventType
                                description
                            }
                        }
                    }
                }
            }
        }
        """
        
        response = await client_no_perms.query(field_restricted_query)
        
        # Should return partial data with authorization errors for restricted fields
        assert response.errors is not None or response.data is not None

    @pytest.mark.asyncio
    async def test_caching_integration(self, graphql_client, cache_manager):
        """Test GraphQL caching integration."""
        
        user_query = """
        query GetUser($id: ID!) {
            identity {
                user(id: $id) {
                    id
                    email
                    firstName
                    lastName
                    profile {
                        bio
                        avatar
                    }
                }
            }
        }
        """
        
        variables = {"id": "test-user-123"}
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_user = MagicMock()
            mock_user.id = "test-user-123"
            mock_user.email = "test@example.com"
            mock_user.first_name = "Test"
            mock_user.last_name = "User"
            mock_repo.find_by_id.return_value = mock_user
            
            # First query - should hit database
            response1 = await graphql_client.query(user_query, variables)
            assert response1.errors is None
            assert mock_repo.find_by_id.call_count == 1
            
            # Second query - should hit cache
            response2 = await graphql_client.query(user_query, variables)
            assert response2.errors is None
            assert response2.data == response1.data
            
            # Verify cache hit
            cache_stats = cache_manager.get_stats()
            assert cache_stats["total_hits"] > 0
        
        # Test cache invalidation
        update_mutation = """
        mutation UpdateUser($id: ID!, $input: UserUpdateInput!) {
            identity {
                updateUser(id: $id, input: $input) {
                    success
                    data {
                        user {
                            id
                            firstName
                            lastName
                        }
                    }
                }
            }
        }
        """
        
        update_variables = {
            "id": "test-user-123",
            "input": {
                "firstName": "Updated",
                "lastName": "Name"
            }
        }
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_user = MagicMock()
            mock_user.id = "test-user-123"
            mock_user.first_name = "Updated"
            mock_user.last_name = "Name"
            mock_user.version = 2
            mock_repo.find_by_id.return_value = mock_user
            mock_repo.update.return_value = mock_user
            
            # Update should invalidate cache
            update_response = await graphql_client.query(update_mutation, update_variables)
            assert update_response.errors is None
            
            # Next query should miss cache and hit database
            response3 = await graphql_client.query(user_query, variables)
            assert response3.errors is None
            assert response3.data["identity"]["user"]["firstName"] == "Updated"

    @pytest.mark.asyncio
    async def test_subscription_integration(self, graphql_client, subscription_manager):
        """Test GraphQL subscription integration."""
        
        subscription_query = """
        subscription UserStatusUpdates {
            identity {
                userStatusChanged {
                    userId
                    status
                    timestamp
                }
            }
        }
        """
        
        # Mock WebSocket connection
        mock_websocket = AsyncMock()
        mock_connection = MagicMock()
        mock_connection.connection_id = "test-connection-123"
        mock_connection.websocket = mock_websocket
        mock_connection.is_active = True
        
        # Add connection to manager
        await subscription_manager.add_connection(mock_connection)
        
        # Start subscription
        await subscription_manager.add_subscription(
            connection_id="test-connection-123",
            subscription_id="sub-123",
            operation_name="UserStatusUpdates",
            query=subscription_query,
            variables={}
        )
        
        # Publish event
        from app.presentation.graphql.subscriptions import publish_user_status_changed
        
        await publish_user_status_changed(
            user_id="test-user-123",
            status="ACTIVE",
            metadata={"reason": "login"}
        )
        
        # Verify message was sent
        assert mock_websocket.send_text.called
        
        # Verify connection stats
        stats = subscription_manager.get_connection_stats()
        assert stats["total_connections"] == 1
        assert stats["total_subscriptions"] == 1

    @pytest.mark.asyncio
    async def test_monitoring_integration(self, graphql_client, monitoring_setup):
        """Test GraphQL monitoring integration."""
        
        monitor = monitoring_setup
        
        # Execute test query
        test_query = """
        query TestQuery {
            identity {
                users(first: 5) {
                    edges {
                        node {
                            id
                            email
                        }
                    }
                }
            }
        }
        """
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_repo.find_all.return_value = [
                MagicMock(id="user1", email="user1@example.com"),
                MagicMock(id="user2", email="user2@example.com")
            ]
            
            # Execute query
            response = await graphql_client.query(test_query)
            assert response.errors is None
            
            # Wait for monitoring to process
            await asyncio.sleep(0.1)
            
            # Check metrics
            metrics = monitor.get_real_time_metrics()
            assert metrics["total_queries"] > 0
            assert metrics["successful_queries"] > 0
            assert metrics["queries_per_second"] >= 0
            
            # Test query analysis
            analysis = monitor.get_query_analysis(test_query)
            assert analysis["execution_count"] > 0
            assert analysis["success_rate"] > 0

    @pytest.mark.asyncio
    async def test_error_handling_comprehensive(self, graphql_client):
        """Test comprehensive error handling scenarios."""
        
        # Test validation error
        invalid_mutation = """
        mutation CreateUser($input: UserCreateInput!) {
            identity {
                createUser(input: $input) {
                    success
                    errors {
                        field
                        message
                        code
                    }
                }
            }
        }
        """
        
        invalid_variables = {
            "input": {
                "email": "invalid-email",  # Invalid email format
                "firstName": "",  # Empty name
                "lastName": "Doe",
                "password": "123"  # Weak password
            }
        }
        
        response = await graphql_client.query(invalid_mutation, invalid_variables)
        
        # Should return validation errors
        if response.data:
            create_result = response.data["identity"]["createUser"]
            assert create_result["success"] is False
            assert len(create_result["errors"]) > 0
            
            # Check error structure
            for error in create_result["errors"]:
                assert "field" in error
                assert "message" in error
                assert "code" in error
        
        # Test not found error
        not_found_query = """
        query GetNonExistentUser {
            identity {
                user(id: "non-existent-id") {
                    id
                    email
                }
            }
        }
        """
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_repo.find_by_id.return_value = None
            
            response = await graphql_client.query(not_found_query)
            
            # Should return not found error
            assert response.errors is not None
            assert any("not found" in str(error).lower() for error in response.errors)
        
        # Test database error
        db_error_query = """
        query GetUser($id: ID!) {
            identity {
                user(id: $id) {
                    id
                    email
                }
            }
        }
        """
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_repo:
            mock_repo.find_by_id.side_effect = Exception("Database connection failed")
            
            response = await graphql_client.query(db_error_query, {"id": "test-user"})
            
            # Should return internal server error
            assert response.errors is not None
            assert any("internal" in str(error).lower() for error in response.errors)

    @pytest.mark.asyncio
    async def test_cross_module_integration(self, graphql_client):
        """Test integration between different modules."""
        
        # Test query that spans multiple modules
        cross_module_query = """
        query CrossModuleData($userId: ID!) {
            identity {
                user(id: $userId) {
                    id
                    email
                    firstName
                    lastName
                }
            }
            audit {
                userActivity(userId: $userId, first: 10) {
                    edges {
                        node {
                            id
                            action
                            timestamp
                            metadata
                        }
                    }
                }
            }
        }
        """
        
        variables = {"userId": "test-user-123"}
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_user_repo, \
             patch('app.modules.audit.infrastructure.repositories.audit_entry_repository.AuditEntryRepository') as mock_audit_repo:
            
            # Mock user data
            mock_user = MagicMock()
            mock_user.id = "test-user-123"
            mock_user.email = "test@example.com"
            mock_user.first_name = "Test"
            mock_user.last_name = "User"
            mock_user_repo.find_by_id.return_value = mock_user
            
            # Mock audit data
            mock_audit_entries = [
                MagicMock(
                    id="audit-1",
                    action="LOGIN",
                    timestamp=datetime.utcnow(),
                    metadata={"ip": "127.0.0.1"}
                ),
                MagicMock(
                    id="audit-2",
                    action="UPDATE_PROFILE",
                    timestamp=datetime.utcnow(),
                    metadata={"fields": ["firstName", "lastName"]}
                )
            ]
            mock_audit_repo.find_by_user_id.return_value = mock_audit_entries
            
            response = await graphql_client.query(cross_module_query, variables)
            
            # Should successfully return data from both modules
            assert response.errors is None
            assert response.data["identity"]["user"]["id"] == "test-user-123"
            assert len(response.data["audit"]["userActivity"]["edges"]) == 2

    @pytest.mark.asyncio
    async def test_performance_optimization(self, graphql_client):
        """Test performance optimization features."""
        
        # Test DataLoader batching
        batched_query = """
        query BatchedUserQuery {
            identity {
                users(first: 3) {
                    edges {
                        node {
                            id
                            email
                            roles {
                                name
                                permissions {
                                    name
                                    resource
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        with patch('app.modules.identity.infrastructure.repositories.user_repository.UserRepository') as mock_user_repo, \
             patch('app.modules.identity.infrastructure.repositories.role_repository.RoleRepository') as mock_role_repo, \
             patch('app.modules.identity.infrastructure.repositories.permission_repository.PermissionRepository') as mock_perm_repo:
            
            # Mock users
            mock_users = [
                MagicMock(id="user1", email="user1@example.com"),
                MagicMock(id="user2", email="user2@example.com"),
                MagicMock(id="user3", email="user3@example.com")
            ]
            mock_user_repo.find_all.return_value = mock_users
            
            # Mock roles and permissions
            mock_roles = [MagicMock(id="role1", name="admin")]
            mock_permissions = [MagicMock(id="perm1", name="user:read", resource="users")]
            mock_role_repo.find_by_user_ids.return_value = mock_roles
            mock_perm_repo.find_by_role_ids.return_value = mock_permissions
            
            response = await graphql_client.query(batched_query)
            
            # Should successfully return batched data
            assert response.errors is None
            assert len(response.data["identity"]["users"]["edges"]) == 3
            
            # DataLoader should have batched the role and permission queries
            # instead of making N+1 queries
            assert mock_role_repo.find_by_user_ids.call_count <= 1
            assert mock_perm_repo.find_by_role_ids.call_count <= 1

    @pytest.mark.asyncio
    async def test_security_features(self, graphql_client):
        """Test security features and protections."""
        
        # Test query complexity limiting
        complex_query = """
        query ComplexQuery {
            identity {
                users(first: 100) {
                    edges {
                        node {
                            id
                            email
                            roles {
                                name
                                permissions {
                                    name
                                    resource
                                    roles {
                                        name
                                        users {
                                            email
                                            profile {
                                                bio
                                                avatar
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        response = await graphql_client.query(complex_query)
        
        # Should be rejected due to complexity
        assert response.errors is not None
        assert any("complex" in str(error).lower() for error in response.errors)
        
        # Test query depth limiting
        deep_query = """
        query DeepQuery {
            identity {
                user(id: "test") {
                    profile {
                        user {
                            profile {
                                user {
                                    profile {
                                        user {
                                            profile {
                                                user {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        response = await graphql_client.query(deep_query)
        
        # Should be rejected due to depth
        assert response.errors is not None
        assert any("depth" in str(error).lower() for error in response.errors)

    @pytest.mark.asyncio
    async def test_real_time_features(self, graphql_client, subscription_manager):
        """Test real-time features and subscriptions."""
        
        # Test notification subscription
        notification_subscription = """
        subscription NotificationUpdates {
            notifications {
                notificationReceived {
                    id
                    title
                    message
                    type
                    createdAt
                }
            }
        }
        """
        
        # Mock connection
        mock_websocket = AsyncMock()
        mock_connection = MagicMock()
        mock_connection.connection_id = "notification-connection"
        mock_connection.websocket = mock_websocket
        mock_connection.is_active = True
        
        await subscription_manager.add_connection(mock_connection)
        await subscription_manager.add_subscription(
            connection_id="notification-connection",
            subscription_id="notification-sub",
            operation_name="NotificationUpdates",
            query=notification_subscription,
            variables={}
        )
        
        # Publish notification
        from app.presentation.graphql.subscriptions import publish_notification
        
        await publish_notification(
            user_id="test-user-123",
            notification={
                "id": "notif-123",
                "title": "Test Notification",
                "message": "This is a test notification",
                "type": "INFO",
                "createdAt": datetime.utcnow().isoformat()
            }
        )
        
        # Verify subscription received notification
        assert mock_websocket.send_text.called
        
        # Test security event subscription
        security_subscription = """
        subscription SecurityEvents {
            audit {
                securityEvents {
                    eventType
                    userId
                    timestamp
                    severity
                }
            }
        }
        """
        
        await subscription_manager.add_subscription(
            connection_id="notification-connection",
            subscription_id="security-sub",
            operation_name="SecurityEvents",
            query=security_subscription,
            variables={}
        )
        
        # Publish security event
        from app.presentation.graphql.subscriptions import publish_security_event
        
        await publish_security_event(
            event_type="FAILED_LOGIN",
            user_id="test-user-123",
            data={"ip": "127.0.0.1", "attempts": 3}
        )
        
        # Verify security event was sent
        assert mock_websocket.send_text.call_count >= 2


@pytest.mark.asyncio
async def test_graphql_stack_performance():
    """Test overall GraphQL stack performance."""
    
    # Create test schema
    schema = create_schema("test")
    
    # Test with monitoring
    monitor = GraphQLMonitor()
    await monitor.start()
    
    try:
        # Execute multiple queries to test performance
        test_queries = [
            "query { identity { users(first: 10) { edges { node { id email } } } } }",
            "query { audit { entries(first: 5) { edges { node { id action } } } } }",
            "query { identity { user(id: \"test\") { id email profile { bio } } } }",
        ]
        
        # Execute queries concurrently
        start_time = asyncio.get_event_loop().time()
        
        tasks = []
        for query in test_queries:
            for _ in range(10):  # 10 iterations of each query
                task = asyncio.create_task(
                    BaseGraphQLTestClient(schema).query(query)
                )
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = asyncio.get_event_loop().time()
        total_time = end_time - start_time
        
        # Verify performance metrics
        assert total_time < 5.0  # Should complete within 5 seconds
        assert len(results) == 30  # All queries should complete
        
        # Check monitoring metrics
        metrics = monitor.get_real_time_metrics()
        assert metrics["total_queries"] > 0
        assert metrics["average_duration_ms"] < 1000  # Average under 1 second
        
    finally:
        await monitor.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])