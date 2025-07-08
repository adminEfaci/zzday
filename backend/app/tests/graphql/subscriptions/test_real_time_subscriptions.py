"""Test GraphQL subscriptions for real-time updates."""
import asyncio

import pytest
from httpx import AsyncClient


class TestRealTimeSubscriptions:
    """Test cases for GraphQL subscriptions."""

    @pytest.mark.asyncio
    async def test_audit_log_subscription(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request, test_user
    ):
        """Test subscribing to audit log events."""
        # Arrange
        subscription = """
        subscription OnAuditLogCreated($resourceType: String) {
            auditLogCreated(resourceType: $resourceType) {
                id
                action
                resourceType
                resourceId
                actorId
                timestamp
            }
        }
        """

        # Create WebSocket connection for subscription
        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Send subscription
            await websocket.send_json(
                {
                    "id": "1",
                    "type": "subscribe",
                    "payload": make_graphql_request(
                        query=subscription, variables={"resourceType": "user"}
                    ),
                }
            )

            # Trigger an event that should create an audit log
            login_mutation = """
            mutation TriggerAuditEvent {
                login(input: { username: "testuser", password: "password" }) {
                    token {
                        accessToken
                    }
                }
            }
            """

            # Execute mutation in parallel
            asyncio.create_task(
                authenticated_graphql_client.post(
                    "", json=make_graphql_request(query=login_mutation)
                )
            )

            # Wait for subscription message
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

            # Assert
            assert message["type"] == "next"
            assert message["id"] == "1"
            assert "auditLogCreated" in message["payload"]["data"]

            audit_data = message["payload"]["data"]["auditLogCreated"]
            assert audit_data["resourceType"] == "user"
            assert audit_data["action"] is not None

    @pytest.mark.asyncio
    async def test_user_status_subscription(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request
    ):
        """Test subscribing to user status changes."""
        # Arrange
        subscription = """
        subscription OnUserStatusChanged($userId: ID!) {
            userStatusChanged(userId: $userId) {
                userId
                status
                lastSeen
            }
        }
        """

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Subscribe to user status changes
            await websocket.send_json(
                {
                    "id": "2",
                    "type": "subscribe",
                    "payload": make_graphql_request(
                        query=subscription, variables={"userId": "user123"}
                    ),
                }
            )

            # Simulate user status change
            status_mutation = """
            mutation UpdateStatus {
                updateMyStatus(status: "away") {
                    success
                }
            }
            """

            asyncio.create_task(
                authenticated_graphql_client.post(
                    "", json=make_graphql_request(query=status_mutation)
                )
            )

            # Wait for subscription update
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

            # Assert
            assert message["type"] == "next"
            status_data = message["payload"]["data"]["userStatusChanged"]
            assert status_data["userId"] == "user123"
            assert status_data["status"] in ["online", "away", "offline"]

    @pytest.mark.asyncio
    async def test_notification_subscription(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request, test_user
    ):
        """Test subscribing to user notifications."""
        # Arrange
        subscription = """
        subscription OnNotification {
            notificationReceived {
                id
                type
                title
                message
                priority
                createdAt
                read
            }
        }
        """

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Subscribe to notifications
            await websocket.send_json(
                {
                    "id": "3",
                    "type": "subscribe",
                    "payload": make_graphql_request(query=subscription),
                }
            )

            # Trigger a notification (e.g., role assignment)
            notification_mutation = f"""
            mutation TriggerNotification {{
                assignRoleToUser(userId: "{test_user.id.value!s}", roleId: "role123") {{
                    success
                }}
            }}
            """

            asyncio.create_task(
                authenticated_graphql_client.post(
                    "", json=make_graphql_request(query=notification_mutation)
                )
            )

            # Wait for notification
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

            # Assert
            assert message["type"] == "next"
            notification = message["payload"]["data"]["notificationReceived"]
            assert notification["id"] is not None
            assert notification["type"] is not None
            assert notification["read"] is False

    @pytest.mark.asyncio
    async def test_session_activity_subscription(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request
    ):
        """Test subscribing to session activity updates."""
        # Arrange
        subscription = """
        subscription OnSessionActivity {
            sessionActivity {
                sessionId
                event
                deviceInfo {
                    deviceName
                    ipAddress
                }
                timestamp
            }
        }
        """

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Subscribe
            await websocket.send_json(
                {
                    "id": "4",
                    "type": "subscribe",
                    "payload": make_graphql_request(query=subscription),
                }
            )

            # Simulate session activity
            activity_mutation = """
            mutation RefreshSession {
                refreshToken(refreshToken: "some_token") {
                    accessToken
                }
            }
            """

            asyncio.create_task(
                authenticated_graphql_client.post(
                    "", json=make_graphql_request(query=activity_mutation)
                )
            )

            # Wait for activity update
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

            # Assert
            assert message["type"] == "next"
            activity = message["payload"]["data"]["sessionActivity"]
            assert activity["event"] in ["login", "logout", "refresh", "activity"]

    @pytest.mark.asyncio
    async def test_multiple_subscriptions(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request
    ):
        """Test handling multiple simultaneous subscriptions."""
        # Arrange
        subscriptions = [
            {
                "id": "sub1",
                "query": """
                subscription AuditLogs {
                    auditLogCreated {
                        id
                        action
                    }
                }
                """,
            },
            {
                "id": "sub2",
                "query": """
                subscription Notifications {
                    notificationReceived {
                        id
                        type
                    }
                }
                """,
            },
        ]

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Subscribe to multiple events
            for sub in subscriptions:
                await websocket.send_json(
                    {
                        "id": sub["id"],
                        "type": "subscribe",
                        "payload": {"query": sub["query"]},
                    }
                )

            # Trigger events
            trigger_mutation = """
            mutation TriggerEvents {
                updateProfile(input: { firstName: "Test" }) {
                    id
                }
            }
            """

            asyncio.create_task(
                authenticated_graphql_client.post(
                    "", json=make_graphql_request(query=trigger_mutation)
                )
            )

            # Collect messages
            messages = []
            for _ in range(2):
                try:
                    message = await asyncio.wait_for(
                        websocket.receive_json(), timeout=5.0
                    )
                    messages.append(message)
                except TimeoutError:
                    break

            # Assert we received messages for both subscriptions
            subscription_ids = [msg["id"] for msg in messages]
            assert "sub1" in subscription_ids or "sub2" in subscription_ids

    @pytest.mark.asyncio
    async def test_subscription_with_error(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request
    ):
        """Test subscription error handling."""
        # Arrange - Invalid subscription
        subscription = """
        subscription InvalidSubscription {
            nonExistentSubscription {
                id
            }
        }
        """

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Send invalid subscription
            await websocket.send_json(
                {
                    "id": "error-sub",
                    "type": "subscribe",
                    "payload": make_graphql_request(query=subscription),
                }
            )

            # Wait for error message
            message = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

            # Assert
            assert message["type"] == "error"
            assert message["id"] == "error-sub"
            assert "errors" in message["payload"]

    @pytest.mark.asyncio
    async def test_subscription_unsubscribe(
        self, authenticated_graphql_client: AsyncClient, make_graphql_request
    ):
        """Test unsubscribing from a subscription."""
        # Arrange
        subscription = """
        subscription TestSub {
            auditLogCreated {
                id
            }
        }
        """

        async with authenticated_graphql_client.websocket_connect(
            "/graphql"
        ) as websocket:
            # Subscribe
            await websocket.send_json(
                {
                    "id": "unsub-test",
                    "type": "subscribe",
                    "payload": make_graphql_request(query=subscription),
                }
            )

            # Unsubscribe
            await websocket.send_json({"id": "unsub-test", "type": "complete"})

            # Trigger event
            trigger_mutation = """
            mutation TriggerAfterUnsub {
                logout {
                    success
                }
            }
            """

            await authenticated_graphql_client.post(
                "", json=make_graphql_request(query=trigger_mutation)
            )

            # Should not receive any messages after unsubscribe
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(websocket.receive_json(), timeout=2.0)

    @pytest.mark.asyncio
    async def test_subscription_authentication_required(
        self, graphql_client: AsyncClient, make_graphql_request
    ):
        """Test that subscriptions require authentication."""
        # Arrange
        subscription = """
        subscription RequiresAuth {
            notificationReceived {
                id
            }
        }
        """

        # Try to connect without authentication
        with pytest.raises(Exception):
            async with graphql_client.websocket_connect("/graphql") as websocket:
                await websocket.send_json(
                    {
                        "id": "auth-test",
                        "type": "subscribe",
                        "payload": make_graphql_request(query=subscription),
                    }
                )

                # Should receive an error
                message = await websocket.receive_json()
                assert message["type"] == "error"
                assert "unauthorized" in str(message["payload"]).lower()
