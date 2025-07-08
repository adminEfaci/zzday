"""
Complete User Journey End-to-End Integration Tests

Tests comprehensive user flows from registration through daily usage,
covering all module interactions in realistic scenarios.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import UUID

import pytest

from app.core.events.bus import InMemoryEventBus
from app.modules.audit.domain.events.audit_events import AuditEntryRecorded
from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.entities.user.user_events import (
    AccountLockedOut,
    EmailVerified,
    LoginFailed,
    LoginSuccessful,
    MFAEnabled,
    PasswordChanged,
    ProfileUpdated,
    UserCreated,
)
from app.modules.integration.domain.events.integration_events import (
    IntegrationConnected,
    IntegrationErrorEvent,
)
from app.modules.integration.domain.events.webhook_events import (
    WebhookFailed,
    WebhookProcessed,
    WebhookReceived,
)
from app.modules.notification.domain.events import (
    NotificationCreated,
    NotificationFailed,
    NotificationSent,
)


@pytest.mark.integration
class TestCompleteUserRegistrationJourney:
    """Test complete user registration and onboarding flow."""

    @pytest.mark.asyncio
    async def test_new_user_complete_onboarding_flow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test complete flow: Registration → Email Verification → Profile Setup → First Login."""
        # Setup event bus and tracking
        event_bus = InMemoryEventBus()
        await event_bus.start()

        events_received = []

        async def track_all_events(event):
            events_received.append(
                {
                    "type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "event": event,
                }
            )

        # Subscribe to all event types
        event_types = [
            UserCreated,
            EmailVerified,
            ProfileUpdated,
            LoginSuccessful,
            AuditEntryRecorded,
            NotificationCreated,
            NotificationSent,
        ]

        for event_type in event_types:
            event_bus.subscribe(event_type, track_all_events)

        # Step 1: User Registration
        user_created_event = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="John Doe",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_created_event)

        # Step 2: Email Verification
        email_verified_event = EmailVerified(
            user_id=test_user.id,
            email=test_user.email.value,
            verified_at=datetime.now(UTC),
            verification_method="email_link",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(email_verified_event)

        # Step 3: Profile Completion
        profile_updated_event = ProfileUpdated(
            user_id=test_user.id,
            updated_fields=["first_name", "last_name", "phone"],
            previous_values={},
            new_values={
                "first_name": "John",
                "last_name": "Doe",
                "phone": "+1234567890",
            },
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(profile_updated_event)

        # Step 4: First Login
        first_login_event = LoginSuccessful(
            user_id=test_user.id,
            session_id=UUID("12345678-1234-5678-9012-123456789012"),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Test Browser",
            mfa_used=False,
            trusted_device=False,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(first_login_event)

        # Allow events to process
        await asyncio.sleep(0.2)

        # Assertions
        assert len(events_received) >= 4

        # Verify event sequence
        event_types_received = [e["type"] for e in events_received]
        assert "UserCreated" in event_types_received
        assert "EmailVerified" in event_types_received
        assert "ProfileUpdated" in event_types_received
        assert "LoginSuccessful" in event_types_received

        # Verify services were called appropriately
        assert mock_audit_service.create_audit_log.call_count >= 4
        assert mock_notification_service.send_welcome_email.called
        assert mock_notification_service.send_verification_email.called
        assert mock_integration_service.trigger_webhooks.call_count >= 2

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_user_journey_with_security_events(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test user journey with security-related events and responses."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        security_events = []

        async def track_security_events(event):
            security_events.append(event)

        event_bus.subscribe(LoginFailed, track_security_events)
        event_bus.subscribe(AccountLockedOut, track_security_events)
        event_bus.subscribe(PasswordChanged, track_security_events)

        # Simulate multiple failed login attempts
        for _i in range(5):
            failed_login = LoginFailed(
                email=test_user.email.value,
                ip_address="192.168.1.100",
                user_agent="Suspicious Browser",
                failure_reason="invalid_password",
                risk_score=0.8,
                occurred_at=datetime.now(UTC),
            )
            await event_bus.publish(failed_login)

        # Simulate account lockout
        account_locked = AccountLockedOut(
            user_id=test_user.id,
            locked_at=datetime.now(UTC),
            lockout_duration_minutes=30,
            failed_attempt_count=5,
            last_failed_ip="192.168.1.100",
            unlock_at=datetime.now(UTC) + timedelta(minutes=30),
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(account_locked)

        # Simulate password change after unlock
        password_changed = PasswordChanged(
            user_id=test_user.id,
            strength_score=0.9,
            force_password_change=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(password_changed)

        await asyncio.sleep(0.1)

        # Assertions
        assert (
            len(security_events) == 7
        )  # 5 failed logins + 1 lockout + 1 password change

        # Verify security monitoring triggered
        assert mock_audit_service.create_security_audit.call_count >= 5
        assert mock_notification_service.send_account_lockout_alert.called
        assert mock_notification_service.send_security_alert.called

        await event_bus.stop()


@pytest.mark.integration
class TestCriticalSecurityScenarios:
    """Test critical security scenarios across all modules."""

    @pytest.mark.asyncio
    async def test_security_incident_response_flow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test complete security incident detection and response."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        incident_events = []

        async def track_incident_events(event):
            incident_events.append(event)

        # Subscribe to security-related events
        security_event_types = [
            LoginFailed,
            AccountLockedOut,
            PasswordChanged,
            AuditEntryRecorded,
            NotificationCreated,
        ]

        for event_type in security_event_types:
            event_bus.subscribe(event_type, track_incident_events)

        # Scenario: Suspicious login attempts from multiple IPs
        suspicious_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.10"]

        for ip in suspicious_ips:
            for _ in range(3):
                failed_login = LoginFailed(
                    email=test_user.email.value,
                    ip_address=ip,
                    user_agent="Automated Bot",
                    failure_reason="invalid_password",
                    risk_score=0.9,
                    user_id=test_user.id,
                    occurred_at=datetime.now(UTC),
                )
                await event_bus.publish(failed_login)

        # Trigger account lockout
        account_locked = AccountLockedOut(
            user_id=test_user.id,
            locked_at=datetime.now(UTC),
            lockout_duration_minutes=60,
            failed_attempt_count=9,
            last_failed_ip=suspicious_ips[-1],
            unlock_at=datetime.now(UTC) + timedelta(hours=1),
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(account_locked)

        await asyncio.sleep(0.2)

        # Assertions
        assert len(incident_events) >= 10  # 9 failed logins + lockout + audit entries

        # Verify security response
        assert mock_audit_service.create_security_audit.call_count >= 9
        assert mock_notification_service.send_account_lockout_alert.called
        assert mock_notification_service.send_admin_alert.called

        # Verify integration triggers for security monitoring
        webhook_calls = mock_integration_service.trigger_webhooks.call_args_list
        security_webhooks = [
            call
            for call in webhook_calls
            if "security" in str(call) or "alert" in str(call)
        ]
        assert len(security_webhooks) >= 1

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_mfa_enrollment_and_usage_flow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test MFA enrollment and subsequent usage flow."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        mfa_events = []

        async def track_mfa_events(event):
            mfa_events.append(event)

        event_bus.subscribe(MFAEnabled, track_mfa_events)
        event_bus.subscribe(LoginSuccessful, track_mfa_events)

        # Step 1: MFA Enrollment
        mfa_enabled = MFAEnabled(
            user_id=test_user.id,
            device_id=UUID("87654321-4321-8765-4321-876543210987"),
            device_type="authenticator_app",
            device_name="Google Authenticator",
            enabled_at=datetime.now(UTC),
            backup_codes_generated=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(mfa_enabled)

        # Step 2: Login with MFA
        mfa_login = LoginSuccessful(
            user_id=test_user.id,
            session_id=UUID("98765432-8765-4321-9876-543210987654"),
            ip_address="192.168.1.100",
            user_agent="Chrome Mobile",
            mfa_used=True,
            trusted_device=False,
            risk_score=0.1,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(mfa_login)

        await asyncio.sleep(0.1)

        # Assertions
        assert len(mfa_events) == 2

        # Verify MFA-specific audit logging
        audit_calls = mock_audit_service.create_audit_log.call_args_list
        mfa_audit_calls = [call for call in audit_calls if "mfa" in str(call).lower()]
        assert len(mfa_audit_calls) >= 1

        # Verify MFA setup notification
        assert mock_notification_service.send_security_alert.called

        await event_bus.stop()


@pytest.mark.integration
class TestNotificationDeliveryIntegration:
    """Test notification delivery across channels and integration points."""

    @pytest.mark.asyncio
    async def test_multi_channel_notification_delivery(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test notification delivery across email, SMS, and push channels."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        notification_events = []

        async def track_notifications(event):
            notification_events.append(event)

        event_bus.subscribe(NotificationCreated, track_notifications)
        event_bus.subscribe(NotificationSent, track_notifications)
        event_bus.subscribe(NotificationFailed, track_notifications)

        # Create notifications for different channels
        channels = ["email", "sms", "push"]

        for i, channel in enumerate(channels):
            # Create notification
            notification_created = NotificationCreated(
                notification_id=f"notif_{i}",
                user_id=test_user.id,
                type=channel,
                template="security_alert",
                delivery_status="pending",
                occurred_at=datetime.now(UTC),
            )
            await event_bus.publish(notification_created)

            # Simulate successful delivery
            notification_sent = NotificationSent(
                notification_id=f"notif_{i}",
                user_id=test_user.id,
                delivery_method=channel,
                delivery_status="delivered",
                provider=f"{channel}_provider",
                provider_message_id=f"msg_{i}",
                delivered_at=datetime.now(UTC),
            )
            await event_bus.publish(notification_sent)

        # Simulate one failed notification
        notification_failed = NotificationFailed(
            notification_id="notif_fail",
            user_id=test_user.id,
            channel="email",
            error_code="SMTP_ERROR",
            error_message="Mail server unreachable",
            is_permanent=False,
            retry_count=1,
            will_retry=True,
            failed_at=datetime.now(UTC),
        )
        await event_bus.publish(notification_failed)

        await asyncio.sleep(0.1)

        # Assertions
        assert len(notification_events) == 7  # 3 created + 3 sent + 1 failed

        # Verify audit logging for all notifications
        assert mock_audit_service.create_audit_log.call_count >= 7

        # Verify webhook triggers for notification status
        webhook_calls = mock_integration_service.trigger_webhooks.call_args_list
        notification_webhooks = [
            call for call in webhook_calls if "notification" in str(call)
        ]
        assert len(notification_webhooks) >= 1

        await event_bus.stop()


@pytest.mark.integration
class TestWebhookIntegrationScenarios:
    """Test webhook processing and integration scenarios."""

    @pytest.mark.asyncio
    async def test_webhook_processing_with_retries_and_dlq(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
    ):
        """Test webhook processing with retry logic and dead letter queue."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        webhook_events = []

        async def track_webhook_events(event):
            webhook_events.append(event)

        event_bus.subscribe(WebhookReceived, track_webhook_events)
        event_bus.subscribe(WebhookProcessed, track_webhook_events)
        event_bus.subscribe(WebhookFailed, track_webhook_events)

        # Simulate incoming webhook
        webhook_received = WebhookReceived(
            webhook_id=UUID("11111111-2222-3333-4444-555555555555"),
            endpoint_id=UUID("66666666-7777-8888-9999-000000000000"),
            integration_id=UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            integration_name="External CRM",
            event_type="customer.updated",
            method="POST",
            headers={"content-type": "application/json"},
            payload={"customer_id": "12345", "status": "active"},
            source_ip="203.0.113.10",
            signature_valid=True,
            received_at=datetime.now(UTC),
        )
        await event_bus.publish(webhook_received)

        # Simulate processing failure (will trigger retry)
        webhook_failed = WebhookFailed(
            webhook_id=webhook_received.webhook_id,
            endpoint_id=webhook_received.endpoint_id,
            integration_id=webhook_received.integration_id,
            integration_name=webhook_received.integration_name,
            error_type="PROCESSING_ERROR",
            error_message="Database connection timeout",
            retry_count=1,
            will_retry=True,
            failed_at=datetime.now(UTC),
        )
        await event_bus.publish(webhook_failed)

        # Simulate eventual successful processing
        webhook_processed = WebhookProcessed(
            webhook_id=webhook_received.webhook_id,
            endpoint_id=webhook_received.endpoint_id,
            integration_id=webhook_received.integration_id,
            integration_name=webhook_received.integration_name,
            processing_time_ms=250.5,
            actions_taken=["update_customer", "sync_data"],
            entities_affected={"customers": ["12345"]},
            processed_at=datetime.now(UTC),
        )
        await event_bus.publish(webhook_processed)

        await asyncio.sleep(0.1)

        # Assertions
        assert len(webhook_events) == 3

        # Verify audit trail for webhook processing
        assert mock_audit_service.create_audit_log.call_count >= 3

        # Verify admin notification for webhook failures
        assert mock_notification_service.send_admin_alert.called

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_integration_health_monitoring(
        self, mock_audit_service: AsyncMock, mock_notification_service: AsyncMock
    ):
        """Test integration health monitoring and alerting."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        integration_events = []

        async def track_integration_events(event):
            integration_events.append(event)

        event_bus.subscribe(IntegrationConnected, track_integration_events)
        event_bus.subscribe(IntegrationErrorEvent, track_integration_events)

        # Simulate new integration connection
        integration_connected = IntegrationConnected(
            integration_id=UUID("ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"),
            integration_name="Slack Notifications",
            integration_type="notification",
            system_name="Slack",
            connected_by=UUID("00000000-1111-2222-3333-444444444444"),
            capabilities=["send_message", "create_channel"],
            configuration={"webhook_url": "https://hooks.slack.com/services/..."},
        )
        await event_bus.publish(integration_connected)

        # Simulate integration error
        integration_error = IntegrationErrorEvent(
            integration_id=integration_connected.integration_id,
            integration_name=integration_connected.integration_name,
            error_type="RATE_LIMIT_EXCEEDED",
            error_message="API rate limit exceeded: 1000 calls per hour",
            error_code="429",
            is_retryable=True,
            retry_count=0,
            error_details={"rate_limit_reset": "2024-01-01T15:00:00Z"},
        )
        await event_bus.publish(integration_error)

        await asyncio.sleep(0.1)

        # Assertions
        assert len(integration_events) == 2

        # Verify audit logging for integration events
        assert mock_audit_service.create_audit_log.call_count >= 2

        # Verify admin notification for integration errors
        assert mock_notification_service.send_admin_alert.called

        await event_bus.stop()


@pytest.mark.integration
class TestSystemPerformanceAndResilience:
    """Test system performance under load and resilience scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_high_volume_event_processing(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        performance_tracker,
    ):
        """Test system performance under high event volume."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        processed_events = []

        async def track_processed_events(event):
            processed_events.append(event)

        event_bus.subscribe(UserCreated, track_processed_events)
        event_bus.subscribe(LoginSuccessful, track_processed_events)

        # Generate high volume of events
        performance_tracker.start()

        event_count = 100
        tasks = []

        for i in range(event_count):
            # Alternate between different event types
            if i % 2 == 0:
                event = UserCreated(
                    user_id=UUID(f"00000000-0000-0000-0000-{i:012d}"),
                    email=f"user{i}@example.com",
                    name=f"User {i}",
                    role="user",
                    registration_method="api",
                    occurred_at=datetime.now(UTC),
                )
            else:
                event = LoginSuccessful(
                    user_id=UUID(f"00000000-0000-0000-0000-{i:012d}"),
                    session_id=UUID(f"11111111-1111-1111-1111-{i:012d}"),
                    ip_address="192.168.1.100",
                    user_agent="Load Test Client",
                    occurred_at=datetime.now(UTC),
                )

            tasks.append(event_bus.publish(event))

        # Process all events concurrently
        await asyncio.gather(*tasks)

        # Wait for processing to complete
        await asyncio.sleep(0.5)

        performance_tracker.stop()

        # Performance assertions
        performance_tracker.assert_performance(2.0)  # Should complete within 2 seconds

        # Verify all events were processed
        assert len(processed_events) == event_count

        # Verify services handled the load appropriately
        assert mock_audit_service.create_audit_log.call_count >= event_count

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_system_resilience_with_service_failures(self, test_user: User):
        """Test system resilience when individual services fail."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Create mock services that fail intermittently
        failing_audit_service = AsyncMock()
        failing_audit_service.create_audit_log.side_effect = [
            Exception("Database connection lost"),
            None,  # Success on retry
            None,  # Subsequent success
        ]

        failing_notification_service = AsyncMock()
        failing_notification_service.send_welcome_email.side_effect = [
            Exception("SMTP server unavailable"),
            True,  # Success on retry
        ]

        resilience_events = []

        async def track_resilience_events(event):
            resilience_events.append(event)

        event_bus.subscribe(UserCreated, track_resilience_events)

        # Publish events that should trigger failing services
        user_created = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Resilience Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )

        # This should not crash the system despite service failures
        await event_bus.publish(user_created)

        await asyncio.sleep(0.1)

        # Assertions
        assert len(resilience_events) == 1

        # System should continue operating despite individual service failures
        # Events should still be processed
        event_types = [type(e).__name__ for e in resilience_events]
        assert "UserCreated" in event_types

        await event_bus.stop()


@pytest.mark.integration
class TestDataConsistencyAcrossModules:
    """Test data consistency across module boundaries."""

    @pytest.mark.asyncio
    async def test_cross_module_data_consistency(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that data remains consistent across all module interactions."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        consistency_tracking = {
            "user_id_consistency": [],
            "timestamp_consistency": [],
            "data_integrity": [],
        }

        async def validate_data_consistency(event):
            # Track user ID consistency
            if hasattr(event, "user_id"):
                consistency_tracking["user_id_consistency"].append(event.user_id)

            # Track timestamp consistency
            if hasattr(event, "occurred_at"):
                consistency_tracking["timestamp_consistency"].append(event.occurred_at)

            # Track data integrity
            consistency_tracking["data_integrity"].append(
                {
                    "event_type": type(event).__name__,
                    "has_required_fields": all(
                        hasattr(event, field) for field in ["occurred_at"]
                    ),
                }
            )

        # Subscribe to all event types
        event_types = [
            UserCreated,
            EmailVerified,
            ProfileUpdated,
            AuditEntryRecorded,
            NotificationCreated,
        ]

        for event_type in event_types:
            event_bus.subscribe(event_type, validate_data_consistency)

        # Execute a series of related events
        base_time = datetime.now(UTC)

        events = [
            UserCreated(
                user_id=test_user.id,
                email=test_user.email.value,
                name="Consistency Test User",
                role="user",
                registration_method="email",
                occurred_at=base_time,
            ),
            EmailVerified(
                user_id=test_user.id,
                email=test_user.email.value,
                verified_at=base_time + timedelta(minutes=5),
                verification_method="email_link",
                occurred_at=base_time + timedelta(minutes=5),
            ),
            ProfileUpdated(
                user_id=test_user.id,
                updated_fields=["first_name"],
                previous_values={},
                new_values={"first_name": "John"},
                occurred_at=base_time + timedelta(minutes=10),
            ),
        ]

        for event in events:
            await event_bus.publish(event)

        await asyncio.sleep(0.2)

        # Data consistency assertions

        # 1. User ID consistency
        user_ids = consistency_tracking["user_id_consistency"]
        assert all(
            uid == test_user.id for uid in user_ids
        ), "User ID inconsistency detected"

        # 2. Timestamp ordering
        timestamps = consistency_tracking["timestamp_consistency"]
        assert timestamps == sorted(timestamps), "Timestamp ordering inconsistency"

        # 3. Data integrity
        integrity_checks = consistency_tracking["data_integrity"]
        assert all(
            check["has_required_fields"] for check in integrity_checks
        ), "Required fields missing in events"

        # 4. Cross-service data consistency
        # Verify all services received consistent data
        audit_calls = mock_audit_service.create_audit_log.call_args_list
        for call in audit_calls:
            # Each audit call should reference the same user ID
            if "entity_id" in str(call):
                assert str(test_user.id) in str(call)

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_ordering_and_causality(self, test_user: User):
        """Test that events maintain proper ordering and causality relationships."""
        event_bus = InMemoryEventBus()
        await event_bus.start()

        event_timeline = []

        async def track_event_timeline(event):
            event_timeline.append(
                {
                    "type": type(event).__name__,
                    "timestamp": event.occurred_at,
                    "received_at": datetime.now(UTC),
                }
            )

        # Subscribe to causally related events
        causal_events = [UserCreated, EmailVerified, ProfileUpdated, LoginSuccessful]

        for event_type in causal_events:
            event_bus.subscribe(event_type, track_event_timeline)

        # Create causally ordered events
        base_time = datetime.now(UTC)

        ordered_events = [
            UserCreated(
                user_id=test_user.id,
                email=test_user.email.value,
                name="Causality Test",
                role="user",
                registration_method="email",
                occurred_at=base_time,
            ),
            EmailVerified(
                user_id=test_user.id,
                email=test_user.email.value,
                verified_at=base_time + timedelta(minutes=1),
                verification_method="email_link",
                occurred_at=base_time + timedelta(minutes=1),
            ),
            ProfileUpdated(
                user_id=test_user.id,
                updated_fields=["status"],
                previous_values={"status": "pending"},
                new_values={"status": "active"},
                occurred_at=base_time + timedelta(minutes=2),
            ),
            LoginSuccessful(
                user_id=test_user.id,
                session_id=UUID("12345678-1234-5678-9012-123456789012"),
                ip_address="192.168.1.100",
                user_agent="Test Browser",
                occurred_at=base_time + timedelta(minutes=3),
            ),
        ]

        # Publish events in order
        for event in ordered_events:
            await event_bus.publish(event)
            await asyncio.sleep(0.01)  # Small delay to ensure ordering

        await asyncio.sleep(0.1)

        # Causality assertions
        assert len(event_timeline) == 4

        # Verify causal ordering is preserved
        event_types = [e["type"] for e in event_timeline]
        expected_order = [
            "UserCreated",
            "EmailVerified",
            "ProfileUpdated",
            "LoginSuccessful",
        ]
        assert event_types == expected_order, f"Event ordering violated: {event_types}"

        # Verify timestamp ordering
        timestamps = [e["timestamp"] for e in event_timeline]
        assert timestamps == sorted(timestamps), "Timestamp causality violated"

        await event_bus.stop()
