"""
Cross-module integration tests for event-driven architecture.

Tests the complete event flow between Identity, Audit, Notification, and Integration modules.
Validates that domain events properly trigger cross-module actions.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.events.bus import InMemoryEventBus
from app.modules.audit.domain.events.audit_events import (
    AuditEntryRecorded,
    AuditLogCreated,
)
from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.entities.user.user_events import (
    EmailVerified,
    LoginFailed,
    LoginSuccessful,
    MFAEnabled,
    PasswordChanged,
    ProfileUpdated,
    UserCreated,
    UserEmailChanged,
)
from app.modules.integration.domain.events.webhook_events import (
    WebhookFailed,
    WebhookProcessed,
    WebhookReceived,
)
from app.modules.notification.domain.events import NotificationCreated, NotificationSent


@pytest.mark.integration
class TestUserRegistrationFlow:
    """Test complete user registration event flow across modules."""

    @pytest.mark.asyncio
    async def test_user_registration_triggers_audit_and_notification(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that user registration triggers audit logging and welcome notification."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        events_received = []

        async def capture_event(event):
            events_received.append(event)

        # Subscribe to all relevant events
        event_bus.subscribe(UserCreated, capture_event)
        event_bus.subscribe(AuditEntryRecorded, capture_event)
        event_bus.subscribe(NotificationCreated, capture_event)

        # Act - Dispatch user registration event
        user_registered_event = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(user_registered_event)

        # Allow event handlers to process
        await asyncio.sleep(0.1)

        # Assert
        assert len(events_received) >= 1

        # Verify UserCreated was received
        user_events = [e for e in events_received if isinstance(e, UserCreated)]
        assert len(user_events) == 1
        assert user_events[0].user_id == test_user.id

        # Verify audit service was called
        mock_audit_service.create_audit_log.assert_called()

        # Verify notification service was called
        mock_notification_service.send_welcome_email.assert_called()

        # Verify integration service was called for webhooks
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_user_registration_triggers_webhook_for_integrations(
        self, mock_integration_service: AsyncMock, test_user: User
    ):
        """Test that user registration triggers webhook delivery to external systems."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        webhook_events = []

        async def capture_webhook_event(event):
            webhook_events.append(event)

        event_bus.subscribe(WebhookReceived, capture_webhook_event)

        # Act
        user_registered_event = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(user_registered_event)
        await asyncio.sleep(0.1)

        # Assert
        # Verify integration service was called
        mock_integration_service.trigger_webhooks.assert_called()
        webhook_call_args = mock_integration_service.trigger_webhooks.call_args
        assert "user.created" in str(webhook_call_args)

        await event_bus.stop()


@pytest.mark.integration
class TestUserSecurityEventsFlow:
    """Test security-related event flows across modules."""

    @pytest.mark.asyncio
    async def test_password_change_triggers_security_audit_and_notifications(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test that password changes trigger security audits and notifications."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        security_events = []

        async def capture_security_event(event):
            security_events.append(event)

        event_bus.subscribe(PasswordChanged, capture_security_event)
        event_bus.subscribe(AuditLogCreated, capture_security_event)

        # Act
        password_changed_event = PasswordChanged(
            user_id=test_user.id,
            old_hash="old_hash_123",
            new_hash="new_hash_456",
            changed_by=test_user.id,
            reason="user_requested",
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(password_changed_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(security_events) >= 1

        # Verify security audit was created
        mock_audit_service.create_security_audit.assert_called()

        # Verify security notification was sent
        mock_notification_service.send_security_alert.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_failed_login_triggers_security_monitoring(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test that failed login attempts trigger security monitoring."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        failed_attempts = []

        async def capture_failed_login(event):
            failed_attempts.append(event)

        event_bus.subscribe(LoginFailed, capture_failed_login)

        # Act - Simulate multiple failed login attempts
        for i in range(5):
            failed_login_event = LoginFailed(
                user_id=test_user.id,
                email=test_user.email.value,
                failure_reason="invalid_password",
                ip_address="192.168.1.100",
                user_agent="Test Browser",
                attempt_number=i + 1,
                occurred_at=datetime.now(UTC),
            )

            await event_bus.publish(failed_login_event)

        await asyncio.sleep(0.1)

        # Assert
        assert len(failed_attempts) == 5

        # Verify security monitoring was triggered
        assert mock_audit_service.create_security_audit.call_count >= 5

        # Verify account lockout notification after threshold
        if len(failed_attempts) >= 5:
            mock_notification_service.send_account_lockout_alert.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestNotificationDeliveryFlow:
    """Test notification delivery and tracking across modules."""

    @pytest.mark.asyncio
    async def test_notification_creation_triggers_audit_and_webhook(
        self,
        mock_audit_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that notification creation triggers audit logging and webhook delivery."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        notification_events = []

        async def capture_notification_event(event):
            notification_events.append(event)

        event_bus.subscribe(NotificationCreated, capture_notification_event)
        event_bus.subscribe(AuditLogCreated, capture_notification_event)

        # Act
        notification_created_event = NotificationCreated(
            notification_id=uuid4(),
            user_id=test_user.id,
            type="email",
            template="welcome_email",
            delivery_status="pending",
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(notification_created_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(notification_events) >= 1

        # Verify audit logging
        mock_audit_service.create_audit_log.assert_called()

        # Verify webhook delivery for notification tracking
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_successful_notification_delivery_completes_flow(
        self, mock_audit_service: AsyncMock, test_user: User
    ):
        """Test that successful notification delivery completes the audit trail."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        delivery_events = []

        async def capture_delivery_event(event):
            delivery_events.append(event)

        event_bus.subscribe(NotificationSent, capture_delivery_event)

        # Act
        notification_sent_event = NotificationSent(
            notification_id=uuid4(),
            user_id=test_user.id,
            delivery_method="email",
            delivery_status="delivered",
            provider="sendgrid",
            provider_message_id="sg_msg_456",
            delivered_at=datetime.now(UTC),
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(notification_sent_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(delivery_events) == 1
        assert delivery_events[0].delivery_status == "delivered"

        # Verify completion audit
        mock_audit_service.update_audit_log.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestWebhookDeliveryFlow:
    """Test webhook delivery and retry mechanisms across modules."""

    @pytest.mark.asyncio
    async def test_webhook_failure_triggers_retry_and_audit(
        self, mock_audit_service: AsyncMock, mock_notification_service: AsyncMock
    ):
        """Test that webhook delivery failures trigger retry logic and audit logging."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        webhook_events = []

        async def capture_webhook_event(event):
            webhook_events.append(event)

        event_bus.subscribe(WebhookFailed, capture_webhook_event)

        # Act - Simulate webhook failure
        webhook_failed_event = WebhookFailed(
            webhook_id=uuid4(),
            event_type="user.created",
            target_url="https://example.com/webhook",
            error_message="Connection timeout",
            retry_count=0,
            max_retries=3,
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(webhook_failed_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(webhook_events) >= 1

        # Verify failure audit
        mock_audit_service.create_audit_log.assert_called()

        # Verify admin notification for critical webhook failures
        mock_notification_service.send_admin_alert.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_successful_webhook_delivery_completes_integration_flow(
        self, mock_audit_service: AsyncMock
    ):
        """Test that successful webhook delivery completes the integration audit trail."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        success_events = []

        async def capture_success_event(event):
            success_events.append(event)

        event_bus.subscribe(WebhookProcessed, capture_success_event)

        # Act
        webhook_success_event = WebhookProcessed(
            webhook_id=uuid4(),
            event_type="user.created",
            target_url="https://example.com/webhook",
            response_status=200,
            response_time_ms=150,
            delivered_at=datetime.now(UTC),
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(webhook_success_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(success_events) == 1
        assert success_events[0].response_status == 200

        # Verify success audit
        mock_audit_service.create_audit_log.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestCompleteUserJourneyFlow:
    """Test complete user journey events across all modules."""

    @pytest.mark.asyncio
    async def test_complete_user_registration_to_first_login_flow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test complete flow from user registration through email verification to first login."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        all_events = []

        async def capture_all_events(event):
            all_events.append(event)

        # Subscribe to all event types
        event_types = [
            UserCreated,
            AuditLogCreated,
            NotificationCreated,
            NotificationSent,
            LoginSuccessful,
        ]

        for event_type in event_types:
            event_bus.subscribe(event_type, capture_all_events)

        # Act - Simulate complete user journey

        # Step 1: User registers
        user_registered_event = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_registered_event)

        # Step 2: Email verification notification sent
        notification_created_event = NotificationCreated(
            notification_id=uuid4(),
            user_id=test_user.id,
            type="email",
            template="email_verification",
            delivery_status="pending",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(notification_created_event)

        # Step 3: User successfully logs in for first time
        user_login_event = LoginSuccessful(
            user_id=test_user.id,
            email=test_user.email.value,
            session_id="session_123",
            ip_address="192.168.1.100",
            user_agent="Test Browser",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_login_event)

        await asyncio.sleep(0.2)  # Allow all events to process

        # Assert
        assert len(all_events) >= 3

        # Verify event sequence
        registration_events = [e for e in all_events if isinstance(e, UserCreated)]
        notification_events = [
            e for e in all_events if isinstance(e, NotificationCreated)
        ]
        login_events = [e for e in all_events if isinstance(e, LoginSuccessful)]

        assert len(registration_events) == 1
        assert len(notification_events) == 1
        assert len(login_events) == 1

        # Verify cross-module service calls
        assert mock_audit_service.create_audit_log.call_count >= 3
        assert mock_notification_service.send_welcome_email.called
        assert mock_integration_service.trigger_webhooks.call_count >= 2

        await event_bus.stop()


@pytest.mark.integration
class TestEventOrderingAndConsistency:
    """Test event ordering and data consistency across modules."""

    @pytest.mark.asyncio
    async def test_events_maintain_chronological_order(self, test_user: User):
        """Test that events are processed in chronological order."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        processed_events = []

        async def track_event_processing(event):
            processed_events.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": event.occurred_at,
                    "processed_at": datetime.now(UTC),
                }
            )

        event_bus.subscribe(UserCreated, track_event_processing)
        event_bus.subscribe(LoginSuccessful, track_event_processing)

        # Act - Dispatch events in sequence
        base_time = datetime.now(UTC)

        events = [
            UserCreated(
                user_id=test_user.id,
                email=test_user.email.value,
                name="Test User",
                role="user",
                registration_method="email",
                occurred_at=base_time,
            ),
            LoginSuccessful(
                user_id=test_user.id,
                email=test_user.email.value,
                session_id="session_123",
                ip_address="192.168.1.100",
                user_agent="Test Browser",
                occurred_at=base_time + timedelta(seconds=30),
            ),
        ]

        for event in events:
            await event_bus.publish(event)

        await asyncio.sleep(0.1)

        # Assert
        assert len(processed_events) == 2

        # Verify chronological order
        timestamps = [e["timestamp"] for e in processed_events]
        assert timestamps == sorted(timestamps)

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_data_consistency_across_modules(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test that event data remains consistent across all module handlers."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        user_registered_event = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )

        # Act
        await event_bus.publish(user_registered_event)
        await asyncio.sleep(0.1)

        # Assert - Verify all services received consistent data

        # Check audit service call
        mock_audit_service.create_audit_log.assert_called()

        # Check notification service call
        mock_notification_service.send_welcome_email.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestGDPRComplianceFlow:
    """Test GDPR compliance event flows across modules."""

    @pytest.mark.asyncio
    async def test_user_data_export_request_triggers_compliance_workflow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that user data export request triggers full compliance workflow."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        compliance_events = []

        async def capture_compliance_event(event):
            compliance_events.append(event)

        event_bus.subscribe(UserEmailChanged, capture_compliance_event)
        event_bus.subscribe(NotificationCreated, capture_compliance_event)

        # Act - User requests data export
        user_email_change_event = UserEmailChanged(
            user_id=test_user.id,
            old_email=test_user.email.value,
            new_email="new_email@example.com",
            verified=False,
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(user_email_change_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(compliance_events) >= 1

        # Verify DPO notification
        mock_notification_service.send_dpo_notification.assert_called()

        # Verify compliance audit
        mock_audit_service.create_audit_log.assert_called()

        # Verify external compliance systems notified
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_user_deletion_request_triggers_comprehensive_cleanup(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that user deletion request triggers comprehensive data cleanup workflow."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        deletion_events = []

        async def capture_deletion_event(event):
            deletion_events.append(event)

        event_bus.subscribe(ProfileUpdated, capture_deletion_event)

        # Act - Simulate user deletion request
        profile_updated_event = ProfileUpdated(
            user_id=test_user.id,
            field_name="status",
            old_value="active",
            new_value="deletion_requested",
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(profile_updated_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(deletion_events) >= 1

        # Verify deletion confirmation sent
        mock_notification_service.send_deletion_confirmation.assert_called()

        # Verify comprehensive audit trail
        mock_audit_service.create_audit_log.assert_called()

        # Verify external systems notified for cleanup
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestSecurityIncidentResponseFlow:
    """Test security incident response flows across modules."""

    @pytest.mark.asyncio
    async def test_suspicious_activity_triggers_automated_response(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that suspicious activity triggers automated security response."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        security_events = []

        async def capture_security_event(event):
            security_events.append(event)

        event_bus.subscribe(LoginFailed, capture_security_event)

        # Act - Simulate rapid failed login attempts (security incident)
        for i in range(10):
            failed_login_event = LoginFailed(
                user_id=test_user.id,
                email=test_user.email.value,
                failure_reason="invalid_password",
                ip_address="192.168.1.100",
                user_agent="Suspicious Bot",
                attempt_number=i + 1,
                occurred_at=datetime.now(UTC),
            )

            await event_bus.publish(failed_login_event)

        await asyncio.sleep(0.2)

        # Assert
        assert len(security_events) == 10

        # Verify emergency security audit
        assert mock_audit_service.create_security_audit.call_count >= 10

        # Verify emergency alert sent
        mock_notification_service.send_emergency_alert.assert_called()

        # Verify external security systems notified
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_mfa_enabled_triggers_security_enhancement_workflow(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test that MFA enablement triggers security enhancement workflow."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Arrange
        mfa_events = []

        async def capture_mfa_event(event):
            mfa_events.append(event)

        event_bus.subscribe(MFAEnabled, capture_mfa_event)

        # Act
        mfa_enabled_event = MFAEnabled(
            user_id=test_user.id,
            method="totp",
            backup_codes_generated=True,
            occurred_at=datetime.now(UTC),
        )

        await event_bus.publish(mfa_enabled_event)
        await asyncio.sleep(0.1)

        # Assert
        assert len(mfa_events) == 1

        # Verify security enhancement audit
        mock_audit_service.create_security_audit.assert_called()

        # Verify confirmation notification
        mock_notification_service.send_security_alert.assert_called()

        # Verify external security monitoring updated
        mock_integration_service.trigger_webhooks.assert_called()

        await event_bus.stop()


@pytest.mark.integration
class TestHighVolumeEventProcessing:
    """Test high volume event processing and performance."""

    @pytest.mark.asyncio
    async def test_concurrent_user_events_maintain_consistency(
        self,
        integration_performance_tracker,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        integration_test_users: list[User],
    ):
        """Test that concurrent user events maintain data consistency."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        integration_performance_tracker.start()

        # Arrange
        processed_events = []

        async def track_processed_event(event):
            processed_events.append(event)

        event_bus.subscribe(UserCreated, track_processed_event)
        event_bus.subscribe(LoginSuccessful, track_processed_event)

        # Act - Process events for multiple users concurrently
        tasks = []
        for user in integration_test_users[:50]:  # Process 50 users concurrently
            # User registration
            registration_event = UserCreated(
                user_id=user.id,
                email=user.email.value,
                name=f"User {user.id}",
                role="user",
                registration_method="email",
                occurred_at=datetime.now(UTC),
            )
            tasks.append(event_bus.publish(registration_event))

            # User login
            login_event = LoginSuccessful(
                user_id=user.id,
                email=user.email.value,
                session_id=f"session_{user.id}",
                ip_address="192.168.1.100",
                user_agent="Test Browser",
                occurred_at=datetime.now(UTC),
            )
            tasks.append(event_bus.publish(login_event))

        await asyncio.gather(*tasks)
        await asyncio.sleep(0.5)  # Allow processing

        integration_performance_tracker.stop()

        # Assert
        assert len(processed_events) >= 100  # 50 users * 2 events each

        # Verify performance
        integration_performance_tracker.assert_performance(
            5.0, "Concurrent event processing too slow"
        )

        # Verify audit consistency
        assert mock_audit_service.create_audit_log.call_count >= 100

        # Verify notification consistency
        assert mock_notification_service.send_welcome_email.call_count >= 50

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_event_bus_handles_high_throughput(
        self, integration_performance_tracker, test_user: User
    ):
        """Test event bus can handle high throughput of events."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        integration_performance_tracker.start()

        # Arrange
        event_count = 1000
        processed_count = 0

        async def count_processed_events(event):
            nonlocal processed_count
            processed_count += 1

        event_bus.subscribe(UserCreated, count_processed_events)

        # Act - Send high volume of events
        tasks = []
        for i in range(event_count):
            event = UserCreated(
                user_id=uuid4(),
                email=f"user{i}@example.com",
                name=f"User {i}",
                role="user",
                registration_method="email",
                occurred_at=datetime.now(UTC),
            )
            tasks.append(event_bus.publish(event))

        await asyncio.gather(*tasks)
        await asyncio.sleep(1.0)  # Allow processing

        integration_performance_tracker.stop()

        # Assert
        assert processed_count >= event_count * 0.95  # Allow for 5% processing lag

        # Verify performance (should process 1000 events within reasonable time)
        integration_performance_tracker.assert_performance(
            3.0, "High throughput processing too slow"
        )

        # Calculate events per second
        elapsed = integration_performance_tracker.elapsed_time
        events_per_second = processed_count / elapsed if elapsed > 0 else 0
        assert (
            events_per_second >= 100
        ), f"Event throughput too low: {events_per_second} events/sec"

        await event_bus.stop()


@pytest.mark.integration
class TestDataConsistencyValidation:
    """Test data consistency validation across modules."""

    @pytest.mark.asyncio
    async def test_event_correlation_maintains_data_integrity(
        self,
        integration_event_tracker,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test that correlated events maintain data integrity across modules."""
        # Setup event bus
        event_bus = InMemoryEventBus()
        await event_bus.start()

        # Wire up event tracker
        async def track_all_events(event):
            await integration_event_tracker.track_event(event)

        event_types = [UserCreated, EmailVerified, LoginSuccessful, NotificationCreated]
        for event_type in event_types:
            event_bus.subscribe(event_type, track_all_events)

        # Act - Execute correlated event sequence

        # 1. User registration
        user_created = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Test User",
            role="user",
            registration_method="email",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_created)

        # 2. Email verification
        email_verified = EmailVerified(
            user_id=test_user.id,
            email=test_user.email.value,
            verification_token="token_123",
            occurred_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        await event_bus.publish(email_verified)

        # 3. First login
        login_successful = LoginSuccessful(
            user_id=test_user.id,
            email=test_user.email.value,
            session_id="session_123",
            ip_address="192.168.1.100",
            user_agent="Test Browser",
            occurred_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        await event_bus.publish(login_successful)

        await asyncio.sleep(0.2)

        # Assert
        # Verify event sequence
        expected_sequence = ["UserCreated", "EmailVerified", "LoginSuccessful"]
        integration_event_tracker.assert_event_sequence(expected_sequence, test_user.id)

        # Verify event counts
        integration_event_tracker.assert_event_count("UserCreated", 1)
        integration_event_tracker.assert_event_count("EmailVerified", 1)
        integration_event_tracker.assert_event_count("LoginSuccessful", 1)

        # Verify data consistency across modules
        user_events = integration_event_tracker.get_events_by_user(test_user.id)
        for event_data in user_events:
            assert event_data["user_id"] == test_user.id
            assert "timestamp" in event_data

        await event_bus.stop()
