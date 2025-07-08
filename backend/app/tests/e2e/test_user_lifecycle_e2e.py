"""
End-to-End User Lifecycle Tests

Complete user lifecycle testing from registration through account management,
testing all modules working together in production-like scenarios.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.events.bus import InMemoryEventBus
from app.modules.audit.domain.events.audit_events import *
from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.entities.user.user_events import *
from app.modules.integration.domain.events.integration_events import *
from app.modules.integration.domain.events.webhook_events import *
from app.modules.notification.domain.events import *


@pytest.mark.e2e
class TestCompleteUserLifecycleE2E:
    """End-to-end tests for complete user lifecycle scenarios."""

    @pytest.mark.asyncio
    async def test_complete_user_lifecycle_from_registration_to_deletion(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        user_factory,
        email_factory,
        performance_tracker,
    ):
        """Test complete user lifecycle: Registration → Usage → Deactivation → Deletion."""

        # Setup comprehensive event tracking
        event_bus = InMemoryEventBus()
        await event_bus.start()

        lifecycle_timeline = []

        async def track_lifecycle_events(event):
            lifecycle_timeline.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": getattr(event, "occurred_at", datetime.now(UTC)),
                    "user_id": getattr(event, "user_id", None),
                    "event_data": event,
                }
            )

        # Subscribe to all lifecycle events
        lifecycle_events = [
            UserCreated,
            UserActivated,
            EmailVerified,
            ProfileUpdated,
            LoginSuccessful,
            PasswordChanged,
            UserSuspended,
            UserDeactivated,
            UserDeleted,
            AuditEntryRecorded,
            NotificationCreated,
            NotificationSent,
        ]

        for event_type in lifecycle_events:
            event_bus.subscribe(event_type, track_lifecycle_events)

        performance_tracker.start()

        # PHASE 1: User Registration and Activation
        test_user = user_factory(
            email=email_factory("lifecycle_test"), is_active=False, is_verified=False
        )

        # 1. User Registration
        user_created = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="Lifecycle Test User",
            role="user",
            registration_method="web_form",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_created)

        # 2. Email Verification
        email_verified = EmailVerified(
            user_id=test_user.id,
            email=test_user.email.value,
            verified_at=datetime.now(UTC),
            verification_method="email_link",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(email_verified)

        # 3. Account Activation
        user_activated = UserActivated(
            user_id=test_user.id,
            activation_method="email_verification",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_activated)

        # PHASE 2: Active Usage Period

        # 4. Profile Completion
        profile_updated = ProfileUpdated(
            user_id=test_user.id,
            updated_fields=["first_name", "last_name", "phone", "preferences"],
            previous_values={},
            new_values={
                "first_name": "John",
                "last_name": "Doe",
                "phone": "+1234567890",
                "preferences": {"theme": "dark", "notifications": True},
            },
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(profile_updated)

        # 5. Multiple Login Sessions
        login_sessions = []
        for i in range(3):
            session_id = uuid4()
            login_sessions.append(session_id)

            login_successful = LoginSuccessful(
                user_id=test_user.id,
                session_id=session_id,
                ip_address=f"192.168.1.{100 + i}",
                user_agent=f"Browser Session {i + 1}",
                is_first_login=(i == 0),
                mfa_used=False,
                trusted_device=(i == 0),
                occurred_at=datetime.now(UTC),
            )
            await event_bus.publish(login_successful)

        # 6. Security Events - Password Change
        password_changed = PasswordChanged(
            user_id=test_user.id,
            strength_score=0.9,
            force_password_change=False,
            password_age_days=90,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(password_changed)

        # 7. MFA Setup
        mfa_enabled = MFAEnabled(
            user_id=test_user.id,
            device_id=uuid4(),
            device_type="authenticator_app",
            device_name="Google Authenticator",
            enabled_at=datetime.now(UTC),
            backup_codes_generated=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(mfa_enabled)

        # PHASE 3: Account Issues and Recovery

        # 8. Security Incident - Failed Logins
        for i in range(3):
            login_failed = LoginFailed(
                email=test_user.email.value,
                ip_address="203.0.113.100",  # Suspicious IP
                user_agent="Automated Scanner",
                failure_reason="invalid_password",
                risk_score=0.8,
                user_id=test_user.id,
                occurred_at=datetime.now(UTC),
            )
            await event_bus.publish(login_failed)

        # 9. Temporary Suspension
        user_suspended = UserSuspended(
            user_id=test_user.id,
            reason="Suspicious activity detected",
            suspended_by=uuid4(),  # Admin user ID
            suspension_expires_at=datetime.now(UTC) + timedelta(hours=24),
            automatic_suspension=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_suspended)

        # 10. Reactivation after Investigation
        user_reactivated = UserReactivated(
            user_id=test_user.id,
            reactivated_by=uuid4(),  # Admin user ID
            reactivation_reason="False positive - user verified identity",
            previous_status="suspended",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_reactivated)

        # PHASE 4: Account Closure

        # 11. User Requests Account Deactivation
        user_deactivated = UserDeactivated(
            user_id=test_user.id,
            reason="User requested account closure",
            deactivated_by=test_user.id,  # Self-deactivation
            data_retention_required=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_deactivated)

        # 12. Data Export (GDPR Compliance)
        user_exported = UserExported(
            user_id=test_user.id,
            export_id=uuid4(),
            export_format="json",
            data_categories=["profile", "activity", "preferences"],
            requested_by=test_user.id,
            gdpr_request=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_exported)

        # 13. Final Deletion (After Retention Period)
        user_deleted = UserDeleted(
            user_id=test_user.id,
            deleted_by=uuid4(),  # System or Admin
            deletion_reason="Retention period expired",
            data_retained=False,
            retained_data_types=[],
            gdpr_compliant=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_deleted)

        # Allow all events to process
        await asyncio.sleep(0.5)

        performance_tracker.stop()

        # COMPREHENSIVE ASSERTIONS

        # 1. Event Timeline Verification
        assert len(lifecycle_timeline) >= 20  # Minimum expected events

        # 2. Verify Event Sequence Integrity
        user_events = [e for e in lifecycle_timeline if e["user_id"] == test_user.id]
        event_types = [e["event_type"] for e in user_events]

        # Key lifecycle milestones should be present
        required_milestones = [
            "UserCreated",
            "EmailVerified",
            "UserActivated",
            "ProfileUpdated",
            "LoginSuccessful",
            "PasswordChanged",
            "MFAEnabled",
            "UserSuspended",
            "UserReactivated",
            "UserDeactivated",
            "UserDeleted",
        ]

        for milestone in required_milestones:
            assert milestone in event_types, f"Missing lifecycle milestone: {milestone}"

        # 3. Audit Trail Completeness
        audit_call_count = mock_audit_service.create_audit_log.call_count
        assert audit_call_count >= len(
            required_milestones
        ), f"Insufficient audit entries: {audit_call_count}"

        # 4. Notification System Integration
        notification_calls = [
            mock_notification_service.send_welcome_email.call_count,
            mock_notification_service.send_verification_email.call_count,
            mock_notification_service.send_security_alert.call_count,
            mock_notification_service.send_account_status_notification.call_count,
        ]
        assert sum(notification_calls) >= 4, "Insufficient notifications sent"

        # 5. Integration Webhook Triggers
        webhook_call_count = mock_integration_service.trigger_webhooks.call_count
        assert (
            webhook_call_count >= 5
        ), f"Insufficient webhook triggers: {webhook_call_count}"

        # 6. Performance Requirements
        performance_tracker.assert_performance(5.0)  # Complete lifecycle < 5 seconds

        # 7. Data Consistency Verification
        user_id_consistency = [e["user_id"] for e in user_events if e["user_id"]]
        assert all(
            uid == test_user.id for uid in user_id_consistency
        ), "User ID consistency violation"

        # 8. Chronological Ordering
        timestamps = [e["timestamp"] for e in user_events]
        assert timestamps == sorted(timestamps), "Event timestamp ordering violation"

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_multi_user_concurrent_operations_e2e(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        user_factory,
        email_factory,
        performance_tracker,
    ):
        """Test concurrent operations across multiple users."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        concurrent_events = []

        async def track_concurrent_events(event):
            concurrent_events.append(
                {
                    "event_type": type(event).__name__,
                    "user_id": getattr(event, "user_id", None),
                    "timestamp": datetime.now(UTC),
                }
            )

        # Subscribe to key events
        event_bus.subscribe(UserCreated, track_concurrent_events)
        event_bus.subscribe(LoginSuccessful, track_concurrent_events)
        event_bus.subscribe(PasswordChanged, track_concurrent_events)

        performance_tracker.start()

        # Create multiple users
        users = [user_factory(email=email_factory(f"concurrent_{i}")) for i in range(5)]

        # Concurrent operations
        tasks = []

        for i, user in enumerate(users):
            # User creation
            tasks.append(
                event_bus.publish(
                    UserCreated(
                        user_id=user.id,
                        email=user.email.value,
                        name=f"Concurrent User {i}",
                        role="user",
                        registration_method="api",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

            # Login attempt
            tasks.append(
                event_bus.publish(
                    LoginSuccessful(
                        user_id=user.id,
                        session_id=uuid4(),
                        ip_address=f"192.168.1.{10 + i}",
                        user_agent=f"Client {i}",
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

            # Password change
            tasks.append(
                event_bus.publish(
                    PasswordChanged(
                        user_id=user.id,
                        strength_score=0.8 + (i * 0.02),
                        occurred_at=datetime.now(UTC),
                    )
                )
            )

        # Execute all operations concurrently
        await asyncio.gather(*tasks)

        await asyncio.sleep(0.3)

        performance_tracker.stop()

        # Assertions
        assert len(concurrent_events) == 15  # 5 users × 3 events each

        # Verify all users are represented
        user_ids_in_events = {e["user_id"] for e in concurrent_events if e["user_id"]}
        expected_user_ids = {user.id for user in users}
        assert (
            user_ids_in_events == expected_user_ids
        ), "Not all users represented in events"

        # Performance under concurrent load
        performance_tracker.assert_performance(
            3.0
        )  # Should handle concurrent ops efficiently

        # Verify audit system handled concurrent load
        assert mock_audit_service.create_audit_log.call_count >= 15

        await event_bus.stop()


@pytest.mark.e2e
class TestSystemIntegrationE2E:
    """End-to-end tests for system-wide integration scenarios."""

    @pytest.mark.asyncio
    async def test_external_system_integration_e2e(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test complete external system integration flow."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        integration_flow = []

        async def track_integration_flow(event):
            integration_flow.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "event": event,
                }
            )

        # Subscribe to integration-related events
        integration_events = [
            IntegrationConnected,
            WebhookReceived,
            WebhookProcessed,
            UserCreated,
            NotificationSent,
        ]

        for event_type in integration_events:
            event_bus.subscribe(event_type, track_integration_flow)

        # SCENARIO: External CRM Integration

        # 1. CRM Integration Setup
        integration_id = uuid4()
        integration_connected = IntegrationConnected(
            integration_id=integration_id,
            integration_name="External CRM",
            integration_type="crm",
            system_name="Salesforce",
            connected_by=uuid4(),
            capabilities=["sync_contacts", "receive_webhooks", "send_data"],
            configuration={
                "api_endpoint": "https://api.salesforce.com",
                "webhook_url": "https://our-app.com/webhooks/salesforce",
            },
        )
        await event_bus.publish(integration_connected)

        # 2. User Registration (triggers CRM sync)
        user_created = UserCreated(
            user_id=test_user.id,
            email=test_user.email.value,
            name="CRM Integration Test",
            role="customer",
            registration_method="web",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_created)

        # 3. Incoming Webhook from CRM (customer status update)
        webhook_received = WebhookReceived(
            webhook_id=uuid4(),
            endpoint_id=uuid4(),
            integration_id=integration_id,
            integration_name="External CRM",
            event_type="customer.status_changed",
            method="POST",
            headers={
                "content-type": "application/json",
                "x-signature": "valid-signature",
            },
            payload={
                "customer_id": str(test_user.id),
                "status": "premium",
                "effective_date": datetime.now(UTC).isoformat(),
            },
            source_ip="203.0.113.50",
            signature_valid=True,
            received_at=datetime.now(UTC),
        )
        await event_bus.publish(webhook_received)

        # 4. Webhook Processing (triggers profile update)
        webhook_processed = WebhookProcessed(
            webhook_id=webhook_received.webhook_id,
            endpoint_id=webhook_received.endpoint_id,
            integration_id=integration_id,
            integration_name="External CRM",
            processing_time_ms=145.2,
            actions_taken=["update_customer_status", "trigger_notifications"],
            entities_affected={"users": [str(test_user.id)]},
            processed_at=datetime.now(UTC),
        )
        await event_bus.publish(webhook_processed)

        # 5. Status Update Notification
        notification_sent = NotificationSent(
            notification_id="notif_status_update",
            user_id=test_user.id,
            delivery_method="email",
            delivery_status="delivered",
            provider="sendgrid",
            provider_message_id="sg_12345",
            delivered_at=datetime.now(UTC),
        )
        await event_bus.publish(notification_sent)

        await asyncio.sleep(0.2)

        # ASSERTIONS

        # 1. Complete Integration Flow
        assert len(integration_flow) == 5

        flow_events = [e["event_type"] for e in integration_flow]
        expected_flow = [
            "IntegrationConnected",
            "UserCreated",
            "WebhookReceived",
            "WebhookProcessed",
            "NotificationSent",
        ]

        for expected_event in expected_flow:
            assert (
                expected_event in flow_events
            ), f"Missing integration event: {expected_event}"

        # 2. Audit Trail for Integration
        audit_calls = mock_audit_service.create_audit_log.call_args_list
        integration_audits = [
            call
            for call in audit_calls
            if "integration" in str(call).lower() or "webhook" in str(call).lower()
        ]
        assert len(integration_audits) >= 2, "Insufficient integration audit entries"

        # 3. External System Notifications
        assert mock_integration_service.trigger_webhooks.call_count >= 2

        # 4. User Notification Delivery
        assert mock_notification_service.send_status_update_notification.called

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_disaster_recovery_scenario_e2e(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
    ):
        """Test system behavior during disaster recovery scenarios."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        disaster_events = []

        async def track_disaster_events(event):
            disaster_events.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "severity": getattr(event, "severity", "normal"),
                }
            )

        # Subscribe to critical events
        critical_events = [
            LoginFailed,
            AccountLockedOut,
            IntegrationErrorEvent,
            AuditEntryRecorded,
        ]

        for event_type in critical_events:
            event_bus.subscribe(event_type, track_disaster_events)

        # DISASTER SCENARIO: Multiple System Failures

        # 1. Database Connection Issues (simulated via audit failures)
        mock_audit_service.create_audit_log.side_effect = Exception(
            "Database connection lost"
        )

        # 2. Massive Failed Login Attempts (potential DDoS)
        attack_ips = [f"203.0.113.{i}" for i in range(10, 20)]

        for ip in attack_ips:
            for _attempt in range(10):
                login_failed = LoginFailed(
                    email=test_user.email.value,
                    ip_address=ip,
                    user_agent="AttackBot/1.0",
                    failure_reason="invalid_credentials",
                    risk_score=0.95,
                    user_id=test_user.id,
                    occurred_at=datetime.now(UTC),
                )
                await event_bus.publish(login_failed)

        # 3. Account Lockout Due to Attack
        account_locked = AccountLockedOut(
            user_id=test_user.id,
            locked_at=datetime.now(UTC),
            lockout_duration_minutes=120,  # Extended lockout
            failed_attempt_count=100,
            last_failed_ip=attack_ips[-1],
            unlock_at=datetime.now(UTC) + timedelta(hours=2),
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(account_locked)

        # 4. Integration System Failures
        integration_error = IntegrationErrorEvent(
            integration_id=uuid4(),
            integration_name="Critical Payment System",
            error_type="CONNECTION_TIMEOUT",
            error_message="Payment gateway unreachable",
            error_code="504",
            is_retryable=False,
            retry_count=5,
            error_details={
                "timeout_duration": "30s",
                "last_attempt": datetime.now(UTC).isoformat(),
            },
        )
        await event_bus.publish(integration_error)

        await asyncio.sleep(0.3)

        # DISASTER RECOVERY ASSERTIONS

        # 1. System Continues Operating Despite Failures
        assert len(disaster_events) >= 100  # Many events processed despite failures

        # 2. Attack Detection
        failed_login_events = [
            e for e in disaster_events if e["event_type"] == "LoginFailed"
        ]
        assert len(failed_login_events) >= 100, "Failed to process attack events"

        # 3. Security Response Triggered
        lockout_events = [
            e for e in disaster_events if e["event_type"] == "AccountLockedOut"
        ]
        assert len(lockout_events) >= 1, "Security lockout not triggered"

        # 4. Integration Error Handling
        integration_errors = [
            e for e in disaster_events if e["event_type"] == "IntegrationErrorEvent"
        ]
        assert len(integration_errors) >= 1, "Integration errors not processed"

        # 5. Graceful Degradation
        # Even with audit system failing, events should still be processed
        event_types = {e["event_type"] for e in disaster_events}
        assert (
            len(event_types) >= 3
        ), "System not maintaining functionality during failures"

        # 6. Emergency Notifications
        assert mock_notification_service.send_emergency_alert.called
        assert mock_notification_service.send_admin_alert.call_count >= 2

        await event_bus.stop()


@pytest.mark.e2e
class TestComplianceAndSecurityE2E:
    """End-to-end tests for compliance and security scenarios."""

    @pytest.mark.asyncio
    async def test_gdpr_compliance_workflow_e2e(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        mock_integration_service: AsyncMock,
        test_user: User,
    ):
        """Test complete GDPR compliance workflow."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        gdpr_timeline = []

        async def track_gdpr_events(event):
            gdpr_timeline.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "user_id": getattr(event, "user_id", None),
                    "gdpr_relevant": True,
                }
            )

        # Subscribe to GDPR-relevant events
        gdpr_events = [
            ConsentGranted,
            ConsentRevoked,
            UserExported,
            UserDeleted,
            ProfileUpdated,
            NotificationSent,
        ]

        for event_type in gdpr_events:
            event_bus.subscribe(event_type, track_gdpr_events)

        # GDPR WORKFLOW

        # 1. Initial Consent
        consent_granted = ConsentGranted(
            user_id=test_user.id,
            consent_type="data_processing",
            consent_version="2.1",
            granted_at=datetime.now(UTC),
            ip_address="192.168.1.100",
            valid_until=datetime.now(UTC) + timedelta(days=365),
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(consent_granted)

        # 2. Marketing Consent
        marketing_consent = ConsentGranted(
            user_id=test_user.id,
            consent_type="marketing_communications",
            consent_version="1.0",
            granted_at=datetime.now(UTC),
            ip_address="192.168.1.100",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(marketing_consent)

        # 3. Data Processing Activities
        profile_updated = ProfileUpdated(
            user_id=test_user.id,
            updated_fields=["preferences", "analytics_tracking"],
            previous_values={"analytics_tracking": False},
            new_values={"analytics_tracking": True, "preferences": {"theme": "dark"}},
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(profile_updated)

        # 4. Consent Withdrawal
        consent_revoked = ConsentRevoked(
            user_id=test_user.id,
            consent_type="marketing_communications",
            revoked_at=datetime.now(UTC),
            revocation_reason="User no longer wishes to receive marketing emails",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(consent_revoked)

        # 5. Data Export Request (Right to Data Portability)
        user_exported = UserExported(
            user_id=test_user.id,
            export_id=uuid4(),
            export_format="json",
            data_categories=["profile", "activity", "preferences", "consents"],
            requested_by=test_user.id,
            gdpr_request=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_exported)

        # 6. Right to Erasure Request
        user_deleted = UserDeleted(
            user_id=test_user.id,
            deleted_by=test_user.id,
            deletion_reason="GDPR Right to Erasure request",
            data_retained=False,
            retained_data_types=[],
            gdpr_compliant=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(user_deleted)

        # 7. Confirmation Notification
        deletion_notification = NotificationSent(
            notification_id="gdpr_deletion_confirmation",
            user_id=test_user.id,
            delivery_method="email",
            delivery_status="delivered",
            provider="gdpr_compliance_service",
            provider_message_id="gdpr_12345",
            delivered_at=datetime.now(UTC),
        )
        await event_bus.publish(deletion_notification)

        await asyncio.sleep(0.2)

        # GDPR COMPLIANCE ASSERTIONS

        # 1. Complete GDPR Timeline
        assert len(gdpr_timeline) == 7

        gdpr_events_processed = [e["event_type"] for e in gdpr_timeline]
        required_gdpr_events = [
            "ConsentGranted",
            "ConsentRevoked",
            "UserExported",
            "UserDeleted",
            "NotificationSent",
        ]

        for required_event in required_gdpr_events:
            assert (
                required_event in gdpr_events_processed
            ), f"Missing GDPR event: {required_event}"

        # 2. Audit Trail for Compliance
        audit_calls = mock_audit_service.create_audit_log.call_args_list
        gdpr_audits = [
            call
            for call in audit_calls
            if "gdpr" in str(call).lower() or "consent" in str(call).lower()
        ]
        assert len(gdpr_audits) >= 4, "Insufficient GDPR audit trail"

        # 3. Data Protection Officer Notifications
        assert mock_notification_service.send_dpo_notification.call_count >= 2

        # 4. External System Synchronization
        webhook_calls = mock_integration_service.trigger_webhooks.call_args_list
        gdpr_webhooks = [
            call
            for call in webhook_calls
            if "gdpr" in str(call).lower() or "deletion" in str(call).lower()
        ]
        assert len(gdpr_webhooks) >= 1, "GDPR webhooks not triggered"

        # 5. User Rights Fulfillment
        assert mock_notification_service.send_data_export_notification.called
        assert mock_notification_service.send_deletion_confirmation.called

        await event_bus.stop()

    @pytest.mark.asyncio
    async def test_security_audit_comprehensive_e2e(
        self,
        mock_audit_service: AsyncMock,
        mock_notification_service: AsyncMock,
        test_user: User,
        admin_user: User,
    ):
        """Test comprehensive security audit across all modules."""

        event_bus = InMemoryEventBus()
        await event_bus.start()

        security_audit_trail = []

        async def track_security_audit(event):
            security_audit_trail.append(
                {
                    "event_type": type(event).__name__,
                    "timestamp": datetime.now(UTC),
                    "risk_level": getattr(event, "risk_score", 0.0),
                    "user_id": getattr(event, "user_id", None),
                }
            )

        # Subscribe to security-relevant events
        security_events = [
            LoginSuccessful,
            LoginFailed,
            PasswordChanged,
            MFAEnabled,
            AccountLockedOut,
            RiskLevelChanged,
            APIKeyCreated,
            APIKeyRevoked,
        ]

        for event_type in security_events:
            event_bus.subscribe(event_type, track_security_audit)

        # COMPREHENSIVE SECURITY SCENARIO

        # 1. Normal User Activity
        normal_login = LoginSuccessful(
            user_id=test_user.id,
            session_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Chrome/91.0",
            risk_score=0.1,
            mfa_used=False,
            trusted_device=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(normal_login)

        # 2. Suspicious Activity Detection
        suspicious_login = LoginSuccessful(
            user_id=test_user.id,
            session_id=uuid4(),
            ip_address="203.0.113.100",  # Different country
            user_agent="Unknown Browser",
            risk_score=0.7,
            mfa_used=True,  # MFA required due to risk
            trusted_device=False,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(suspicious_login)

        # 3. Risk Level Escalation
        risk_changed = RiskLevelChanged(
            user_id=test_user.id,
            old_risk_level="low",
            new_risk_level="medium",
            risk_factors=["unusual_location", "new_device"],
            risk_score=0.7,
            assessed_by="automated_system",
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(risk_changed)

        # 4. Security Response - MFA Enforcement
        mfa_enabled = MFAEnabled(
            user_id=test_user.id,
            device_id=uuid4(),
            device_type="sms",
            device_name="Emergency MFA",
            enabled_at=datetime.now(UTC),
            backup_codes_generated=True,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(mfa_enabled)

        # 5. Admin Security Actions
        api_key_created = APIKeyCreated(
            api_key_id=uuid4(),
            user_id=admin_user.id,
            key_name="Security Audit API",
            permissions=["read:audit_logs", "read:security_events"],
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_by=admin_user.id,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(api_key_created)

        # 6. Failed Attack Sequence
        for _i in range(5):
            attack_attempt = LoginFailed(
                email=test_user.email.value,
                ip_address="203.0.113.200",
                user_agent="AttackTool/2.0",
                failure_reason="brute_force_detected",
                risk_score=1.0,
                user_id=test_user.id,
                occurred_at=datetime.now(UTC),
            )
            await event_bus.publish(attack_attempt)

        # 7. Account Protection
        account_locked = AccountLockedOut(
            user_id=test_user.id,
            locked_at=datetime.now(UTC),
            lockout_duration_minutes=60,
            failed_attempt_count=5,
            last_failed_ip="203.0.113.200",
            unlock_at=datetime.now(UTC) + timedelta(hours=1),
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(account_locked)

        # 8. Password Reset (Security Recovery)
        password_changed = PasswordChanged(
            user_id=test_user.id,
            strength_score=0.95,
            force_password_change=True,
            password_age_days=0,
            occurred_at=datetime.now(UTC),
        )
        await event_bus.publish(password_changed)

        await asyncio.sleep(0.3)

        # SECURITY AUDIT ASSERTIONS

        # 1. Complete Security Event Coverage
        assert len(security_audit_trail) >= 10

        # 2. Risk Escalation Detection
        high_risk_events = [e for e in security_audit_trail if e["risk_level"] >= 0.7]
        assert len(high_risk_events) >= 2, "High-risk events not properly tracked"

        # 3. Security Response Verification
        event_types = [e["event_type"] for e in security_audit_trail]
        security_responses = ["MFAEnabled", "AccountLockedOut", "PasswordChanged"]

        for response in security_responses:
            assert (
                response in event_types
            ), f"Security response not triggered: {response}"

        # 4. Admin Security Actions
        admin_events = [
            e for e in security_audit_trail if e["user_id"] == admin_user.id
        ]
        assert len(admin_events) >= 1, "Admin security actions not tracked"

        # 5. Comprehensive Audit Logging
        assert mock_audit_service.create_security_audit.call_count >= 8

        # 6. Security Team Notifications
        assert mock_notification_service.send_security_alert.call_count >= 3
        assert mock_notification_service.send_admin_alert.call_count >= 2

        await event_bus.stop()
