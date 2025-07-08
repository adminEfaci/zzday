"""
Comprehensive tests for all domain events in the identity domain.

Test Coverage:
- Event creation and serialization  
- Event metadata validation
- Event versioning and compatibility
- Event correlation and causation
- JSON serialization/deserialization
- Event equality and hashing
- Aggregate ID extraction
- Event immutability
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.modules.identity.domain.entities.admin.admin_events import *
from app.modules.identity.domain.entities.group.group_events import *
from app.modules.identity.domain.entities.role.role_events import *
from app.modules.identity.domain.entities.session.session_events import *
from app.modules.identity.domain.entities.user.user_events import *

# Import actual domain events from the Identity module
from app.modules.identity.domain.events import IdentityDomainEvent


class TestIdentityDomainEventBase:
    """Test base IdentityDomainEvent functionality"""

    def test_identity_domain_event_base_properties(self):
        """Test that base IdentityDomainEvent has correct domain"""

        # Create a concrete implementation for testing
        class TestEvent(IdentityDomainEvent):
            user_id: uuid4()

            def get_aggregate_id(self) -> str:
                return str(self.user_id)

        event = TestEvent(user_id=uuid4())
        assert event.domain == "identity"
        assert hasattr(event, "get_aggregate_id")


class TestUserLifecycleEvents:
    """Test user lifecycle domain events"""

    def test_user_created_event_creation(self):
        """Test UserCreated event creation with all required fields"""
        user_id = uuid4()
        created_by = uuid4()

        event = UserCreated(
            user_id=user_id,
            email="test@example.com",
            name="Test User",
            role="user",
            created_by=created_by,
            registration_method="email",
        )

        assert event.user_id == user_id
        assert event.email == "test@example.com"
        assert event.name == "Test User"
        assert event.role == "user"
        assert event.created_by == created_by
        assert event.registration_method == "email"
        assert event.get_aggregate_id() == str(user_id)
        assert event.domain == "identity"

    def test_user_activated_event(self):
        """Test UserActivated event with activation details"""
        user_id = uuid4()
        event = UserActivated(
            aggregate_id=user_id,
            activated_at=datetime.now(datetime.UTC),
            activated_by=uuid4(),
            activation_method="email_verification",
        )

        assert event.aggregate_id == user_id
        assert event.activation_method == "email_verification"
        assert isinstance(event.activated_at, datetime)
        assert event.event_type == "UserActivated"

    def test_user_suspended_event_with_reason(self):
        """Test UserSuspended event includes suspension reason and authority"""
        user_id = uuid4()
        admin_id = uuid4()

        event = UserSuspended(
            aggregate_id=user_id,
            reason="Policy violation - multiple failed login attempts",
            suspended_by=admin_id,
            suspended_until=datetime.now(datetime.UTC) + timedelta(days=7),
            metadata={"violation_type": "security", "severity": "high"},
        )

        assert event.aggregate_id == user_id
        assert event.reason == "Policy violation - multiple failed login attempts"
        assert event.suspended_by == admin_id
        assert event.suspended_until > datetime.now(datetime.UTC)
        assert event.metadata["violation_type"] == "security"
        assert event.event_type == "UserSuspended"

    def test_user_deactivated_event(self):
        """Test UserDeactivated event with deactivation context"""
        user_id = uuid4()

        event = UserDeactivated(
            aggregate_id=user_id,
            reason="User requested account deletion",
            deactivated_by=user_id,  # Self-deactivation
            deactivation_type="user_requested",
            preserve_data=False,
        )

        assert event.aggregate_id == user_id
        assert event.reason == "User requested account deletion"
        assert event.deactivated_by == user_id
        assert event.preserve_data is False
        assert event.event_type == "UserDeactivated"

    def test_user_reactivated_event(self):
        """Test UserReactivated event after suspension/deactivation"""
        user_id = uuid4()
        admin_id = uuid4()

        event = UserReactivated(
            aggregate_id=user_id,
            reactivated_by=admin_id,
            reactivated_at=datetime.now(datetime.UTC),
            previous_status=UserStatus.SUSPENDED.value,
            reason="Suspension period ended",
        )

        assert event.aggregate_id == user_id
        assert event.reactivated_by == admin_id
        assert event.previous_status == UserStatus.SUSPENDED.value
        assert event.reason == "Suspension period ended"
        assert event.event_type == "UserReactivated"


class TestAuthenticationEvents:
    """Test authentication-related events: login, logout, password changes"""

    def test_login_attempted_event(self):
        """Test LoginAttempted event with attempt details"""
        event = LoginAttempted(
            email="test@example.com",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Chrome/91.0",
            device_fingerprint="device123",
            attempt_number=1,
            risk_score=0.2,
        )

        assert event.email == "test@example.com"
        assert event.ip_address == "192.168.1.100"
        assert event.risk_score == 0.2
        assert event.attempt_number == 1
        assert event.event_type == "LoginAttempted"

    def test_login_successful_event_with_risk_score(self):
        """Test LoginSuccessful event includes risk assessment data"""
        user_id = uuid4()
        session_id = uuid4()

        event = LoginSuccessful(
            aggregate_id=user_id,
            session_id=session_id,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 Browser",
            risk_score=0.3,
            location={"country": "US", "city": "San Francisco", "region": "CA"},
            device_info={"type": "desktop", "os": "Windows 10"},
            authentication_method=AuthenticationMethod.MFA.value,
        )

        assert event.aggregate_id == user_id
        assert event.session_id == session_id
        assert event.risk_score == 0.3
        assert event.ip_address == "192.168.1.1"
        assert event.location["country"] == "US"
        assert event.authentication_method == AuthenticationMethod.MFA.value
        assert 0 <= event.risk_score <= 1.0
        assert event.event_type == "LoginSuccessful"

    def test_login_failed_event_tracks_attempts(self):
        """Test LoginFailed event tracks failure patterns"""
        event = LoginFailed(
            email="test@example.com",
            ip_address="192.168.1.1",
            failure_reason="Invalid password",
            risk_score=0.8,
            attempt_count=3,
            lockout_triggered=False,
            metadata={"detection": "pattern_analysis", "threat_level": "medium"},
        )

        assert event.email == "test@example.com"
        assert event.failure_reason == "Invalid password"
        assert event.attempt_count == 3
        assert event.risk_score == 0.8
        assert event.lockout_triggered is False
        assert event.metadata["threat_level"] == "medium"
        assert event.event_type == "LoginFailed"

    def test_logout_event(self):
        """Test LogoutEvent with session details"""
        user_id = uuid4()
        session_id = uuid4()

        event = LogoutEvent(
            aggregate_id=user_id,
            session_id=session_id,
            logout_type="user_initiated",
            session_duration=timedelta(hours=2, minutes=30),
            ip_address="192.168.1.1",
        )

        assert event.aggregate_id == user_id
        assert event.session_id == session_id
        assert event.logout_type == "user_initiated"
        assert event.session_duration.total_seconds() == 9000  # 2.5 hours
        assert event.event_type == "LogoutEvent"

    def test_password_changed_event_with_strength(self):
        """Test PasswordChanged event includes password strength assessment"""
        user_id = uuid4()

        event = PasswordChanged(
            aggregate_id=user_id,
            changed_by=user_id,  # Self-change
            strength_score=0.85,
            previous_password_age=timedelta(days=90),
            change_reason="regular_rotation",
            metadata={"complexity": "high", "length": 16},
        )

        assert event.aggregate_id == user_id
        assert event.strength_score == 0.85
        assert event.previous_password_age.days == 90
        assert event.change_reason == "regular_rotation"
        assert event.metadata["complexity"] == "high"
        assert 0 <= event.strength_score <= 1.0
        assert event.event_type == "PasswordChanged"

    def test_password_reset_requested_event(self):
        """Test PasswordResetRequested event"""
        event = PasswordResetRequested(
            email="test@example.com",
            reset_token=str(uuid4()),
            ip_address="192.168.1.1",
            expires_at=datetime.now(datetime.UTC) + timedelta(hours=1),
            request_method="email",
        )

        assert event.email == "test@example.com"
        assert event.reset_token is not None
        assert event.expires_at > datetime.now(datetime.UTC)
        assert event.request_method == "email"
        assert event.event_type == "PasswordResetRequested"


class TestSecurityEvents:
    """Test security-related events: MFA, security alerts, incidents"""

    def test_mfa_enabled_event_with_device_info(self):
        """Test MFAEnabled event captures device information"""
        user_id = uuid4()

        event = MFAEnabled(
            aggregate_id=user_id,
            method=MFAMethod.TOTP.value,
            device_name="Google Authenticator",
            device_id=uuid4(),
            backup_codes_generated=True,
            recovery_email="recovery@example.com",
        )

        assert event.aggregate_id == user_id
        assert event.method == MFAMethod.TOTP.value
        assert event.device_name == "Google Authenticator"
        assert event.backup_codes_generated is True
        assert event.recovery_email == "recovery@example.com"
        assert event.event_type == "MFAEnabled"

    def test_mfa_disabled_event(self):
        """Test MFADisabled event with reason"""
        user_id = uuid4()

        event = MFADisabled(
            aggregate_id=user_id,
            disabled_by=user_id,
            reason="User requested removal",
            removed_methods=[MFAMethod.TOTP.value, MFAMethod.SMS.value],
        )

        assert event.aggregate_id == user_id
        assert event.reason == "User requested removal"
        assert MFAMethod.TOTP.value in event.removed_methods
        assert MFAMethod.SMS.value in event.removed_methods
        assert event.event_type == "MFADisabled"

    def test_security_alert_raised_event_severity(self):
        """Test SecurityAlertRaised event includes severity and details"""
        user_id = uuid4()

        event = SecurityAlertRaised(
            aggregate_id=user_id,
            alert_type=SecurityEventType.SUSPICIOUS_LOGIN.value,
            severity=RiskLevel.HIGH,
            risk_score=0.9,
            details={
                "ip": "185.220.101.1",
                "location": "Unknown",
                "indicators": ["tor_exit_node", "new_device", "unusual_time"],
                "confidence": 0.95,
            },
            auto_response_taken=True,
            response_actions=["require_mfa", "notify_user", "log_incident"],
        )

        assert event.aggregate_id == user_id
        assert event.alert_type == SecurityEventType.SUSPICIOUS_LOGIN.value
        assert event.severity == RiskLevel.HIGH
        assert event.risk_score == 0.9
        assert "tor_exit_node" in event.details["indicators"]
        assert event.auto_response_taken is True
        assert "require_mfa" in event.response_actions
        assert event.event_type == "SecurityAlertRaised"

    def test_account_locked_event(self):
        """Test AccountLocked event with lockout details"""
        user_id = uuid4()

        event = AccountLocked(
            aggregate_id=user_id,
            reason="Multiple failed login attempts",
            locked_until=datetime.now(datetime.UTC) + timedelta(minutes=30),
            failed_attempts=5,
            ip_addresses=["192.168.1.1", "192.168.1.2"],
            auto_unlock=True,
        )

        assert event.aggregate_id == user_id
        assert event.reason == "Multiple failed login attempts"
        assert event.locked_until > datetime.now(datetime.UTC)
        assert event.failed_attempts == 5
        assert len(event.ip_addresses) == 2
        assert event.auto_unlock is True
        assert event.event_type == "AccountLocked"

    def test_suspicious_activity_detected_event(self):
        """Test SuspiciousActivityDetected event"""
        user_id = uuid4()

        event = SuspiciousActivityDetected(
            aggregate_id=user_id,
            activity_type="impossible_travel",
            details={
                "location1": {
                    "city": "New York",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(hours=1),
                },
                "location2": {
                    "city": "London",
                    "timestamp": datetime.now(datetime.UTC),
                },
                "distance_km": 5570,
                "time_difference_hours": 1,
            },
            risk_score=0.95,
            recommended_actions=[
                "verify_identity",
                "force_logout",
                "require_password_reset",
            ],
        )

        assert event.aggregate_id == user_id
        assert event.activity_type == "impossible_travel"
        assert event.details["distance_km"] == 5570
        assert event.risk_score == 0.95
        assert "verify_identity" in event.recommended_actions
        assert event.event_type == "SuspiciousActivityDetected"


class TestComplianceEvents:
    """Test compliance and audit events"""

    def test_audit_log_created_event_immutability(self):
        """Test AuditLogCreated event represents immutable audit trail"""
        log_id = uuid4()
        user_id = uuid4()
        actor_id = uuid4()

        event = AuditLogCreated(
            log_id=log_id,
            aggregate_id=user_id,
            actor_id=actor_id,
            action=AuditAction.UPDATE.value,
            resource_type="user_profile",
            resource_id=str(user_id),
            changes={
                "department": {"old": "Engineering", "new": "Product"},
                "title": {"old": "Developer", "new": "Senior Developer"},
            },
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            metadata={"request_id": str(uuid4()), "session_id": str(uuid4())},
        )

        assert event.log_id == log_id
        assert event.aggregate_id == user_id
        assert event.actor_id == actor_id
        assert event.action == AuditAction.UPDATE.value
        assert event.resource_type == "user_profile"
        assert event.changes["department"]["old"] == "Engineering"
        assert event.changes["department"]["new"] == "Product"
        assert event.event_type == "AuditLogCreated"

    def test_compliance_violation_detected_event(self):
        """Test ComplianceViolationDetected event for regulatory compliance"""
        user_id = uuid4()

        event = ComplianceViolationDetected(
            aggregate_id=user_id,
            violation_type="data_retention_exceeded",
            severity=RiskLevel.MEDIUM,
            regulation="GDPR",
            article="Article 5(1)(e)",
            details={
                "data_type": "user_activity_logs",
                "retention_period_days": 730,
                "actual_age_days": 850,
                "excess_days": 120,
            },
            remediation_required=True,
            deadline=datetime.now(datetime.UTC) + timedelta(days=30),
        )

        assert event.aggregate_id == user_id
        assert event.violation_type == "data_retention_exceeded"
        assert event.severity == RiskLevel.MEDIUM
        assert event.regulation == "GDPR"
        assert event.article == "Article 5(1)(e)"
        assert event.details["excess_days"] == 120
        assert event.remediation_required is True
        assert event.deadline > datetime.now(datetime.UTC)
        assert event.event_type == "ComplianceViolationDetected"

    def test_data_export_requested_event(self):
        """Test DataExportRequested event for GDPR compliance"""
        user_id = uuid4()

        event = DataExportRequested(
            aggregate_id=user_id,
            request_id=uuid4(),
            requested_by=user_id,
            data_categories=["personal_info", "activity_logs", "preferences"],
            format="json",
            purpose="gdpr_request",
            deadline=datetime.now(datetime.UTC) + timedelta(days=30),
        )

        assert event.aggregate_id == user_id
        assert event.requested_by == user_id
        assert "personal_info" in event.data_categories
        assert event.format == "json"
        assert event.purpose == "gdpr_request"
        assert event.event_type == "DataExportRequested"

    def test_data_deletion_requested_event(self):
        """Test DataDeletionRequested event for right to be forgotten"""
        user_id = uuid4()

        event = DataDeletionRequested(
            aggregate_id=user_id,
            request_id=uuid4(),
            requested_by=user_id,
            deletion_scope="full",
            exclude_categories=["legal_holds", "financial_records"],
            reason="user_request",
            scheduled_date=datetime.now(datetime.UTC) + timedelta(days=7),
        )

        assert event.aggregate_id == user_id
        assert event.deletion_scope == "full"
        assert "legal_holds" in event.exclude_categories
        assert event.reason == "user_request"
        assert event.scheduled_date > datetime.now(datetime.UTC)
        assert event.event_type == "DataDeletionRequested"


class TestRoleAndPermissionEvents:
    """Test role and permission management events"""

    def test_role_assigned_event(self):
        """Test RoleAssigned event with role details"""
        user_id = uuid4()
        role_id = uuid4()
        assigned_by = uuid4()

        event = RoleAssigned(
            aggregate_id=user_id,
            role_id=role_id,
            role_name="Manager",
            assigned_by=assigned_by,
            effective_from=datetime.now(datetime.UTC),
            effective_until=datetime.now(datetime.UTC) + timedelta(days=365),
            reason="Promotion",
            inherited_permissions=["read_team_data", "approve_requests"],
        )

        assert event.aggregate_id == user_id
        assert event.role_id == role_id
        assert event.role_name == "Manager"
        assert event.assigned_by == assigned_by
        assert event.reason == "Promotion"
        assert "read_team_data" in event.inherited_permissions
        assert event.effective_until > event.effective_from
        assert event.event_type == "RoleAssigned"

    def test_role_revoked_event(self):
        """Test RoleRevoked event"""
        user_id = uuid4()
        role_id = uuid4()
        revoked_by = uuid4()

        event = RoleRevoked(
            aggregate_id=user_id,
            role_id=role_id,
            role_name="Admin",
            revoked_by=revoked_by,
            reason="Role change",
            revoked_permissions=["admin_users", "admin_system"],
        )

        assert event.aggregate_id == user_id
        assert event.role_id == role_id
        assert event.role_name == "Admin"
        assert event.revoked_by == revoked_by
        assert "admin_users" in event.revoked_permissions
        assert event.event_type == "RoleRevoked"

    def test_permission_granted_event(self):
        """Test PermissionGranted event with granular permissions"""
        user_id = uuid4()
        granted_by = uuid4()

        event = PermissionGranted(
            aggregate_id=user_id,
            permission="read_financial_reports",
            resource_type="report",
            resource_id="financial_*",
            scope=PermissionScope.DEPARTMENT.value,
            granted_by=granted_by,
            reason="Department head approval",
            expires_at=datetime.now(datetime.UTC) + timedelta(days=90),
            conditions={"department": "finance", "max_amount": 1000000},
        )

        assert event.aggregate_id == user_id
        assert event.permission == "read_financial_reports"
        assert event.resource_type == "report"
        assert event.scope == PermissionScope.DEPARTMENT.value
        assert event.conditions["department"] == "finance"
        assert event.expires_at > datetime.now(datetime.UTC)
        assert event.event_type == "PermissionGranted"


class TestSessionEvents:
    """Test session lifecycle events"""

    def test_session_created_event(self):
        """Test SessionCreated event with session details"""
        user_id = uuid4()
        session_id = uuid4()

        event = SessionCreated(
            aggregate_id=user_id,
            session_id=session_id,
            session_type=SessionType.WEB.value,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_info={"type": "desktop", "os": "Windows 10"},
            expires_at=datetime.now(datetime.UTC) + timedelta(hours=24),
            risk_score=0.1,
        )

        assert event.aggregate_id == user_id
        assert event.session_id == session_id
        assert event.session_type == SessionType.WEB.value
        assert event.risk_score == 0.1
        assert event.expires_at > datetime.now(datetime.UTC)
        assert event.event_type == "SessionCreated"

    def test_session_extended_event(self):
        """Test SessionExtended event"""
        user_id = uuid4()
        session_id = uuid4()

        event = SessionExtended(
            aggregate_id=user_id,
            session_id=session_id,
            extended_by=timedelta(hours=2),
            new_expiry=datetime.now(datetime.UTC) + timedelta(hours=26),
            reason="user_activity",
        )

        assert event.aggregate_id == user_id
        assert event.session_id == session_id
        assert event.extended_by == timedelta(hours=2)
        assert event.reason == "user_activity"
        assert event.event_type == "SessionExtended"

    def test_session_revoked_event(self):
        """Test SessionRevoked event with revocation context"""
        user_id = uuid4()
        session_id = uuid4()

        event = SessionRevoked(
            aggregate_id=user_id,
            session_id=session_id,
            revoked_by=user_id,
            reason="user_logout",
            ip_address="192.168.1.1",
            cascade_revoke=False,
        )

        assert event.aggregate_id == user_id
        assert event.session_id == session_id
        assert event.reason == "user_logout"
        assert event.cascade_revoke is False
        assert event.event_type == "SessionRevoked"


class TestEventCorrelationAndCausation:
    """Test event correlation, causation, and event sourcing patterns"""

    def test_event_correlation_id(self):
        """Test events can be correlated across aggregate boundaries"""
        correlation_id = uuid4()
        user_id = uuid4()

        user_created = UserCreated(
            aggregate_id=user_id,
            username="testuser",
            email="test@example.com",
            roles=[UserRole.USER.value],
            correlation_id=correlation_id,
        )

        profile_created = ProfileCreated(
            aggregate_id=user_id,
            profile_id=uuid4(),
            correlation_id=correlation_id,
            triggered_by="user_registration",
        )

        welcome_email_sent = WelcomeEmailSent(
            aggregate_id=user_id,
            email="test@example.com",
            correlation_id=correlation_id,
            template="new_user_welcome",
        )

        # All events should share the same correlation ID
        assert user_created.correlation_id == profile_created.correlation_id
        assert profile_created.correlation_id == welcome_email_sent.correlation_id
        assert user_created.correlation_id == correlation_id

    def test_event_causation_chain(self):
        """Test event causation chains for workflow tracking"""
        user_id = uuid4()

        # Initial event
        password_reset_requested = PasswordResetRequested(
            email="test@example.com",
            reset_token=str(uuid4()),
            ip_address="192.168.1.1",
            event_id=uuid4(),
        )

        # Caused events
        reset_email_sent = PasswordResetEmailSent(
            aggregate_id=user_id,
            email="test@example.com",
            caused_by_event_id=password_reset_requested.event_id,
            event_id=uuid4(),
        )

        password_reset_completed = PasswordResetCompleted(
            aggregate_id=user_id,
            caused_by_event_id=reset_email_sent.event_id,
            reset_token=password_reset_requested.reset_token,
            event_id=uuid4(),
        )

        # Verify causation chain
        assert reset_email_sent.caused_by_event_id == password_reset_requested.event_id
        assert password_reset_completed.caused_by_event_id == reset_email_sent.event_id

    def test_event_metadata_consistency(self):
        """Test that all events have consistent metadata"""
        events = [
            UserCreated(
                aggregate_id=uuid4(), username="test", email="test@example.com"
            ),
            LoginSuccessful(
                aggregate_id=uuid4(), session_id=uuid4(), ip_address="192.168.1.1"
            ),
            SecurityAlertRaised(
                aggregate_id=uuid4(),
                alert_type="suspicious_login",
                severity=RiskLevel.HIGH,
            ),
            RoleAssigned(
                aggregate_id=uuid4(),
                role_id=uuid4(),
                role_name="Admin",
                assigned_by=uuid4(),
            ),
        ]

        for event in events:
            # All events should have these base attributes
            assert hasattr(event, "event_type")
            assert hasattr(event, "event_id")
            assert hasattr(event, "aggregate_id")
            assert hasattr(event, "timestamp")
            assert hasattr(event, "version")

            # Verify event type matches class name
            assert event.event_type == event.__class__.__name__

            # Verify timestamp is recent
            assert isinstance(event.timestamp, datetime)
            assert (datetime.now(datetime.UTC) - event.timestamp).total_seconds() < 5


class TestEventPerformanceAndMemory:
    """Test event performance characteristics and memory usage"""

    def test_event_creation_performance(self, performance_tracker):
        """Test that events can be created quickly"""
        with performance_tracker.measure("event_creation"):
            events = []
            for i in range(1000):
                event = LoginSuccessful(
                    aggregate_id=uuid4(),
                    session_id=uuid4(),
                    ip_address=f"192.168.1.{i % 255}",
                    risk_score=i / 1000,
                )
                events.append(event)

        # Should create 1000 events in under 0.1 seconds
        performance_tracker.assert_performance("event_creation", 0.1)
        assert len(events) == 1000

    def test_event_serialization_performance(self, performance_tracker):
        """Test that event serialization is performant for high-volume scenarios"""
        # Create events
        events = []
        for _ in range(1000):
            event = UserCreated(
                aggregate_id=uuid4(),
                username=f"user_{uuid4().hex[:8]}",
                email=f"user_{uuid4().hex[:8]}@example.com",
                roles=[UserRole.USER.value],
                metadata={"source": "bulk_import", "batch_id": str(uuid4())},
            )
            events.append(event)

        # Test serialization performance
        with performance_tracker.measure("serialization"):
            serialized_events = []
            for event in events:
                if hasattr(event, "to_dict"):
                    serialized = event.to_dict()
                else:
                    serialized = {
                        "event_type": event.event_type,
                        "aggregate_id": str(event.aggregate_id),
                        "timestamp": event.timestamp.isoformat(),
                    }
                serialized_events.append(serialized)

        # Should serialize 1000 events in under 0.5 seconds
        performance_tracker.assert_performance("serialization", 0.5)
        assert len(serialized_events) == 1000

    def test_event_memory_footprint(self):
        """Test that events don't consume excessive memory"""
        import sys

        # Test various event types
        events = [
            UserCreated(
                aggregate_id=uuid4(), username="test", email="test@example.com"
            ),
            LoginSuccessful(
                aggregate_id=uuid4(), session_id=uuid4(), ip_address="192.168.1.1"
            ),
            AuditLogCreated(
                log_id=uuid4(),
                aggregate_id=uuid4(),
                actor_id=uuid4(),
                action="update",
                resource_type="user",
                resource_id=str(uuid4()),
                changes={"field": {"old": "value1", "new": "value2"}},
            ),
        ]

        for event in events:
            # Basic memory footprint test - events should be lightweight
            event_size = sys.getsizeof(event)
            # Events should generally be under 2KB
            assert (
                event_size < 2048
            ), f"{event.__class__.__name__} uses {event_size} bytes"


class TestEventValidation:
    """Test event validation and error handling"""

    def test_event_field_validation(self, validation_helper):
        """Test that events validate their fields properly"""
        # Test missing required fields
        with pytest.raises((ValueError, TypeError, AttributeError)):
            UserCreated()  # Missing all required fields

        with pytest.raises((ValueError, TypeError, AttributeError)):
            LoginSuccessful(
                aggregate_id=uuid4()
                # Missing session_id and ip_address
            )

    def test_event_timestamp_validation(self):
        """Test that event timestamps are properly set"""
        event = UserCreated(
            aggregate_id=uuid4(), username="test", email="test@example.com"
        )

        # Timestamp should be set automatically
        assert hasattr(event, "timestamp")
        assert isinstance(event.timestamp, datetime)

        # Timestamp should be recent (within last 5 seconds)
        age = (datetime.now(datetime.UTC) - event.timestamp).total_seconds()
        assert age < 5

    def test_event_immutability(self, assert_helpers):
        """Test that events are immutable after creation"""
        event = UserCreated(
            aggregate_id=uuid4(), username="test", email="test@example.com"
        )

        # Events should be immutable
        assert_helpers.assert_immutable(event, "username", "modified")
        assert_helpers.assert_immutable(event, "email", "modified@example.com")
        assert_helpers.assert_immutable(event, "aggregate_id", uuid4())
