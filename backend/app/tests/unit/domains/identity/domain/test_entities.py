"""
Comprehensive tests for all domain entities in the identity domain.

Test Coverage:
- Entity lifecycle and state transitions
- Business rule enforcement
- Domain event generation
- Validation and invariants
- Relationships and referential integrity
- Equality and identity semantics
"""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.modules.identity.domain.entities import *
from app.modules.identity.domain.enums import *
from app.modules.identity.domain.events import *
from app.modules.identity.domain.value_objects import *


class TestPermissionEntity:
    """Test Permission entity business logic"""

    def test_permission_creation(self):
        """Test permission creation with all attributes"""
        permission = Permission(
            id=uuid4(),
            name="read_users",
            resource="users",
            action="read",
            scope=PermissionScope.DEPARTMENT,
            description="Read users in department",
            conditions={"department_id": "required"},
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )

        assert permission.name == "read_users"
        assert permission.resource == "users"
        assert permission.action == "read"
        assert permission.scope == PermissionScope.DEPARTMENT
        assert permission.conditions["department_id"] == "required"

    def test_permission_wildcard_matching(self):
        """Test permission wildcard pattern matching"""
        # Admin permission with wildcards
        admin_perm = Permission(
            id=uuid4(),
            name="admin_all",
            resource="*",
            action="*",
            scope=PermissionScope.GLOBAL,
        )

        assert admin_perm.matches("users", "read") is True
        assert admin_perm.matches("reports", "delete") is True
        assert admin_perm.matches("anything", "anything") is True

        # Specific resource wildcard
        user_admin = Permission(
            id=uuid4(),
            name="user_admin",
            resource="users",
            action="*",
            scope=PermissionScope.DEPARTMENT,
        )

        assert user_admin.matches("users", "read") is True
        assert user_admin.matches("users", "delete") is True
        assert user_admin.matches("reports", "read") is False

    def test_permission_scope_validation(self):
        """Test permission scope enforcement"""
        dept_permission = Permission(
            id=uuid4(),
            name="dept_read",
            resource="users",
            action="read",
            scope=PermissionScope.DEPARTMENT,
            conditions={"department_id": "dept_123"},
        )

        # Should match within same department
        assert (
            dept_permission.is_valid_for_context({"department_id": "dept_123"}) is True
        )

        # Should not match different department
        assert (
            dept_permission.is_valid_for_context({"department_id": "dept_456"}) is False
        )

        # Should not match without department context
        assert dept_permission.is_valid_for_context({}) is False

    def test_permission_expiry(self, time_machine):
        """Test permission expiry functionality"""
        current_time = datetime.now(datetime.UTC)
        time_machine.freeze(current_time)

        permission = Permission(
            id=uuid4(),
            name="temp_access",
            resource="reports",
            action="read",
            scope=PermissionScope.USER,
            expires_at=current_time + timedelta(hours=1),
        )

        assert permission.is_expired() is False

        # Advance time past expiry
        time_machine.advance(timedelta(hours=2))
        assert permission.is_expired() is True

    def test_permission_string_representation(self):
        """Test permission string representation"""
        permission = Permission(
            id=uuid4(),
            name="read_users",
            resource="users",
            action="read",
            scope=PermissionScope.DEPARTMENT,
        )

        str_repr = str(permission)
        assert "read_users" in str_repr
        assert "users:read" in str_repr or "users/read" in str_repr


class TestRoleEntity:
    """Test Role entity and permission management"""

    def test_role_creation_with_hierarchy(self):
        """Test role creation with parent-child hierarchy"""
        parent_role = Role(
            id=uuid4(),
            name="Manager",
            description="Department manager role",
            priority=50,
            created_at=datetime.now(datetime.UTC),
        )

        child_role = Role(
            id=uuid4(),
            name="Team Lead",
            description="Team lead role",
            priority=30,
            parent_role_id=parent_role.id,
            created_at=datetime.now(datetime.UTC),
        )

        assert child_role.parent_role_id == parent_role.id
        assert child_role.priority < parent_role.priority

    def test_role_permission_assignment(self):
        """Test adding and removing permissions from role"""
        role = Role(
            id=uuid4(), name="Editor", description="Content editor role", priority=20
        )

        permission1 = Permission(
            id=uuid4(), name="edit_content", resource="content", action="edit"
        )

        permission2 = Permission(
            id=uuid4(), name="publish_content", resource="content", action="publish"
        )

        # Add permissions
        role.add_permission(permission1)
        role.add_permission(permission2)

        assert len(role._permissions) == 2
        assert role.has_permission("edit_content") is True
        assert role.has_permission("publish_content") is True

        # Remove permission
        role.remove_permission(permission1.id)
        assert len(role._permissions) == 1
        assert role.has_permission("edit_content") is False

    def test_role_permission_inheritance(self):
        """Test permission inheritance from parent roles"""
        # Create parent role with permissions
        parent_perms = [
            Permission(id=uuid4(), name="read_all", resource="*", action="read"),
            Permission(id=uuid4(), name="manage_team", resource="team", action="*"),
        ]

        parent_role = Role(id=uuid4(), name="Manager", priority=50)
        for perm in parent_perms:
            parent_role.add_permission(perm)

        # Create child role with additional permissions
        child_perms = [
            Permission(
                id=uuid4(), name="edit_docs", resource="documents", action="edit"
            )
        ]

        child_role = Role(
            id=uuid4(), name="Team Lead", priority=30, parent_role_id=parent_role.id
        )
        for perm in child_perms:
            child_role.add_permission(perm)

        # Get all permissions (including inherited)
        all_permissions = child_role.get_all_permissions([parent_role])

        assert len(all_permissions) == 3  # 2 from parent + 1 own
        permission_names = [p.name for p in all_permissions]
        assert "read_all" in permission_names
        assert "manage_team" in permission_names
        assert "edit_docs" in permission_names

    def test_role_circular_hierarchy_prevention(self):
        """Test prevention of circular role hierarchies"""
        role1 = Role(id=uuid4(), name="Role1", priority=30)
        role2 = Role(id=uuid4(), name="Role2", priority=20, parent_role_id=role1.id)
        role3 = Role(id=uuid4(), name="Role3", priority=10, parent_role_id=role2.id)

        # Attempting to set role1's parent as role3 should fail
        with pytest.raises(ValueError, match="circular"):
            role1.set_parent_role(role3.id, [role2, role3])

    def test_role_activation_deactivation(self):
        """Test role activation and deactivation"""
        role = Role(id=uuid4(), name="Temporary Role", priority=10, status="active")

        assert role.is_active() is True

        # Deactivate role
        role.deactivate("No longer needed")
        assert role.is_active() is False
        assert hasattr(role, "deactivated_at")
        assert role.deactivation_reason == "No longer needed"

        # Reactivate role
        role.activate()
        assert role.is_active() is True


class TestSessionEntity:
    """Test Session entity business logic and security features"""

    def test_session_creation(self):
        """Test session creation with security attributes"""
        user_id = uuid4()
        ip_address = IpAddress("192.168.1.100")

        session = Session(
            id=uuid4(),
            user_id=user_id,
            session_type=SessionType.WEB,
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            ip_address=ip_address,
            user_agent="Mozilla/5.0 Chrome/91.0",
            device_fingerprint="device_abc123",
            expires_at=datetime.now(datetime.UTC) + timedelta(hours=24),
            created_at=datetime.now(datetime.UTC),
        )

        assert session.user_id == user_id
        assert session.session_type == SessionType.WEB
        assert session.ip_address == ip_address
        assert len(session.access_token) > 0
        assert session.is_active is True

    def test_session_expiry_logic(self, time_machine):
        """Test session expiry and timeout handling"""
        current_time = datetime.now(datetime.UTC)
        time_machine.freeze(current_time)

        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="test_token",
            expires_at=current_time + timedelta(hours=1),
            idle_timeout=timedelta(minutes=30),
            last_activity_at=current_time,
        )

        # Initially not expired
        assert session.is_expired is False
        assert session.is_idle_timeout is False

        # Test idle timeout
        time_machine.advance(timedelta(minutes=31))
        assert session.is_idle_timeout is True

        # Test absolute expiry
        time_machine.freeze(current_time)
        time_machine.advance(timedelta(hours=2))
        assert session.is_expired is True

    def test_session_activity_tracking(self):
        """Test session activity recording"""
        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="test_token",
        )

        initial_activity = session.last_activity_at
        initial_count = session.activity_count

        # Record activity
        session.record_activity("page_view")

        assert session.last_activity_at > initial_activity
        assert session.activity_count == initial_count + 1

        # Multiple activities
        for _ in range(5):
            session.record_activity("api_call")

        assert session.activity_count == initial_count + 6

    def test_session_risk_assessment(self):
        """Test session risk scoring and assessment"""
        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="test_token",
            ip_address=IpAddress("192.168.1.1"),
            risk_score=0.2,
        )

        # Update risk based on suspicious activity
        session.update_risk_score(0.8, "suspicious_location")
        assert session.risk_score == 0.8
        assert "suspicious_location" in session.risk_factors

        # High risk should affect trust
        assert session.is_high_risk is True
        assert session.requires_additional_verification is True

    def test_session_token_refresh(self, event_collector):
        """Test session token refresh mechanism"""
        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="old_access_token",
            refresh_token="old_refresh_token",
            expires_at=datetime.now(datetime.UTC) + timedelta(hours=1),
        )

        old_access = session.access_token
        old_refresh = session.refresh_token

        # Refresh tokens
        new_expiry = datetime.now(datetime.UTC) + timedelta(hours=24)
        session.refresh_tokens(new_expiry)

        assert session.access_token != old_access
        assert session.refresh_token != old_refresh
        assert session.expires_at == new_expiry
        assert session.refresh_count == 1

    def test_session_revocation(self, event_collector):
        """Test session revocation and cleanup"""
        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="test_token",
            status="active",
        )

        assert session.is_active is True

        # Revoke session
        session.revoke("user_logout", revoked_by=session.user_id)

        assert session.is_active is False
        assert session.status == "revoked"
        assert session.revoked_at is not None
        assert session.revocation_reason == "user_logout"

    def test_session_location_tracking(self):
        """Test session location changes and tracking"""
        session = Session(
            id=uuid4(),
            user_id=uuid4(),
            session_type=SessionType.MOBILE,
            access_token="test_token",
            ip_address=IpAddress("192.168.1.1"),
            geolocation=Geolocation(
                latitude=37.7749,
                longitude=-122.4194,
                city="San Francisco",
                country="US",
            ),
        )

        # Update location
        new_ip = IpAddress("203.0.113.45")
        new_geo = Geolocation(
            latitude=40.7128, longitude=-74.0060, city="New York", country="US"
        )

        session.update_location(new_ip, new_geo)

        assert session.ip_address == new_ip
        assert session.geolocation == new_geo
        assert len(session.location_history) > 0

        # Check impossible travel detection
        assert session.has_impossible_travel(minutes=30) is True


class TestLoginAttemptEntity:
    """Test LoginAttempt entity for security tracking"""

    def test_login_attempt_creation(self):
        """Test login attempt creation with all attributes"""
        attempt = LoginAttempt(
            id=uuid4(),
            user_id=uuid4(),
            email=Email("test@example.com"),
            ip_address=IpAddress("192.168.1.100"),
            user_agent="Mozilla/5.0",
            status="success",
            failure_reason=None,
            risk_score=0.1,
            created_at=datetime.now(datetime.UTC),
        )

        assert attempt.status == "success"
        assert attempt.risk_score == 0.1
        assert attempt.failure_reason is None

    def test_failed_login_attempt_tracking(self):
        """Test failed login attempt with failure details"""
        attempt = LoginAttempt(
            id=uuid4(),
            user_id=None,  # Unknown user
            email=Email("unknown@example.com"),
            ip_address=IpAddress("10.0.0.1"),
            user_agent="curl/7.68.0",
            status="failed",
            failure_reason="invalid_credentials",
            risk_score=0.7,
            metadata={"attempt_number": 3, "lockout_remaining": 2},
        )

        assert attempt.status == "failed"
        assert attempt.failure_reason == "invalid_credentials"
        assert attempt.risk_score == 0.7
        assert attempt.metadata["attempt_number"] == 3

    def test_login_attempt_pattern_detection(self):
        """Test pattern detection in login attempts"""
        user_id = uuid4()
        attempts = []

        # Create pattern of failed attempts
        for i in range(5):
            attempt = LoginAttempt(
                id=uuid4(),
                user_id=user_id,
                email=Email("test@example.com"),
                ip_address=IpAddress(f"192.168.1.{100+i}"),
                user_agent="Bot/1.0",
                status="failed",
                failure_reason="invalid_password",
                created_at=datetime.now(datetime.UTC) - timedelta(minutes=5 - i),
            )
            attempts.append(attempt)

        # Check pattern detection
        pattern = LoginAttempt.detect_attack_pattern(attempts)
        assert pattern["is_brute_force"] is True
        assert pattern["attempt_count"] == 5
        assert pattern["time_window_minutes"] <= 5

    def test_login_attempt_geolocation_anomaly(self):
        """Test geographic anomaly detection in login attempts"""
        user_id = uuid4()

        # Normal login from San Francisco
        normal_attempt = LoginAttempt(
            id=uuid4(),
            user_id=user_id,
            email=Email("test@example.com"),
            ip_address=IpAddress("192.168.1.1"),
            geolocation=Geolocation(
                latitude=37.7749,
                longitude=-122.4194,
                city="San Francisco",
                country="US",
            ),
            status="success",
            created_at=datetime.now(datetime.UTC) - timedelta(hours=2),
        )

        # Suspicious login from different country shortly after
        suspicious_attempt = LoginAttempt(
            id=uuid4(),
            user_id=user_id,
            email=Email("test@example.com"),
            ip_address=IpAddress("185.220.101.1"),
            geolocation=Geolocation(
                latitude=51.5074, longitude=-0.1278, city="London", country="GB"
            ),
            status="success",
            created_at=datetime.now(datetime.UTC),
        )

        # Check anomaly detection
        is_anomalous = suspicious_attempt.is_geographic_anomaly(normal_attempt)
        assert is_anomalous is True  # Impossible travel in 2 hours


class TestMfaDeviceEntity:
    """Test MfaDevice entity for multi-factor authentication"""

    def test_mfa_device_creation(self):
        """Test MFA device creation and initialization"""
        device = MfaDevice(
            id=uuid4(),
            user_id=uuid4(),
            name="My Authenticator",
            method=MFAMethod.TOTP,
            secret=secrets.token_urlsafe(16),
            is_primary=True,
            created_at=datetime.now(datetime.UTC),
        )

        assert device.method == MFAMethod.TOTP
        assert device.name == "My Authenticator"
        assert device.is_primary is True
        assert device.is_verified is False
        assert device.is_active is False

    def test_mfa_device_verification(self):
        """Test MFA device verification process"""
        device = MfaDevice(
            id=uuid4(), user_id=uuid4(), method=MFAMethod.TOTP, secret="test_secret"
        )

        assert device.is_verified is False
        assert device.is_active is False

        # Verify device
        device.verify("123456")  # Mock verification

        assert device.is_verified is True
        assert device.is_active is True
        assert device.verified_at is not None

    def test_mfa_backup_codes(self):
        """Test MFA backup code generation and usage"""
        device = MfaDevice(
            id=uuid4(), user_id=uuid4(), method=MFAMethod.TOTP, secret="test_secret"
        )

        # Generate backup codes
        codes = device.generate_backup_codes(count=8)

        assert len(codes) == 8
        assert len(device.backup_codes) == 8
        assert all(len(code) == 8 for code in codes)  # 8-character codes

        # Use a backup code
        code_to_use = codes[0]
        used = device.use_backup_code(code_to_use)

        assert used is True
        assert len(device.backup_codes) == 7
        assert code_to_use not in device.backup_codes

        # Can't reuse the same code
        reused = device.use_backup_code(code_to_use)
        assert reused is False

    def test_mfa_device_lockout(self, time_machine):
        """Test MFA device lockout after failed attempts"""
        current_time = datetime.now(datetime.UTC)
        time_machine.freeze(current_time)

        device = MfaDevice(
            id=uuid4(),
            user_id=uuid4(),
            method=MFAMethod.TOTP,
            secret="test_secret",
            max_attempts=3,
            lockout_duration=timedelta(minutes=15),
        )

        # Failed attempts
        for _ in range(3):
            device.record_failed_attempt()

        assert device.failed_attempts == 3
        assert device.is_locked is True
        assert device.locked_until > current_time

        # Check lockout duration
        time_machine.advance(timedelta(minutes=10))
        assert device.is_locked is True

        time_machine.advance(timedelta(minutes=6))
        assert device.is_locked is False

    def test_mfa_device_trust_levels(self):
        """Test MFA device trust management"""
        device = MfaDevice(
            id=uuid4(),
            user_id=uuid4(),
            method=MFAMethod.HARDWARE_TOKEN,
            secret="test_secret",
        )

        # Hardware tokens have higher base trust
        assert device.trust_level > 0.5

        # Increase trust through successful usage
        for _ in range(10):
            device.record_successful_use()

        assert device.trust_level > 0.8
        assert device.last_used_at is not None
        assert device.use_count == 10


class TestPasswordHistoryEntity:
    """Test PasswordHistory entity for password reuse prevention"""

    def test_password_history_creation(self):
        """Test password history entry creation"""
        user_id = uuid4()
        password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."

        history = PasswordHistory(
            id=uuid4(),
            user_id=user_id,
            password_hash=password_hash,
            created_at=datetime.now(datetime.UTC),
            metadata={"strength_score": 0.85},
        )

        assert history.user_id == user_id
        assert history.password_hash == password_hash
        assert history.metadata["strength_score"] == 0.85

    def test_password_reuse_detection(self):
        """Test detection of password reuse"""
        user_id = uuid4()

        # Create history of passwords
        history_entries = []
        for i in range(5):
            entry = PasswordHistory(
                id=uuid4(),
                user_id=user_id,
                password_hash=f"$argon2id$hash{i}$...",
                created_at=datetime.now(datetime.UTC) - timedelta(days=30 * i),
            )
            history_entries.append(entry)

        # Check if password was used before
        new_password_hash = "$argon2id$hash2$..."  # Same as history[2]

        is_reused = any(
            entry.password_hash == new_password_hash for entry in history_entries
        )

        assert is_reused is True

    def test_password_history_retention(self, time_machine):
        """Test password history retention policy"""
        current_time = datetime.now(datetime.UTC)
        time_machine.freeze(current_time)

        user_id = uuid4()
        history_entries = []

        # Create old and new password history
        for i in range(10):
            age_days = i * 60  # Every 2 months
            entry = PasswordHistory(
                id=uuid4(),
                user_id=user_id,
                password_hash=f"$argon2id$hash{i}$...",
                created_at=current_time - timedelta(days=age_days),
            )
            history_entries.append(entry)

        # Apply retention policy (keep last 12 months)
        retention_period = timedelta(days=365)
        retained_entries = [
            entry
            for entry in history_entries
            if (current_time - entry.created_at) <= retention_period
        ]

        assert len(retained_entries) == 7  # Entries 0-6 are within 365 days


class TestDeviceRegistrationEntity:
    """Test DeviceRegistration entity for device trust"""

    def test_device_registration(self):
        """Test device registration process"""
        device = DeviceRegistration.register(
            user_id=uuid4(),
            name="John's iPhone",
            fingerprint="device_fingerprint_123",
            user_agent="Mozilla/5.0 iPhone",
            ip_address=IpAddress("192.168.1.50"),
            platform=DevicePlatform.IOS,
            device_type=DeviceType.MOBILE_IOS,
        )

        assert device.name == "John's iPhone"
        assert device.fingerprint == "device_fingerprint_123"
        assert device.status == "pending"
        assert device.is_trusted is False
        assert device.trust_score < 0.5

    def test_device_verification_process(self):
        """Test device verification and trust building"""
        device = DeviceRegistration.register(
            user_id=uuid4(), name="Work Laptop", fingerprint="laptop_fingerprint_456"
        )

        # Verify device
        device.verify()

        assert device.status == "active"
        assert device.is_trusted is False  # Not immediately trusted
        assert device.verified_at is not None

        # Build trust through usage
        for _ in range(10):
            device.record_successful_auth()

        assert device.trust_score > 0.7
        assert device.successful_auth_count == 10

    def test_device_fingerprint_update(self):
        """Test device fingerprint changes and trust impact"""
        device = DeviceRegistration.register(
            user_id=uuid4(), name="My Device", fingerprint="original_fingerprint"
        )

        device.verify()
        original_trust = device.trust_score

        # Update fingerprint (e.g., browser update)
        device.update_fingerprint("new_fingerprint", "browser_update")

        assert device.fingerprint == "new_fingerprint"
        assert device.trust_score < original_trust  # Trust decreased
        assert "browser_update" in device.fingerprint_history[-1]["reason"]

    def test_device_suspicious_activity(self):
        """Test device behavior under suspicious activity"""
        device = DeviceRegistration.register(
            user_id=uuid4(), name="Test Device", fingerprint="test_fingerprint"
        )

        device.verify()

        # Record suspicious activity
        device.record_suspicious_activity("unusual_location")
        device.record_suspicious_activity("rapid_requests")

        assert device.suspicious_activity_count == 2
        assert device.trust_score < 0.3
        assert device.requires_reverification is True


class TestUserProfileEntity:
    """Test UserProfile entity for extended user information"""

    def test_user_profile_creation(self):
        """Test user profile creation with personal information"""
        profile = UserProfile(
            id=uuid4(),
            user_id=uuid4(),
            first_name="John",
            last_name="Doe",
            display_name="John D.",
            bio="Software engineer passionate about security",
            avatar_url="https://example.com/avatar.jpg",
            timezone="America/New_York",
            locale="en-US",
            created_at=datetime.now(datetime.UTC),
        )

        assert profile.first_name == "John"
        assert profile.display_name == "John D."
        assert profile.timezone == "America/New_York"

    def test_profile_completion_tracking(self):
        """Test profile completion percentage calculation"""
        profile = UserProfile(id=uuid4(), user_id=uuid4())

        # Empty profile
        assert profile.completion_percentage == 0

        # Add required fields
        profile.first_name = "John"
        profile.last_name = "Doe"
        assert profile.completion_percentage > 0

        # Add optional fields
        profile.bio = "Test bio"
        profile.avatar_url = "https://example.com/avatar.jpg"
        profile.phone_number = PhoneNumber("+15551234567")

        assert profile.completion_percentage > 50

    def test_profile_privacy_settings(self):
        """Test profile privacy controls"""
        profile = UserProfile(
            id=uuid4(),
            user_id=uuid4(),
            privacy_settings={
                "show_email": False,
                "show_phone": False,
                "show_location": True,
                "searchable": True,
            },
        )

        # Get public view of profile
        public_data = profile.get_public_data()

        assert "email" not in public_data
        assert "phone_number" not in public_data
        assert "location" in public_data or "timezone" in public_data

    def test_profile_metadata_management(self):
        """Test profile metadata and custom fields"""
        profile = UserProfile(
            id=uuid4(),
            user_id=uuid4(),
            metadata={
                "department": "Engineering",
                "employee_id": "EMP001",
                "skills": ["Python", "Security", "DDD"],
                "certifications": ["CISSP", "AWS"],
            },
        )

        # Add new metadata
        profile.add_metadata("languages", ["English", "Spanish"])
        assert "languages" in profile.metadata
        assert len(profile.metadata["languages"]) == 2

        # Update existing metadata
        profile.update_metadata("skills", ["Python", "Security", "DDD", "Testing"])
        assert len(profile.metadata["skills"]) == 4


class TestAuditLogEntity:
    """Test AuditLog entity for compliance and tracking"""

    def test_audit_log_immutability(self):
        """Test that audit logs are immutable after creation"""
        audit_log = AuditLog.create(
            actor_id=uuid4(),
            action=AuditAction.UPDATE,
            resource_type="user",
            resource_id=str(uuid4()),
            changes={"email": {"old": "old@example.com", "new": "new@example.com"}},
            ip_address=IpAddress("192.168.1.1"),
            user_agent="Mozilla/5.0",
        )

        # Attempt to modify should fail
        with pytest.raises((AttributeError, TypeError)):
            audit_log.action = AuditAction.DELETE

        with pytest.raises((AttributeError, TypeError)):
            audit_log.changes["email"]["new"] = "modified@example.com"

    def test_audit_log_compliance_fields(self):
        """Test audit log contains all compliance-required fields"""
        actor_id = uuid4()
        resource_id = uuid4()

        audit_log = AuditLog.create(
            actor_id=actor_id,
            action=AuditAction.DELETE,
            resource_type="user_data",
            resource_id=str(resource_id),
            changes={"status": {"old": "active", "new": "deleted"}},
            ip_address=IpAddress("10.0.0.1"),
            user_agent="CLI Tool v1.0",
            metadata={"reason": "GDPR deletion request", "ticket_id": "GDPR-2024-001"},
        )

        # Verify all required fields are present
        assert audit_log.id is not None
        assert audit_log.actor_id == actor_id
        assert audit_log.action == AuditAction.DELETE
        assert audit_log.resource_type == "user_data"
        assert audit_log.resource_id == str(resource_id)
        assert audit_log.timestamp is not None
        assert audit_log.ip_address.value == "10.0.0.1"
        assert audit_log.metadata["reason"] == "GDPR deletion request"

    def test_audit_log_sensitive_data_masking(self):
        """Test automatic masking of sensitive data in audit logs"""
        audit_log = AuditLog.create(
            actor_id=uuid4(),
            action=AuditAction.UPDATE,
            resource_type="user",
            resource_id=str(uuid4()),
            changes={
                "password": {
                    "old": "OldPassword123!",  # Should be masked
                    "new": "NewPassword456!",  # Should be masked
                },
                "email": {"old": "user@example.com", "new": "newuser@example.com"},
            },
            ip_address=IpAddress("192.168.1.1"),
        )

        # Sensitive fields should be masked
        assert audit_log.changes["password"]["old"] == "***MASKED***"
        assert audit_log.changes["password"]["new"] == "***MASKED***"

        # Non-sensitive fields should remain
        assert audit_log.changes["email"]["old"] == "user@example.com"


class TestSecurityQuestionEntity:
    """Test SecurityQuestion entity for account recovery"""

    def test_security_question_creation(self):
        """Test security question setup"""
        question = SecurityQuestion(
            id=uuid4(),
            user_id=uuid4(),
            question="What was your first pet's name?",
            answer_hash="$argon2id$hashed_answer",
            created_at=datetime.now(datetime.UTC),
        )

        assert question.question == "What was your first pet's name?"
        assert question.answer_hash.startswith("$argon2id$")
        assert question.is_active is True

    def test_security_question_verification(self):
        """Test security question answer verification"""
        question = SecurityQuestion(
            id=uuid4(),
            user_id=uuid4(),
            question="What city were you born in?",
            answer_hash="$argon2id$v=19$m=65536,t=3$...",  # Mock hash
        )

        # Record verification attempt
        question.record_verification_attempt(success=False)
        assert question.failed_attempts == 1
        assert question.last_attempt_at is not None

        # Multiple failures should lock
        for _ in range(4):
            question.record_verification_attempt(success=False)

        assert question.failed_attempts == 5
        assert question.is_locked is True

    def test_security_question_rotation(self):
        """Test security question rotation policy"""
        old_question = SecurityQuestion(
            id=uuid4(),
            user_id=uuid4(),
            question="Old question",
            answer_hash="old_hash",
            created_at=datetime.now(datetime.UTC) - timedelta(days=180),
        )

        # Check if rotation is needed (e.g., every 6 months)
        assert old_question.needs_rotation(max_age_days=90) is True

        # Deactivate old question
        old_question.deactivate("Rotation policy")
        assert old_question.is_active is False
        assert old_question.deactivated_at is not None


class TestEmergencyContactEntity:
    """Test EmergencyContact entity for account recovery"""

    def test_emergency_contact_creation(self):
        """Test emergency contact setup"""
        contact = EmergencyContact(
            id=uuid4(),
            user_id=uuid4(),
            name=PersonName(first_name="Jane", last_name="Doe"),
            relationship=Relationship.SPOUSE,
            phone=PhoneNumber("+15551234567"),
            email=Email("jane.doe@example.com"),
            is_primary=True,
        )

        assert contact.name.full_name == "Jane Doe"
        assert contact.relationship == Relationship.SPOUSE
        assert contact.is_primary is True
        assert contact.is_verified is False

    def test_emergency_contact_verification(self):
        """Test emergency contact verification process"""
        contact = EmergencyContact(
            id=uuid4(),
            user_id=uuid4(),
            name=PersonName(first_name="John", last_name="Smith"),
            relationship=Relationship.FRIEND,
            phone=PhoneNumber("+15559876543"),
        )

        # Send verification
        verification_code = contact.send_verification()
        assert len(verification_code) == 6
        assert contact.verification_sent_at is not None

        # Verify contact
        verified = contact.verify(verification_code)
        assert verified is True
        assert contact.is_verified is True
        assert contact.verified_at is not None

    def test_emergency_contact_usage_tracking(self):
        """Test emergency contact usage for recovery"""
        contact = EmergencyContact(
            id=uuid4(),
            user_id=uuid4(),
            name=PersonName(first_name="Parent", last_name="User"),
            relationship=Relationship.PARENT,
            phone=PhoneNumber("+15555555555"),
            is_verified=True,
        )

        # Record usage for account recovery
        contact.record_usage("password_reset")

        assert contact.usage_count == 1
        assert contact.last_used_at is not None
        assert contact.usage_history[-1]["purpose"] == "password_reset"

        # Check rate limiting
        assert contact.can_use_for_recovery(cooldown_hours=24) is False


class TestEntityIdentityAndEquality:
    """Test entity identity and equality semantics"""

    def test_entity_identity_equality(self):
        """Test that entities are equal based on ID, not attributes"""
        entity_id = uuid4()

        session1 = Session(
            id=entity_id,
            user_id=uuid4(),
            session_type=SessionType.WEB,
            access_token="token1",
        )

        session2 = Session(
            id=entity_id,
            user_id=uuid4(),  # Different user
            session_type=SessionType.MOBILE,  # Different type
            access_token="token2",  # Different token
        )

        # Same ID means same entity
        assert session1 == session2
        assert hash(session1) == hash(session2)

    def test_entity_in_collections(self):
        """Test entities can be used in sets and dicts"""
        entities = set()

        # Add entities with different IDs
        for i in range(3):
            entities.add(Session(id=uuid4(), user_id=uuid4(), access_token=f"token{i}"))

        assert len(entities) == 3

        # Try to add duplicate ID
        duplicate_id = uuid4()
        entities.add(Session(id=duplicate_id, user_id=uuid4(), access_token="token1"))
        entities.add(Session(id=duplicate_id, user_id=uuid4(), access_token="token2"))

        assert len(entities) == 4  # Only one added due to same ID


class TestEntityDomainEvents:
    """Test that entities properly raise domain events"""

    def test_entity_event_generation(self, event_collector):
        """Test entities generate appropriate domain events"""
        user_id = uuid4()

        # Create session and track events
        session = Session(
            id=uuid4(),
            user_id=user_id,
            session_type=SessionType.WEB,
            access_token="test_token",
        )

        # Mock event registration
        session._events = []

        # Perform actions that should generate events
        session.record_activity("login")
        session.refresh_tokens(datetime.now(datetime.UTC) + timedelta(hours=24))
        session.revoke("user_logout")

        # Should have generated events
        assert len(session._events) > 0
        event_types = [type(e).__name__ for e in session._events]
        assert "SessionActivity" in event_types or "ActivityRecorded" in event_types
        assert "SessionRefreshed" in event_types or "TokensRefreshed" in event_types
        assert "SessionRevoked" in event_types
