"""
Comprehensive tests for all domain services in the identity domain.

Test Coverage:
- Service method functionality
- Business logic orchestration
- Error handling and edge cases
- Dependencies and mocking
- Performance benchmarks
- Security validation
"""

import asyncio
import secrets
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.modules.identity.domain.entities import *
from app.modules.identity.domain.enums import *
from app.modules.identity.domain.errors import *
from app.modules.identity.domain.events import *
from app.modules.identity.domain.services import *
from app.modules.identity.domain.specifications import *
from app.modules.identity.domain.value_objects import *


class TestAuthorizationService:
    """Test AuthorizationService business logic orchestration"""

    @pytest.fixture
    def auth_service(self, mock_repositories):
        """Create AuthorizationService with mocked dependencies"""
        return AuthorizationService(
            user_repository=mock_repositories["user_repository"],
            role_repository=mock_repositories["role_repository"],
            permission_repository=mock_repositories["permission_repository"],
        )

    @pytest.mark.asyncio
    async def test_check_permission_basic(self, auth_service, mock_repositories):
        """Test basic permission checking"""
        user_id = uuid4()
        context = AuthorizationContext(
            user_id=user_id,
            resource_type="report",
            resource_id="report_123",
            action="read",
            context_data={"department_id": "sales"},
        )

        # Setup mocks
        user = UserFactory(id=user_id, status=UserStatus.ACTIVE)
        role = RoleFactory(name="Manager")
        permission = PermissionFactory(
            resource="report", action="read", scope=PermissionScope.DEPARTMENT
        )

        mock_repositories["user_repository"].get_by_id.return_value = user
        mock_repositories["role_repository"].get_user_roles.return_value = [role]
        mock_repositories["permission_repository"].get_user_permissions.return_value = [
            permission
        ]

        # Test
        result = await auth_service.check_permission(context, "read_report")

        assert result.allowed is True
        assert result.user_id == user_id
        assert result.permission == "read_report"
        assert result.reason == "Permission granted through role"

    @pytest.mark.asyncio
    async def test_check_permission_denied_inactive_user(
        self, auth_service, mock_repositories
    ):
        """Test permission denied for inactive user"""
        user_id = uuid4()
        context = AuthorizationContext(
            user_id=user_id,
            resource_type="report",
            resource_id="report_123",
            action="read",
        )

        # Setup inactive user
        user = UserFactory(id=user_id, status=UserStatus.SUSPENDED)
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Test
        result = await auth_service.check_permission(context, "read_report")

        assert result.allowed is False
        assert result.reason == "User is not active"
        assert result.denial_code == "USER_INACTIVE"

    @pytest.mark.asyncio
    async def test_check_permission_with_wildcard(
        self, auth_service, mock_repositories
    ):
        """Test permission checking with wildcard permissions"""
        user_id = uuid4()
        context = AuthorizationContext(
            user_id=user_id, resource_type="users", action="delete"
        )

        # Setup admin with wildcard permission
        user = UserFactory(id=user_id, status=UserStatus.ACTIVE)
        admin_permission = PermissionFactory(
            name="admin_all", resource="*", action="*", scope=PermissionScope.GLOBAL
        )

        mock_repositories["user_repository"].get_by_id.return_value = user
        mock_repositories["permission_repository"].get_user_permissions.return_value = [
            admin_permission
        ]

        # Test
        result = await auth_service.check_permission(context, "delete_user")

        assert result.allowed is True
        assert "wildcard" in result.metadata.get("match_type", "")

    @pytest.mark.asyncio
    async def test_get_user_effective_permissions(
        self, auth_service, mock_repositories
    ):
        """Test getting all effective permissions for a user"""
        user_id = uuid4()

        # Setup permissions hierarchy
        direct_permission = PermissionFactory(
            name="read_profile", resource="profile", action="read"
        )
        role_permission = PermissionFactory(
            name="manage_team", resource="team", action="*"
        )

        mock_repositories[
            "permission_repository"
        ].get_direct_permissions.return_value = [direct_permission]
        mock_repositories["permission_repository"].get_user_permissions.return_value = [
            direct_permission,
            role_permission,
        ]

        # Test
        permissions = await auth_service.get_user_effective_permissions(user_id)

        assert len(permissions) == 2
        assert direct_permission in permissions
        assert role_permission in permissions

    @pytest.mark.asyncio
    async def test_check_role_permission_context_aware(
        self, auth_service, mock_repositories
    ):
        """Test context-aware role permission checking"""
        user_id = uuid4()
        role_id = uuid4()

        # Setup department-scoped role
        user = UserFactory(id=user_id, status=UserStatus.ACTIVE)
        role = RoleFactory(
            id=role_id, name="Department Manager", conditions={"department_id": "sales"}
        )

        mock_repositories["user_repository"].get_by_id.return_value = user
        mock_repositories["role_repository"].get_by_id.return_value = role
        mock_repositories["role_repository"].get_user_roles.return_value = [role]

        # Test with matching context
        context_data = {"department_id": "sales"}
        result = await auth_service.check_role(user_id, role_id, context_data)
        assert result.has_role is True

        # Test with non-matching context
        context_data = {"department_id": "marketing"}
        result = await auth_service.check_role(user_id, role_id, context_data)
        assert result.has_role is False
        assert result.reason == "Role context requirements not met"

    @pytest.mark.asyncio
    async def test_get_resource_permissions(self, auth_service, mock_repositories):
        """Test getting all permissions for a resource"""
        resource_type = "report"
        resource_id = "financial_report_2024"

        permissions = [
            PermissionFactory(name="read_report", resource="report", action="read"),
            PermissionFactory(name="edit_report", resource="report", action="write"),
            PermissionFactory(name="delete_report", resource="report", action="delete"),
        ]

        mock_repositories[
            "permission_repository"
        ].get_resource_permissions.return_value = permissions

        # Test
        result = await auth_service.get_resource_permissions(resource_type, resource_id)

        assert len(result) == 3
        assert all(p.resource == "report" for p in result)


class TestSecurityService:
    """Test SecurityService threat detection and response"""

    @pytest.fixture
    def security_service(self, mock_repositories):
        """Create SecurityService with mocked dependencies"""
        return SecurityService(
            user_repository=mock_repositories["user_repository"],
            session_repository=mock_repositories["session_repository"],
            security_repository=mock_repositories["security_repository"],
            audit_repository=mock_repositories["audit_repository"],
        )

    @pytest.mark.asyncio
    async def test_detect_brute_force_attack(self, security_service, mock_repositories):
        """Test brute force attack detection"""
        email = "target@example.com"

        # Setup failed login attempts
        failed_attempts = []
        for i in range(10):
            attempt = LoginAttempt(
                id=uuid4(),
                email=email,
                ip_address=f"192.168.1.{i}",
                user_agent="Mozilla/5.0",
                success=False,
                failure_reason="Invalid password",
                created_at=datetime.now(datetime.UTC) - timedelta(minutes=i),
            )
            failed_attempts.append(attempt)

        mock_repositories[
            "security_repository"
        ].get_recent_login_attempts.return_value = failed_attempts

        # Test
        threat = await security_service.detect_threats(
            {"email": email, "event_type": "login_failed"}
        )

        assert threat.detected is True
        assert threat.threat_type == SecurityEventType.BRUTE_FORCE_ATTACK
        assert threat.risk_score >= 0.8
        assert "brute_force" in threat.indicators
        assert threat.recommended_actions == [
            "lock_account",
            "notify_user",
            "require_password_reset",
        ]

    @pytest.mark.asyncio
    async def test_detect_credential_stuffing(
        self, security_service, mock_repositories
    ):
        """Test credential stuffing attack detection"""
        # Multiple failed attempts from different IPs in short time
        attempts = []
        base_time = datetime.now(datetime.UTC)

        for i in range(20):
            attempt = LoginAttempt(
                id=uuid4(),
                email=f"user{i % 5}@example.com",
                ip_address=f"185.220.101.{i}",  # Tor exit nodes range
                user_agent="curl/7.68.0",  # Suspicious user agent
                success=False,
                failure_reason="Invalid password",
                created_at=base_time - timedelta(seconds=i * 2),
            )
            attempts.append(attempt)

        mock_repositories[
            "security_repository"
        ].get_recent_login_attempts.return_value = attempts

        # Test
        threat = await security_service.detect_threats(
            {"ip_address": "185.220.101.10", "event_type": "login_failed"}
        )

        assert threat.detected is True
        assert threat.threat_type == SecurityEventType.CREDENTIAL_STUFFING
        assert "automated_tool" in threat.indicators
        assert "distributed_ips" in threat.indicators

    @pytest.mark.asyncio
    async def test_validate_login_context_normal(
        self, security_service, mock_repositories
    ):
        """Test login context validation for normal login"""
        user_id = uuid4()

        # Setup normal login context
        context = {
            "user_id": user_id,
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            "location": {"country": "US", "city": "San Francisco"},
            "device_fingerprint": "known_device_123",
        }

        # Setup user login history
        login_history = [
            LoginAttempt(
                id=uuid4(),
                user_id=user_id,
                ip_address="192.168.1.100",
                location={"country": "US", "city": "San Francisco"},
                success=True,
                created_at=datetime.now(datetime.UTC) - timedelta(days=1),
            )
        ]

        mock_repositories[
            "security_repository"
        ].get_user_login_history.return_value = login_history

        # Test
        result = await security_service.validate_login_context(context)

        assert result.is_valid is True
        assert result.risk_score < 0.3
        assert result.risk_factors == []

    @pytest.mark.asyncio
    async def test_validate_login_context_suspicious(
        self, security_service, mock_repositories, security_test_helper
    ):
        """Test login context validation for suspicious login"""
        user_id = uuid4()

        # Setup suspicious context
        context = security_test_helper.create_high_risk_context()
        context["user_id"] = user_id

        # Setup user's normal pattern
        normal_history = []
        for i in range(10):
            attempt = LoginAttempt(
                id=uuid4(),
                user_id=user_id,
                ip_address="192.168.1.1",
                location={"country": "US", "city": "New York"},
                success=True,
                created_at=datetime.now(datetime.UTC) - timedelta(days=i),
            )
            normal_history.append(attempt)

        mock_repositories[
            "security_repository"
        ].get_user_login_history.return_value = normal_history

        # Test
        result = await security_service.validate_login_context(context)

        assert result.is_valid is False
        assert result.risk_score > 0.7
        assert "tor_exit_node" in result.risk_factors
        assert "unusual_location" in result.risk_factors
        assert result.requires_mfa is True

    @pytest.mark.asyncio
    async def test_handle_security_incident(
        self, security_service, mock_repositories, event_collector
    ):
        """Test security incident handling"""
        user_id = uuid4()

        incident = SecurityIncident(
            user_id=user_id,
            incident_type=SecurityEventType.SUSPICIOUS_LOGIN,
            severity=RiskLevel.HIGH,
            details={
                "ip_address": "185.220.101.1",
                "location": "Unknown",
                "indicators": ["tor_exit_node", "new_device"],
            },
        )

        # Test
        response = await security_service.handle_security_incident(incident)

        assert response.incident_id is not None
        assert response.actions_taken == [
            "lock_account",
            "notify_user",
            "force_logout",
            "log_incident",
        ]
        assert response.status == "contained"

        # Verify repositories called
        mock_repositories["security_repository"].log_security_event.assert_called_once()
        mock_repositories[
            "session_repository"
        ].revoke_all_sessions.assert_called_once_with(user_id)

    @pytest.mark.asyncio
    async def test_analyze_user_behavior_patterns(
        self, security_service, mock_repositories
    ):
        """Test user behavior pattern analysis"""
        user_id = uuid4()

        # Setup behavior patterns
        patterns = {
            "login_times": [9, 10, 11, 14, 15, 16],  # Business hours
            "ip_addresses": ["192.168.1.1", "192.168.1.2"],
            "locations": ["US/New York", "US/New York"],
            "devices": ["device_123", "device_456"],
            "failed_attempts": 2,
            "success_rate": 0.95,
        }

        mock_repositories[
            "security_repository"
        ].get_user_patterns.return_value = patterns

        # Test normal behavior
        analysis = await security_service.analyze_user_behavior(
            user_id,
            {"login_time": 10, "ip_address": "192.168.1.1", "location": "US/New York"},
        )

        assert analysis.anomaly_score < 0.3
        assert analysis.is_anomalous is False

        # Test anomalous behavior
        analysis = await security_service.analyze_user_behavior(
            user_id,
            {
                "login_time": 3,  # 3 AM
                "ip_address": "185.220.101.1",  # Tor
                "location": "Unknown",
            },
        )

        assert analysis.anomaly_score > 0.7
        assert analysis.is_anomalous is True
        assert "unusual_time" in analysis.anomalies
        assert "unknown_location" in analysis.anomalies


class TestPasswordService:
    """Test PasswordService password management"""

    @pytest.fixture
    def password_service(self, mock_repositories):
        """Create PasswordService with mocked dependencies"""
        return PasswordService(
            user_repository=mock_repositories["user_repository"],
            password_repository=mock_repositories.get(
                "password_repository", AsyncMock()
            ),
            security_repository=mock_repositories["security_repository"],
        )

    @pytest.mark.asyncio
    async def test_validate_password_strength_strong(self, password_service):
        """Test password strength validation for strong password"""
        result = await password_service.validate_password_strength(
            "MyStr0ng!P@ssw0rd123",
            user_context={"username": "testuser", "email": "test@example.com"},
        )

        assert result.is_valid is True
        assert result.strength_score >= 0.8
        assert result.entropy > 60
        assert "length" in result.passed_criteria
        assert "uppercase" in result.passed_criteria
        assert "lowercase" in result.passed_criteria
        assert "numbers" in result.passed_criteria
        assert "special_chars" in result.passed_criteria

    @pytest.mark.asyncio
    async def test_validate_password_strength_weak(self, password_service):
        """Test password strength validation for weak password"""
        result = await password_service.validate_password_strength("password123")

        assert result.is_valid is False
        assert result.strength_score < 0.5
        assert "common_password" in result.issues
        assert result.suggestions != []

    @pytest.mark.asyncio
    async def test_validate_password_with_user_info(self, password_service):
        """Test password validation prevents using user info"""
        result = await password_service.validate_password_strength(
            "JohnDoe2024!",
            user_context={
                "username": "johndoe",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
            },
        )

        assert result.is_valid is False
        assert "contains_user_info" in result.issues
        assert result.suggestions == ["Avoid using personal information in passwords"]

    @pytest.mark.asyncio
    async def test_check_password_history(self, password_service, mock_repositories):
        """Test password history checking"""
        user_id = uuid4()
        new_password_hash = "$argon2id$v=19$m=65536,t=3,p=4$new_hash"

        # Setup password history
        history = [
            PasswordHistory(
                id=uuid4(),
                user_id=user_id,
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$old_hash_1",
                created_at=datetime.now(datetime.UTC) - timedelta(days=30),
            ),
            PasswordHistory(
                id=uuid4(),
                user_id=user_id,
                password_hash="$argon2id$v=19$m=65536,t=3,p=4$old_hash_2",
                created_at=datetime.now(datetime.UTC) - timedelta(days=60),
            ),
        ]

        mock_repositories[
            "password_repository"
        ].get_password_history.return_value = history

        # Test new password
        result = await password_service.check_password_history(
            user_id, new_password_hash
        )
        assert result.is_reused is False

        # Test reused password
        result = await password_service.check_password_history(
            user_id, history[0].password_hash
        )
        assert result.is_reused is True
        assert result.last_used_date == history[0].created_at

    @pytest.mark.asyncio
    async def test_check_password_breach(self, password_service):
        """Test checking password against breach databases"""
        # Test known breached password
        result = await password_service.check_password_breach("password123")
        assert result.is_breached is True
        assert result.breach_count > 1000000
        assert result.severity == RiskLevel.CRITICAL

        # Test unique password
        unique_password = f"UniqueTestPassword{uuid4().hex}"
        result = await password_service.check_password_breach(unique_password)
        assert result.is_breached is False
        assert result.breach_count == 0

    @pytest.mark.asyncio
    async def test_generate_secure_password(self, password_service):
        """Test secure password generation"""
        # Test with default options
        password = await password_service.generate_secure_password()
        assert len(password) >= 16
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(c in "!@#$%^&*" for c in password)

        # Test with custom options
        options = PasswordGenerationOptions(
            length=24,
            include_symbols=False,
            exclude_ambiguous=True,
            require_all_types=True,
        )
        password = await password_service.generate_secure_password(options)
        assert len(password) == 24
        assert not any(c in "!@#$%^&*" for c in password)
        assert not any(c in "0O1lI" for c in password)  # Ambiguous chars

    @pytest.mark.asyncio
    async def test_calculate_password_entropy(self, password_service):
        """Test password entropy calculation"""
        # Low entropy
        entropy = await password_service.calculate_entropy("password")
        assert entropy < 30

        # Medium entropy
        entropy = await password_service.calculate_entropy("Password123")
        assert 30 <= entropy < 50

        # High entropy
        entropy = await password_service.calculate_entropy("MyC0mpl3x!P@ssw0rd#2024")
        assert entropy > 70

    @pytest.mark.asyncio
    async def test_password_expiry_check(self, password_service, mock_repositories):
        """Test password expiry checking"""
        user_id = uuid4()

        # Setup user with old password
        user = UserFactory(
            id=user_id,
            password_changed_at=datetime.now(datetime.UTC) - timedelta(days=100),
        )
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Test expired password
        result = await password_service.check_password_expiry(user_id, max_age_days=90)
        assert result.is_expired is True
        assert result.days_until_expiry == -10
        assert result.requires_change is True

        # Test valid password
        user.password_changed_at = datetime.now(datetime.UTC) - timedelta(days=30)
        result = await password_service.check_password_expiry(user_id, max_age_days=90)
        assert result.is_expired is False
        assert result.days_until_expiry == 60


class TestMFAService:
    """Test MFAService multi-factor authentication"""

    @pytest.fixture
    def mfa_service(self, mock_repositories):
        """Create MFAService with mocked dependencies"""
        return MFAService(
            user_repository=mock_repositories["user_repository"],
            mfa_repository=mock_repositories["mfa_repository"],
        )

    @pytest.mark.asyncio
    async def test_setup_totp_device(self, mfa_service, mock_repositories):
        """Test TOTP device setup"""
        user_id = uuid4()

        # Test setup
        result = await mfa_service.setup_mfa_device(
            user_id=user_id, method=MFAMethod.TOTP, device_name="Google Authenticator"
        )

        assert result.method == MFAMethod.TOTP
        assert result.secret is not None
        assert len(result.secret) >= 16
        assert result.qr_code is not None
        assert result.backup_codes is not None
        assert len(result.backup_codes) == 10
        assert result.device_id is not None

        # Verify repository called
        mock_repositories["mfa_repository"].create_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_totp_code(self, mfa_service, mock_repositories):
        """Test TOTP code verification"""
        user_id = uuid4()
        device_id = uuid4()
        secret = "JBSWY3DPEHPK3PXP"  # Test secret

        # Setup device
        device = MfaDeviceFactory(
            id=device_id,
            user_id=user_id,
            method=MFAMethod.TOTP,
            secret=secret,
            is_verified=True,
        )
        mock_repositories["mfa_repository"].get_device.return_value = device

        # Generate valid TOTP code
        import pyotp

        totp = pyotp.TOTP(secret)
        valid_code = totp.now()

        # Test valid code
        result = await mfa_service.verify_mfa_code(
            user_id=user_id, device_id=device_id, code=valid_code
        )

        assert result.is_valid is True
        assert result.device_id == device_id
        assert result.method == MFAMethod.TOTP

    @pytest.mark.asyncio
    async def test_verify_backup_code(self, mfa_service, mock_repositories):
        """Test backup code verification"""
        user_id = uuid4()
        device_id = uuid4()
        backup_codes = ["1234-5678", "9012-3456", "5678-9012"]

        # Setup device with backup codes
        device = MfaDeviceFactory(
            id=device_id,
            user_id=user_id,
            method=MFAMethod.TOTP,
            backup_codes=backup_codes,
        )
        mock_repositories["mfa_repository"].get_user_devices.return_value = [device]

        # Test valid backup code
        result = await mfa_service.verify_backup_code(user_id, "1234-5678")

        assert result.is_valid is True
        assert result.remaining_codes == 2
        assert "1234-5678" not in device.backup_codes  # Code consumed

    @pytest.mark.asyncio
    async def test_send_sms_verification(self, mfa_service, mock_repositories):
        """Test SMS verification code sending"""
        user_id = uuid4()
        phone_number = PhoneNumber("+15551234567")

        # Setup SMS device
        device = MfaDeviceFactory(
            user_id=user_id, method=MFAMethod.SMS, phone_number=str(phone_number)
        )
        mock_repositories["mfa_repository"].get_user_devices.return_value = [device]

        # Test sending
        with patch(
            "app.modules.identity.domain.services.mfa_service.send_sms"
        ) as mock_sms:
            result = await mfa_service.send_verification_code(
                user_id=user_id, method=MFAMethod.SMS
            )

            assert result.sent is True
            assert result.method == MFAMethod.SMS
            assert result.masked_destination == "+1555***4567"
            mock_sms.assert_called_once()

    @pytest.mark.asyncio
    async def test_device_lockout_after_failures(self, mfa_service, mock_repositories):
        """Test device lockout after multiple failures"""
        user_id = uuid4()
        device_id = uuid4()

        # Setup device with failed attempts
        device = MfaDeviceFactory(id=device_id, user_id=user_id, failed_attempts=4)
        mock_repositories["mfa_repository"].get_device.return_value = device

        # Test one more failure triggers lockout
        result = await mfa_service.verify_mfa_code(
            user_id=user_id, device_id=device_id, code="wrong_code"
        )

        assert result.is_valid is False
        assert result.locked_out is True
        assert device.failed_attempts == 5
        assert device.locked_until is not None
        assert device.locked_until > datetime.now(datetime.UTC)

    @pytest.mark.asyncio
    async def test_require_mfa_for_sensitive_operation(
        self, mfa_service, mock_repositories
    ):
        """Test MFA requirement for sensitive operations"""
        user_id = uuid4()

        # User with MFA enabled
        user = UserFactory(id=user_id, mfa_enabled=True)
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Test sensitive operations
        sensitive_ops = [
            "change_password",
            "disable_mfa",
            "add_payment_method",
            "delete_account",
            "export_data",
        ]

        for operation in sensitive_ops:
            result = await mfa_service.is_mfa_required_for_operation(user_id, operation)
            assert result.required is True
            assert result.reason == "Sensitive operation requires MFA"


class TestSessionService:
    """Test SessionService session management"""

    @pytest.fixture
    def session_service(self, mock_repositories):
        """Create SessionService with mocked dependencies"""
        return SessionService(
            session_repository=mock_repositories["session_repository"],
            user_repository=mock_repositories["user_repository"],
            device_repository=mock_repositories["device_repository"],
        )

    @pytest.mark.asyncio
    async def test_create_session_normal(self, session_service, mock_repositories):
        """Test normal session creation"""
        user_id = uuid4()

        session_data = {
            "user_id": user_id,
            "ip_address": IpAddress("192.168.1.1"),
            "user_agent": "Mozilla/5.0 Chrome/91.0",
            "device_fingerprint": "device_123",
            "session_type": SessionType.WEB,
        }

        # Mock user
        user = UserFactory(id=user_id, status=UserStatus.ACTIVE)
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Test
        result = await session_service.create_session(session_data)

        assert result.session_id is not None
        assert result.access_token is not None
        assert result.refresh_token is not None
        assert result.expires_at > datetime.now(datetime.UTC)
        assert result.session_type == SessionType.WEB

        # Verify repository called
        mock_repositories["session_repository"].create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_with_concurrent_limit(
        self, session_service, mock_repositories
    ):
        """Test session creation with concurrent session limits"""
        user_id = uuid4()

        # Setup existing sessions
        existing_sessions = []
        for _i in range(5):
            session = SessionFactory(user_id=user_id, is_active=True)
            existing_sessions.append(session)

        mock_repositories[
            "session_repository"
        ].get_active_sessions.return_value = existing_sessions

        # Test creating new session (should revoke oldest)
        session_data = {
            "user_id": user_id,
            "ip_address": IpAddress("192.168.1.1"),
            "user_agent": "Mozilla/5.0",
            "session_type": SessionType.WEB,
        }

        user = UserFactory(id=user_id)
        mock_repositories["user_repository"].get_by_id.return_value = user

        result = await session_service.create_session(session_data, max_concurrent=5)

        assert result.session_id is not None
        # Verify oldest session was revoked
        mock_repositories["session_repository"].revoke_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_session_token(self, session_service, mock_repositories):
        """Test session token validation"""
        session_id = uuid4()
        access_token = secrets.token_urlsafe(32)

        # Setup valid session
        session = SessionFactory(
            id=session_id,
            access_token=access_token,
            expires_at=datetime.now(datetime.UTC) + timedelta(hours=1),
            is_active=True,
        )
        mock_repositories["session_repository"].get_by_token.return_value = session

        # Test valid token
        result = await session_service.validate_session(access_token)

        assert result.is_valid is True
        assert result.session_id == session_id
        assert result.remaining_time > timedelta(minutes=50)

    @pytest.mark.asyncio
    async def test_validate_expired_session(self, session_service, mock_repositories):
        """Test expired session validation"""
        access_token = secrets.token_urlsafe(32)

        # Setup expired session
        session = SessionFactory(
            access_token=access_token,
            expires_at=datetime.now(datetime.UTC) - timedelta(hours=1),
            is_active=True,
        )
        mock_repositories["session_repository"].get_by_token.return_value = session

        # Test
        result = await session_service.validate_session(access_token)

        assert result.is_valid is False
        assert result.error == "Session expired"

        # Verify session was revoked
        mock_repositories["session_repository"].revoke_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_session_token(self, session_service, mock_repositories):
        """Test session token refresh"""
        session_id = uuid4()
        refresh_token = secrets.token_urlsafe(32)

        # Setup session
        session = SessionFactory(
            id=session_id,
            refresh_token=refresh_token,
            refresh_expires_at=datetime.now(datetime.UTC) + timedelta(days=7),
            is_active=True,
        )
        mock_repositories[
            "session_repository"
        ].get_by_refresh_token.return_value = session

        # Test
        result = await session_service.refresh_session(refresh_token)

        assert result.success is True
        assert result.new_access_token is not None
        assert result.new_refresh_token is not None
        assert result.new_access_token != session.access_token

    @pytest.mark.asyncio
    async def test_session_risk_assessment(self, session_service, mock_repositories):
        """Test session risk assessment"""
        session_id = uuid4()

        # Setup risky session
        session = SessionFactory(
            id=session_id,
            ip_address=IpAddress("185.220.101.1"),  # Tor exit node
            risk_score=0.8,
            anomaly_detected=True,
        )
        mock_repositories["session_repository"].get.return_value = session

        # Test
        assessment = await session_service.assess_session_risk(session_id)

        assert assessment.risk_level == RiskLevel.HIGH
        assert assessment.risk_score >= 0.8
        assert "tor_exit_node" in assessment.risk_factors
        assert assessment.requires_reauthentication is True

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_service, mock_repositories):
        """Test cleanup of expired sessions"""
        # Setup expired sessions
        expired_sessions = []
        for i in range(10):
            session = SessionFactory(
                expires_at=datetime.now(datetime.UTC) - timedelta(hours=i + 1),
                is_active=True,
            )
            expired_sessions.append(session)

        mock_repositories[
            "session_repository"
        ].get_expired_sessions.return_value = expired_sessions

        # Test cleanup
        result = await session_service.cleanup_expired_sessions()

        assert result.cleaned_count == 10
        assert result.success is True

        # Verify all sessions deleted
        assert mock_repositories["session_repository"].delete_sessions.call_count == 1
        deleted_ids = mock_repositories["session_repository"].delete_sessions.call_args[
            0
        ][0]
        assert len(deleted_ids) == 10


class TestRiskAssessmentService:
    """Test RiskAssessmentService risk calculation"""

    @pytest.fixture
    def risk_service(self, mock_repositories):
        """Create RiskAssessmentService with mocked dependencies"""
        return RiskAssessmentService(
            security_repository=mock_repositories["security_repository"],
            user_repository=mock_repositories["user_repository"],
        )

    @pytest.mark.asyncio
    async def test_calculate_login_risk_low(self, risk_service, mock_repositories):
        """Test low risk login calculation"""
        user_id = uuid4()

        context = {
            "user_id": user_id,
            "ip_address": "192.168.1.1",
            "location": {"country": "US", "city": "New York"},
            "device_fingerprint": "known_device",
            "time_of_day": 10,  # 10 AM
        }

        # Setup normal user patterns
        patterns = {
            "usual_locations": ["US/New York"],
            "usual_ips": ["192.168.1.1", "192.168.1.2"],
            "usual_devices": ["known_device"],
            "usual_hours": [9, 10, 11, 14, 15, 16],
        }
        mock_repositories[
            "security_repository"
        ].get_user_patterns.return_value = patterns

        # Test
        result = await risk_service.calculate_login_risk(context)

        assert result.risk_score < 0.3
        assert result.risk_level == RiskLevel.LOW
        assert result.factors == {}

    @pytest.mark.asyncio
    async def test_calculate_login_risk_high(self, risk_service, mock_repositories):
        """Test high risk login calculation"""
        user_id = uuid4()

        context = {
            "user_id": user_id,
            "ip_address": "185.220.101.1",  # Tor
            "location": {"country": "Unknown"},
            "device_fingerprint": "new_device",
            "time_of_day": 3,  # 3 AM
            "failed_attempts": 5,
        }

        # Setup normal patterns
        patterns = {
            "usual_locations": ["US/New York"],
            "usual_ips": ["192.168.1.1"],
            "usual_devices": ["device_123"],
            "usual_hours": [9, 10, 11, 14, 15, 16],
            "average_failed_attempts": 0.1,
        }
        mock_repositories[
            "security_repository"
        ].get_user_patterns.return_value = patterns

        # Test
        result = await risk_service.calculate_login_risk(context)

        assert result.risk_score > 0.8
        assert result.risk_level == RiskLevel.CRITICAL
        assert "tor_network" in result.factors
        assert "unusual_time" in result.factors
        assert "new_device" in result.factors
        assert "failed_attempts" in result.factors

    @pytest.mark.asyncio
    async def test_assess_user_trust_score(self, risk_service, mock_repositories):
        """Test user trust score assessment"""
        user_id = uuid4()

        # Setup trusted user profile
        user = UserFactory(
            id=user_id,
            email_verified=True,
            mfa_enabled=True,
            created_at=datetime.now(datetime.UTC) - timedelta(days=365),  # 1 year old
            failed_login_count=0,
        )
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Setup good security history
        security_events = []  # No security incidents
        mock_repositories[
            "security_repository"
        ].get_user_security_events.return_value = security_events

        # Test
        result = await risk_service.assess_user_trust_score(user_id)

        assert result.trust_score > 0.8
        assert result.trust_level == "high"
        assert "account_age" in result.positive_factors
        assert "mfa_enabled" in result.positive_factors
        assert "email_verified" in result.positive_factors

    @pytest.mark.asyncio
    async def test_detect_impossible_travel(self, risk_service):
        """Test impossible travel detection"""
        locations = [
            {
                "city": "New York",
                "country": "US",
                "lat": 40.7128,
                "lon": -74.0060,
                "timestamp": datetime.now(datetime.UTC),
            },
            {
                "city": "London",
                "country": "GB",
                "lat": 51.5074,
                "lon": -0.1278,
                "timestamp": datetime.now(datetime.UTC) + timedelta(hours=1),
            },
        ]

        # Test
        result = await risk_service.detect_impossible_travel(locations)

        assert result.detected is True
        assert result.distance_km > 5000
        assert result.time_hours == 1
        assert result.minimum_travel_hours > 5
        assert result.probability < 0.01

    @pytest.mark.asyncio
    async def test_calculate_transaction_risk(self, risk_service):
        """Test transaction risk calculation"""
        context = {
            "amount": 10000,
            "currency": "USD",
            "recipient": "unknown_account",
            "user_typical_amount": 100,
            "location": "US",
            "device": "new_device",
        }

        # Test
        result = await risk_service.calculate_transaction_risk(context)

        assert result.risk_score > 0.7
        assert "high_amount" in result.factors
        assert "amount_deviation" in result.factors
        assert "new_device" in result.factors


class TestDomainServiceIntegration:
    """Test integration between domain services"""

    @pytest.mark.asyncio
    async def test_login_flow_with_mfa(self, mock_repositories):
        """Test complete login flow with MFA"""
        user_id = uuid4()

        # Setup services
        AuthorizationService(
            mock_repositories["user_repository"],
            mock_repositories["role_repository"],
            mock_repositories["permission_repository"],
        )
        security_service = SecurityService(
            mock_repositories["user_repository"],
            mock_repositories["session_repository"],
            mock_repositories["security_repository"],
            mock_repositories["audit_repository"],
        )
        mfa_service = MFAService(
            mock_repositories["user_repository"], mock_repositories["mfa_repository"]
        )
        session_service = SessionService(
            mock_repositories["session_repository"],
            mock_repositories["user_repository"],
            mock_repositories["device_repository"],
        )

        # Setup user with MFA
        user = UserFactory(id=user_id, mfa_enabled=True, status=UserStatus.ACTIVE)
        mock_repositories["user_repository"].get_by_id.return_value = user

        # Step 1: Validate login context
        login_context = {
            "user_id": user_id,
            "ip_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
        }

        mock_repositories[
            "security_repository"
        ].get_user_login_history.return_value = []
        validation = await security_service.validate_login_context(login_context)
        assert validation.is_valid is True

        # Step 2: Check MFA requirement
        mfa_required = await mfa_service.is_mfa_required_for_operation(user_id, "login")
        assert mfa_required.required is True

        # Step 3: Verify MFA code
        device = MfaDeviceFactory(
            user_id=user_id, method=MFAMethod.TOTP, is_verified=True
        )
        mock_repositories["mfa_repository"].get_user_devices.return_value = [device]
        mock_repositories["mfa_repository"].get_device.return_value = device

        await mfa_service.verify_mfa_code(user_id, device.id, "123456")
        # Assuming valid code for test

        # Step 4: Create session
        session_data = {
            "user_id": user_id,
            "ip_address": IpAddress("192.168.1.1"),
            "user_agent": "Mozilla/5.0",
            "session_type": SessionType.WEB,
            "mfa_verified": True,
        }

        session_result = await session_service.create_session(session_data)
        assert session_result.session_id is not None
        assert session_result.access_token is not None

    @pytest.mark.asyncio
    async def test_suspicious_activity_response(
        self, mock_repositories, event_collector
    ):
        """Test response to suspicious activity detection"""
        user_id = uuid4()

        # Setup services
        security_service = SecurityService(
            mock_repositories["user_repository"],
            mock_repositories["session_repository"],
            mock_repositories["security_repository"],
            mock_repositories["audit_repository"],
        )
        RiskAssessmentService(
            mock_repositories["security_repository"],
            mock_repositories["user_repository"],
        )

        # Detect suspicious activity
        threat_context = {
            "user_id": user_id,
            "ip_address": "185.220.101.1",
            "failed_attempts": 10,
            "timeframe_minutes": 5,
        }

        # Mock suspicious patterns
        attempts = []
        for i in range(10):
            attempt = LoginAttempt(
                id=uuid4(),
                user_id=user_id,
                ip_address="185.220.101.1",
                success=False,
                created_at=datetime.now(datetime.UTC) - timedelta(minutes=i),
            )
            attempts.append(attempt)

        mock_repositories[
            "security_repository"
        ].get_recent_login_attempts.return_value = attempts

        # Detect threat
        threat = await security_service.detect_threats(threat_context)
        assert threat.detected is True
        assert threat.threat_type == SecurityEventType.BRUTE_FORCE_ATTACK

        # Handle incident
        incident = SecurityIncident(
            user_id=user_id,
            incident_type=threat.threat_type,
            severity=RiskLevel.HIGH,
            details=threat.details,
        )

        response = await security_service.handle_security_incident(incident)
        assert "lock_account" in response.actions_taken
        assert "notify_user" in response.actions_taken

        # Verify cascading effects
        mock_repositories["session_repository"].revoke_all_sessions.assert_called_with(
            user_id
        )
        mock_repositories["security_repository"].log_security_event.assert_called()


class TestDomainServicePerformance:
    """Test performance characteristics of domain services"""

    @pytest.mark.asyncio
    async def test_bulk_permission_check_performance(
        self, mock_repositories, performance_tracker
    ):
        """Test performance of bulk permission checking"""
        auth_service = AuthorizationService(
            mock_repositories["user_repository"],
            mock_repositories["role_repository"],
            mock_repositories["permission_repository"],
        )

        # Setup user with many permissions
        user_id = uuid4()
        user = UserFactory(id=user_id, status=UserStatus.ACTIVE)
        permissions = [PermissionFactory() for _ in range(100)]

        mock_repositories["user_repository"].get_by_id.return_value = user
        mock_repositories[
            "permission_repository"
        ].get_user_permissions.return_value = permissions

        # Test bulk check performance
        with performance_tracker.measure("bulk_permission_check"):
            contexts = []
            for i in range(100):
                context = AuthorizationContext(
                    user_id=user_id, resource_type=f"resource_{i}", action="read"
                )
                contexts.append(context)

            # Check permissions
            results = []
            for context in contexts:
                result = await auth_service.check_permission(context, "read")
                results.append(result)

        # Should complete 100 permission checks in under 1 second
        performance_tracker.assert_performance("bulk_permission_check", 1.0)
        assert len(results) == 100

    @pytest.mark.asyncio
    async def test_concurrent_session_creation_performance(
        self, mock_repositories, performance_tracker
    ):
        """Test performance of concurrent session creation"""
        session_service = SessionService(
            mock_repositories["session_repository"],
            mock_repositories["user_repository"],
            mock_repositories["device_repository"],
        )

        # Setup users
        users = [UserFactory() for _ in range(50)]

        async def create_session_for_user(user):
            mock_repositories["user_repository"].get_by_id.return_value = user
            session_data = {
                "user_id": user.id,
                "ip_address": IpAddress("192.168.1.1"),
                "user_agent": "Mozilla/5.0",
                "session_type": SessionType.WEB,
            }
            return await session_service.create_session(session_data)

        # Test concurrent creation
        with performance_tracker.measure("concurrent_sessions"):
            # Create 50 sessions concurrently
            tasks = [create_session_for_user(user) for user in users]
            results = await asyncio.gather(*tasks)

        # Should create 50 sessions in under 2 seconds
        performance_tracker.assert_performance("concurrent_sessions", 2.0)
        assert len(results) == 50
        assert all(r.session_id is not None for r in results)
