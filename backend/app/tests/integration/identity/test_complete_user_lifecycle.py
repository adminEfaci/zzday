"""
Integration tests for complete user lifecycle.

Tests the entire user journey from registration through account management,
security events, and eventual account closure with all related systems.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    RegisterUserCommand,
    VerifyEmailCommand,
)
from app.modules.identity.application.commands.authorization import AssignRoleCommand
from app.modules.identity.application.commands.mfa import (
    SetupMfaCommand,
    VerifyMfaSetupCommand,
)
from app.modules.identity.application.commands.session import RevokeAllSessionsCommand
from app.modules.identity.application.commands.user import (
    ChangePasswordCommand,
    DeactivateUserCommand,
    UpdateUserProfileCommand,
)
from app.modules.identity.application.queries.audit import (
    GetAuditTrailQuery,
    GetUserActivityQuery,
)
from app.modules.identity.application.queries.user import GetUserProfileQuery
from app.modules.identity.domain.enums import AuditEventType, MFAMethod


@pytest.mark.integration
class TestCompleteUserLifecycle:
    """Test complete user lifecycle from registration to deactivation."""

    @pytest.fixture
    def user_data(self, faker):
        """Generate test user data."""
        return {
            "email": faker.email(),
            "username": faker.user_name(),
            "password": "SecurePassword123!@#",
            "first_name": faker.first_name(),
            "last_name": faker.last_name(),
            "phone_number": f"+1-555-{faker.random_int(100, 999)}-{faker.random_int(1000, 9999)}",
        }

    @pytest.mark.asyncio
    async def test_complete_user_journey(self, app_container, user_data):
        """Test complete user journey from registration to deactivation."""
        # Get all required handlers
        register_handler = app_container.get("register_user_command_handler")
        verify_email_handler = app_container.get("verify_email_command_handler")
        login_handler = app_container.get("login_command_handler")
        update_profile_handler = app_container.get(
            "update_user_profile_command_handler"
        )
        change_password_handler = app_container.get("change_password_command_handler")
        setup_mfa_handler = app_container.get("setup_mfa_command_handler")
        verify_mfa_setup_handler = app_container.get("verify_mfa_setup_command_handler")
        assign_role_handler = app_container.get("assign_role_command_handler")
        get_profile_handler = app_container.get("get_user_profile_query_handler")
        get_activity_handler = app_container.get("get_user_activity_query_handler")
        deactivate_handler = app_container.get("deactivate_user_command_handler")

        # Additional services
        email_service = app_container.get("email_service")
        totp_service = app_container.get("totp_service")
        admin_user_id = str(uuid4())  # Mock admin user

        # PHASE 1: Registration and Email Verification
        print("Phase 1: User Registration")

        register_command = RegisterUserCommand(
            email=user_data["email"],
            username=user_data["username"],
            password=user_data["password"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            terms_accepted=True,
        )

        register_result = await register_handler.handle(register_command)
        user_id = register_result.user_id

        assert register_result.success is True
        assert register_result.verification_sent is True
        assert user_id is not None

        # Simulate email verification
        verification_token = email_service.get_last_verification_token(
            user_data["email"]
        )

        verify_email_command = VerifyEmailCommand(token=verification_token)
        verify_result = await verify_email_handler.handle(verify_email_command)

        assert verify_result.success is True
        assert verify_result.email == user_data["email"]

        # PHASE 2: Initial Login and Profile Setup
        print("Phase 2: Initial Login and Profile Setup")

        login_command = LoginCommand(
            email=user_data["email"],
            password=user_data["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )

        login_result = await login_handler.handle(login_command)

        assert login_result.success is True
        assert login_result.access_token is not None
        assert login_result.mfa_required is False  # MFA not setup yet

        # Update profile with additional information
        update_command = UpdateUserProfileCommand(
            user_id=user_id,
            phone_number=user_data["phone_number"],
            address_line1="123 Test Street",
            address_city="Test City",
            address_state="TS",
            address_postal_code="12345",
            address_country="US",
            preferences={
                "newsletter": True,
                "marketing_emails": False,
                "theme": "light",
            },
        )

        update_result = await update_profile_handler.handle(update_command)

        assert update_result.success is True

        # PHASE 3: Security Enhancement - MFA Setup
        print("Phase 3: MFA Setup")

        setup_mfa_command = SetupMfaCommand(
            user_id=user_id,
            method=MFAMethod.TOTP,
            device_name="Primary Authenticator",
            device_id="auth-device-001",
        )

        mfa_setup_result = await setup_mfa_handler.handle(setup_mfa_command)

        assert mfa_setup_result.success is True
        assert mfa_setup_result.secret is not None

        # Verify MFA setup
        totp_code = totp_service.generate_code(mfa_setup_result.secret)

        verify_mfa_command = VerifyMfaSetupCommand(
            user_id=user_id,
            device_id=mfa_setup_result.device_id,
            verification_code=totp_code,
        )

        mfa_verify_result = await verify_mfa_setup_handler.handle(verify_mfa_command)

        assert mfa_verify_result.success is True
        assert mfa_verify_result.mfa_enabled is True

        # PHASE 4: Role Assignment and Privilege Management
        print("Phase 4: Role Assignment")

        # Create a test role first (in real scenario, roles would exist)
        role_service = app_container.get("role_service")
        manager_role = await role_service.create_role(
            name="Manager",
            description="Department Manager",
            permissions=["user:read", "user:write", "report:read"],
            created_by=admin_user_id,
        )

        assign_role_command = AssignRoleCommand(
            user_id=user_id,
            role_id=manager_role.id,
            assigned_by=admin_user_id,
            reason="Promotion to department manager",
        )

        role_result = await assign_role_handler.handle(assign_role_command)

        assert role_result.success is True

        # PHASE 5: Password Change
        print("Phase 5: Password Change")

        new_password = "NewSecurePassword456!@#"

        change_password_command = ChangePasswordCommand(
            user_id=user_id,
            current_password=user_data["password"],
            new_password=new_password,
        )

        password_result = await change_password_handler.handle(change_password_command)

        assert password_result.success is True
        assert password_result.sessions_invalidated is True

        # Update our test data
        user_data["password"] = new_password

        # PHASE 6: Activity Monitoring
        print("Phase 6: Activity Monitoring")

        # Login again with new password to generate activity
        login_command2 = LoginCommand(
            email=user_data["email"],
            password=new_password,
            ip_address="192.168.1.101",  # Different IP
            user_agent="Mozilla/5.0...",
        )

        login_result2 = await login_handler.handle(login_command2)
        assert login_result2.mfa_required is True  # Now requires MFA

        # Check user activity
        activity_query = GetUserActivityQuery(
            user_id=user_id, time_range="24h", include_security_events=True
        )

        activity_result = await get_activity_handler.handle(activity_query)

        assert len(activity_result.activities) > 0
        assert any(
            a.event_type == AuditEventType.USER_REGISTERED
            for a in activity_result.activities
        )
        assert any(
            a.event_type == AuditEventType.EMAIL_VERIFIED
            for a in activity_result.activities
        )
        assert any(
            a.event_type == AuditEventType.MFA_ENABLED
            for a in activity_result.activities
        )
        assert any(
            a.event_type == AuditEventType.PASSWORD_CHANGED
            for a in activity_result.activities
        )

        # PHASE 7: Profile Verification
        print("Phase 7: Profile Verification")

        profile_query = GetUserProfileQuery(user_id=user_id)
        profile_result = await get_profile_handler.handle(profile_query)

        assert profile_result.user_id == user_id
        assert profile_result.email == user_data["email"]
        assert profile_result.username == user_data["username"]
        assert (
            profile_result.full_name
            == f"{user_data['first_name']} {user_data['last_name']}"
        )
        assert profile_result.is_email_verified is True
        assert profile_result.mfa_enabled is True
        assert profile_result.phone_number == user_data["phone_number"]
        assert "Manager" in [r.name for r in profile_result.roles]

        # PHASE 8: Account Deactivation
        print("Phase 8: Account Deactivation")

        deactivate_command = DeactivateUserCommand(
            user_id=user_id,
            deactivated_by=admin_user_id,
            reason="User requested account closure",
            retain_data=True,
            notify_user=True,
        )

        deactivate_result = await deactivate_handler.handle(deactivate_command)

        assert deactivate_result.success is True
        assert deactivate_result.data_retained is True

        # Verify user cannot login after deactivation
        login_command3 = LoginCommand(
            email=user_data["email"],
            password=new_password,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
        )

        with pytest.raises(Exception):  # Should raise account deactivated error
            await login_handler.handle(login_command3)

        # PHASE 9: Final Audit Trail Verification
        print("Phase 9: Audit Trail Verification")

        audit_query = GetAuditTrailQuery(
            user_id=user_id,
            event_types=[
                AuditEventType.USER_REGISTERED,
                AuditEventType.EMAIL_VERIFIED,
                AuditEventType.USER_LOGIN,
                AuditEventType.MFA_ENABLED,
                AuditEventType.ROLE_ASSIGNED,
                AuditEventType.PASSWORD_CHANGED,
                AuditEventType.USER_DEACTIVATED,
            ],
        )

        audit_result = await get_activity_handler.handle(audit_query)

        # Verify complete lifecycle is captured in audit trail
        event_types = [event.event_type for event in audit_result.events]

        assert AuditEventType.USER_REGISTERED in event_types
        assert AuditEventType.EMAIL_VERIFIED in event_types
        assert AuditEventType.USER_LOGIN in event_types
        assert AuditEventType.MFA_ENABLED in event_types
        assert AuditEventType.ROLE_ASSIGNED in event_types
        assert AuditEventType.PASSWORD_CHANGED in event_types
        assert AuditEventType.USER_DEACTIVATED in event_types

        print("Complete user lifecycle test passed!")

    @pytest.mark.asyncio
    async def test_user_security_incident_lifecycle(self, app_container, user_data):
        """Test user lifecycle with security incidents."""
        # Get handlers
        register_handler = app_container.get("register_user_command_handler")
        login_handler = app_container.get("login_command_handler")
        security_service = app_container.get("security_service")
        incident_service = app_container.get("incident_service")
        revoke_sessions_handler = app_container.get(
            "revoke_all_sessions_command_handler"
        )

        # Register user
        register_command = RegisterUserCommand(
            email=user_data["email"],
            username=user_data["username"],
            password=user_data["password"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            terms_accepted=True,
        )

        register_result = await register_handler.handle(register_command)
        user_id = register_result.user_id

        # Normal login
        login_command = LoginCommand(
            email=user_data["email"],
            password=user_data["password"],
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
        )

        login_result = await login_handler.handle(login_command)
        assert login_result.success is True

        # Simulate suspicious activity - multiple failed logins from different IPs
        suspicious_ips = ["203.0.113.100", "198.51.100.200", "185.220.101.1"]

        for ip in suspicious_ips:
            for _ in range(3):  # 3 failed attempts per IP
                try:
                    suspicious_login = LoginCommand(
                        email=user_data["email"],
                        password="WrongPassword123!",
                        ip_address=ip,
                        user_agent="curl/7.68.0",  # Suspicious user agent
                    )
                    await login_handler.handle(suspicious_login)
                except Exception:
                    pass  # Expected to fail

        # Check if security incident was created
        incidents = await incident_service.get_user_incidents(user_id)
        assert len(incidents) > 0

        # Verify brute force detection
        brute_force_incidents = [
            i for i in incidents if i.type == "brute_force_detected"
        ]
        assert len(brute_force_incidents) > 0

        # Simulate account takeover indicators
        # Successful login from suspicious location immediately followed by profile changes
        takeover_login = LoginCommand(
            email=user_data["email"],
            password=user_data["password"],
            ip_address="203.0.113.100",  # Same IP as failed attempts
            user_agent="Mozilla/5.0...",
        )

        await login_handler.handle(takeover_login)

        # This should trigger high risk assessment
        risk_assessment = await security_service.assess_login_risk(
            user_id=user_id,
            context={
                "ip_address": "203.0.113.100",
                "previous_failures": 3,
                "location_change": True,
                "time_since_last_failure": 60,  # 1 minute
            },
        )

        assert risk_assessment["risk_level"] in ["HIGH", "CRITICAL"]

        # Security response: revoke all sessions
        revoke_command = RevokeAllSessionsCommand(
            user_id=user_id,
            revoked_by="security_system",
            reason="Suspected account compromise",
        )

        revoke_result = await revoke_sessions_handler.handle(revoke_command)
        assert revoke_result.success is True
        assert revoke_result.sessions_revoked > 0

    @pytest.mark.asyncio
    async def test_compliance_data_lifecycle(self, app_container, user_data):
        """Test user lifecycle with compliance data handling."""
        # Get handlers
        register_handler = app_container.get("register_user_command_handler")
        gdpr_service = app_container.get("gdpr_compliance_service")
        audit_service = app_container.get("audit_service")

        # Register user with GDPR consent
        register_command = RegisterUserCommand(
            email=user_data["email"],
            username=user_data["username"],
            password=user_data["password"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            terms_accepted=True,
            privacy_consent=True,
            marketing_consent=False,
            gdpr_consent_details={
                "consent_timestamp": datetime.now(UTC),
                "consent_version": "1.0",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
            },
        )

        register_result = await register_handler.handle(register_command)
        user_id = register_result.user_id

        # Simulate GDPR data export request
        export_request = await gdpr_service.request_data_export(
            user_id=user_id, requester_ip="192.168.1.100", verification_method="email"
        )

        assert export_request["status"] == "pending"
        assert export_request["request_id"] is not None

        # Process export request
        export_data = await gdpr_service.generate_data_export(user_id)

        assert "personal_data" in export_data
        assert "account_activity" in export_data
        assert "consent_history" in export_data
        assert export_data["personal_data"]["email"] == user_data["email"]

        # Simulate data retention policy
        retention_policy = await gdpr_service.check_data_retention(user_id)

        assert (
            retention_policy["personal_data_retention_days"] >= 2555
        )  # 7 years minimum
        assert retention_policy["activity_logs_retention_days"] >= 2555

        # Test consent withdrawal
        consent_withdrawal = await gdpr_service.withdraw_consent(
            user_id=user_id,
            consent_types=["marketing"],
            withdrawal_reason="User request",
        )

        assert consent_withdrawal["marketing_consent"] is False

        # Verify audit trail for GDPR actions
        gdpr_audit = await audit_service.get_gdpr_audit_trail(user_id)

        gdpr_events = [event.event_type for event in gdpr_audit]
        assert "consent_given" in gdpr_events
        assert "data_export_requested" in gdpr_events
        assert "consent_withdrawn" in gdpr_events

    @pytest.mark.asyncio
    async def test_multi_tenant_user_lifecycle(self, app_container, user_data):
        """Test user lifecycle across multiple tenants."""
        # Get handlers
        register_handler = app_container.get("register_user_command_handler")
        tenant_service = app_container.get("tenant_service")
        assign_role_handler = app_container.get("assign_role_command_handler")

        # Create test tenants
        tenant_a = await tenant_service.create_tenant("company-a", "Company A")
        tenant_b = await tenant_service.create_tenant("company-b", "Company B")

        # Register user in first tenant
        register_command_a = RegisterUserCommand(
            email=user_data["email"],
            username=user_data["username"],
            password=user_data["password"],
            first_name=user_data["first_name"],
            last_name=user_data["last_name"],
            terms_accepted=True,
            tenant_id=tenant_a.id,
        )

        register_result_a = await register_handler.handle(register_command_a)
        user_id_a = register_result_a.user_id

        # Assign role in tenant A
        role_a = await tenant_service.get_tenant_role(tenant_a.id, "admin")

        assign_role_a = AssignRoleCommand(
            user_id=user_id_a,
            role_id=role_a.id,
            assigned_by="system",
            tenant_id=tenant_a.id,
        )

        await assign_role_handler.handle(assign_role_a)

        # Invite user to second tenant
        invitation = await tenant_service.invite_user_to_tenant(
            email=user_data["email"],
            tenant_id=tenant_b.id,
            role_name="user",
            invited_by="admin_user_b",
        )

        # Accept invitation (creates user association with tenant B)
        accept_result = await tenant_service.accept_tenant_invitation(
            invitation_token=invitation["token"],
            user_id=user_id_a,  # Same user, different tenant context
        )

        assert accept_result["success"] is True

        # Verify user has access to both tenants
        user_tenants = await tenant_service.get_user_tenants(user_id_a)

        assert len(user_tenants) == 2
        tenant_ids = [t.id for t in user_tenants]
        assert tenant_a.id in tenant_ids
        assert tenant_b.id in tenant_ids

        # Verify different roles in different tenants
        permissions_a = await tenant_service.get_user_tenant_permissions(
            user_id_a, tenant_a.id
        )
        permissions_b = await tenant_service.get_user_tenant_permissions(
            user_id_a, tenant_b.id
        )

        assert "admin" in [p.role for p in permissions_a]
        assert "user" in [p.role for p in permissions_b]

        # Remove user from one tenant
        removal_result = await tenant_service.remove_user_from_tenant(
            user_id=user_id_a, tenant_id=tenant_b.id, removed_by="admin_user_b"
        )

        assert removal_result["success"] is True

        # Verify user only has access to tenant A now
        user_tenants_after = await tenant_service.get_user_tenants(user_id_a)
        assert len(user_tenants_after) == 1
        assert user_tenants_after[0].id == tenant_a.id
