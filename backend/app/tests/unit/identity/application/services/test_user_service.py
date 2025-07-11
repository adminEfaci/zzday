"""
Comprehensive unit tests for UserService application service.

Tests cover:
- User management operations
- Business workflow orchestration
- Cross-aggregate coordination
- Transaction management
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest

from app.modules.identity.application.errors import (
    NotFoundError,
)
from app.modules.identity.application.services.user_service import UserService
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities.role import Role
from app.modules.identity.domain.enums import UserType
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import PasswordHash
from app.modules.identity.domain.value_objects.role_id import RoleId
from app.modules.identity.domain.value_objects.user_id import UserId
from app.modules.identity.domain.value_objects.username import Username


class TestUserService:
    """Test suite for UserService application service."""

    @pytest.fixture
    def mock_user_repository(self):
        """Create mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_role_repository(self):
        """Create mock role repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_session_repository(self):
        """Create mock session repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_event_bus(self):
        """Create mock event bus."""
        return AsyncMock()

    @pytest.fixture
    def mock_email_service(self):
        """Create mock email service."""
        return AsyncMock()

    @pytest.fixture
    def mock_audit_service(self):
        """Create mock audit service."""
        return AsyncMock()

    @pytest.fixture
    def user_service(
        self,
        mock_user_repository,
        mock_role_repository,
        mock_session_repository,
        mock_event_bus,
        mock_email_service,
        mock_audit_service,
    ):
        """Create user service with dependencies."""
        return UserService(
            user_repository=mock_user_repository,
            role_repository=mock_role_repository,
            session_repository=mock_session_repository,
            event_bus=mock_event_bus,
            email_service=mock_email_service,
            audit_service=mock_audit_service,
        )

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        user = User.create(
            email=Email("user@example.com"),
            username=Username("testuser"),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        user.activate()
        user.pull_domain_events()
        return user

    @pytest.fixture
    def test_role(self):
        """Create test role."""
        return Role.create(
            name="TestRole",
            description="Test role for unit tests",
        )

    async def test_assign_role_to_user(self, user_service, test_user, test_role):
        """Test assigning role to user."""
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.role_repository.get_by_id.return_value = test_role
        
        await user_service.assign_role_to_user(
            user_id=test_user.id,
            role_id=test_role.id,
            assigned_by="admin@example.com",
        )
        
        # Verify user has role
        assert test_role.id in test_user.roles
        
        # Verify repositories were called
        user_service.user_repository.save.assert_called_once_with(test_user)
        
        # Verify audit was logged
        user_service.audit_service.log_role_assignment.assert_called_once()
        
        # Verify events were published
        user_service.event_bus.publish_batch.assert_called_once()

    async def test_assign_role_to_nonexistent_user(self, user_service, test_role):
        """Test assigning role to non-existent user."""
        user_service.user_repository.get_by_id.return_value = None
        
        with pytest.raises(NotFoundError) as exc_info:
            await user_service.assign_role_to_user(
                user_id=UserId.generate(),
                role_id=test_role.id,
                assigned_by="admin",
            )
        
        assert "User not found" in str(exc_info.value)

    async def test_assign_nonexistent_role(self, user_service, test_user):
        """Test assigning non-existent role."""
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.role_repository.get_by_id.return_value = None
        
        with pytest.raises(NotFoundError) as exc_info:
            await user_service.assign_role_to_user(
                user_id=test_user.id,
                role_id=RoleId.generate(),
                assigned_by="admin",
            )
        
        assert "Role not found" in str(exc_info.value)

    async def test_remove_role_from_user(self, user_service, test_user, test_role):
        """Test removing role from user."""
        test_user.add_role(test_role.id)
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.role_repository.get_by_id.return_value = test_role
        
        await user_service.remove_role_from_user(
            user_id=test_user.id,
            role_id=test_role.id,
            removed_by="admin@example.com",
        )
        
        # Verify role was removed
        assert test_role.id not in test_user.roles
        
        # Verify audit was logged
        user_service.audit_service.log_role_removal.assert_called_once()

    async def test_bulk_assign_roles(self, user_service, test_user):
        """Test bulk assigning multiple roles."""
        roles = [
            Role.create(name=f"Role{i}", description=f"Role {i}")
            for i in range(3)
        ]
        
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.role_repository.get_many_by_ids.return_value = roles
        
        role_ids = [role.id for role in roles]
        
        await user_service.bulk_assign_roles(
            user_id=test_user.id,
            role_ids=role_ids,
            assigned_by="admin",
        )
        
        # Verify all roles were assigned
        for role_id in role_ids:
            assert role_id in test_user.roles

    async def test_deactivate_user_with_sessions(self, user_service, test_user):
        """Test deactivating user revokes all sessions."""
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.session_repository.get_active_sessions_by_user.return_value = [
            Mock(id="session1"),
            Mock(id="session2"),
        ]
        
        await user_service.deactivate_user(
            user_id=test_user.id,
            reason="Account suspension",
            deactivated_by="admin",
        )
        
        # Verify user is deactivated
        assert test_user.is_active is False
        
        # Verify all sessions were revoked
        assert user_service.session_repository.revoke_all_user_sessions.called
        
        # Verify notification was sent
        user_service.email_service.send_account_deactivated_email.assert_called_once()

    async def test_reactivate_user(self, user_service, test_user):
        """Test reactivating a deactivated user."""
        test_user.deactivate("Test")
        user_service.user_repository.get_by_id.return_value = test_user
        
        await user_service.reactivate_user(
            user_id=test_user.id,
            reason="Appeal approved",
            reactivated_by="admin",
        )
        
        # Verify user is active
        assert test_user.is_active is True
        
        # Verify notification was sent
        user_service.email_service.send_account_reactivated_email.assert_called_once()

    async def test_delete_user_gdpr_compliance(self, user_service, test_user):
        """Test deleting user with GDPR compliance."""
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.session_repository.get_all_sessions_by_user.return_value = [
            Mock(id="session1"),
        ]
        
        await user_service.delete_user_gdpr(
            user_id=test_user.id,
            reason="GDPR deletion request",
            requested_by=str(test_user.id),
        )
        
        # Verify user is deleted
        assert test_user.is_deleted is True
        
        # Verify PII was anonymized
        assert test_user.email.value != "user@example.com"
        assert test_user.profile.first_name == "Deleted"
        assert test_user.profile.last_name == "User"
        
        # Verify all sessions were deleted
        user_service.session_repository.delete_all_user_sessions.assert_called_once()
        
        # Verify audit trail
        user_service.audit_service.log_gdpr_deletion.assert_called_once()

    async def test_upgrade_user_to_premium(self, user_service, test_user):
        """Test upgrading user to premium type."""
        user_service.user_repository.get_by_id.return_value = test_user
        
        await user_service.upgrade_to_premium(
            user_id=test_user.id,
            payment_method="credit_card",
            subscription_id="sub_123",
        )
        
        # Verify user type changed
        assert test_user.type == UserType.PREMIUM
        
        # Verify premium role was assigned
        user_service.role_repository.get_by_name.assert_called_with("premium_user")
        
        # Verify welcome email
        user_service.email_service.send_premium_welcome_email.assert_called_once()

    async def test_merge_duplicate_accounts(self, user_service):
        """Test merging duplicate user accounts."""
        primary_user = User.create(
            email=Email("primary@example.com"),
            username=Username("primary"),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        primary_user.activate()
        
        duplicate_user = User.create(
            email=Email("duplicate@example.com"),
            username=Username("duplicate"),
            password_hash=PasswordHash.from_password("Test123!"),
        )
        duplicate_user.activate()
        
        user_service.user_repository.get_by_id.side_effect = [
            primary_user,
            duplicate_user,
        ]
        
        await user_service.merge_duplicate_accounts(
            primary_user_id=primary_user.id,
            duplicate_user_id=duplicate_user.id,
            merge_requested_by="admin",
        )
        
        # Verify duplicate was deactivated
        assert duplicate_user.is_active is False
        
        # Verify sessions were migrated
        user_service.session_repository.migrate_sessions.assert_called_once_with(
            from_user_id=duplicate_user.id,
            to_user_id=primary_user.id,
        )
        
        # Verify audit trail
        user_service.audit_service.log_account_merge.assert_called_once()

    async def test_bulk_user_import(self, user_service):
        """Test bulk importing users."""
        import_data = [
            {
                "email": "user1@example.com",
                "username": "user1",
                "first_name": "User",
                "last_name": "One",
            },
            {
                "email": "user2@example.com",
                "username": "user2",
                "first_name": "User",
                "last_name": "Two",
            },
        ]
        
        user_service.user_repository.exists_by_email.return_value = False
        user_service.user_repository.exists_by_username.return_value = False
        
        results = await user_service.bulk_import_users(
            users_data=import_data,
            default_role_name="imported_user",
            send_welcome_emails=True,
            imported_by="admin",
        )
        
        assert results.total == 2
        assert results.successful == 2
        assert results.failed == 0
        
        # Verify users were saved
        assert user_service.user_repository.save_many.call_count == 1
        
        # Verify welcome emails
        assert user_service.email_service.send_bulk_welcome_emails.called

    async def test_enforce_password_policy(self, user_service, test_user):
        """Test enforcing password policy on users."""
        # Users with old passwords
        users = [test_user]
        test_user.password_changed_at = datetime.now(UTC) - timedelta(days=100)
        
        user_service.user_repository.get_users_with_old_passwords.return_value = users
        
        await user_service.enforce_password_policy(
            max_password_age_days=90,
            notify_before_days=7,
        )
        
        # Verify users were notified
        user_service.email_service.send_password_expiry_notification.assert_called()
        
        # Verify users requiring reset were marked
        assert test_user.requires_password_change is True

    async def test_cleanup_inactive_users(self, user_service):
        """Test cleaning up inactive users."""
        inactive_users = [
            Mock(id=UserId.generate(), last_activity_at=datetime.now(UTC) - timedelta(days=400)),
            Mock(id=UserId.generate(), last_activity_at=datetime.now(UTC) - timedelta(days=500)),
        ]
        
        user_service.user_repository.get_inactive_users.return_value = inactive_users
        
        results = await user_service.cleanup_inactive_users(
            inactive_days=365,
            batch_size=10,
            dry_run=False,
        )
        
        assert results.processed == 2
        assert results.deactivated == 2
        
        # Verify users were deactivated
        for user in inactive_users:
            user.deactivate.assert_called_once()

    async def test_export_user_data(self, user_service, test_user):
        """Test exporting user data for compliance."""
        user_service.user_repository.get_by_id.return_value = test_user
        user_service.session_repository.get_all_sessions_by_user.return_value = []
        user_service.audit_service.get_user_audit_trail.return_value = []
        
        export_data = await user_service.export_user_data(
            user_id=test_user.id,
            format="json",
            include_audit_trail=True,
        )
        
        assert export_data["user"]["id"] == str(test_user.id)
        assert export_data["user"]["email"] == test_user.email.value
        assert "sessions" in export_data
        assert "audit_trail" in export_data
        
        # Verify audit log
        user_service.audit_service.log_data_export.assert_called_once()

    async def test_verify_user_identity(self, user_service, test_user):
        """Test verifying user identity."""
        user_service.user_repository.get_by_id.return_value = test_user
        
        # Mock identity verification service
        user_service.identity_verification_service = AsyncMock()
        user_service.identity_verification_service.verify.return_value = {
            "verified": True,
            "confidence": 0.95,
            "method": "document_check",
        }
        
        result = await user_service.verify_user_identity(
            user_id=test_user.id,
            verification_method="document",
            document_data={"type": "passport", "number": "123456"},
        )
        
        assert result.verified is True
        assert test_user.identity_verified is True
        assert test_user.identity_verification_date is not None
        
        # Verify notification
        user_service.email_service.send_identity_verified_email.assert_called_once()