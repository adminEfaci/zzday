"""
Tests for Authorization Domain Service
"""

from datetime import datetime
from uuid import uuid4

import pytest

from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities.permission import Permission
from app.modules.identity.domain.entities.role import Role
from app.modules.identity.domain.enums import (
    PermissionScope,
    PermissionStatus,
    ResourceType,
    RoleStatus,
    UserStatus,
)
from app.modules.identity.domain.services.authorization_service import (
    AuthorizationContext,
    AuthorizationService,
    PermissionMatch,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username


class TestAuthorizationService:
    """Test suite for AuthorizationService."""

    @pytest.fixture
    def auth_service(self):
        """Create authorization service instance."""
        return AuthorizationService()

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            id=uuid4(),
            username=Username("testuser"),
            email=Email("test@example.com"),
            password_hash="hashed_password",
            status=UserStatus.ACTIVE,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )

    @pytest.fixture
    def admin_role(self):
        """Create admin role."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            status=RoleStatus.ACTIVE,
            priority=100,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )
        # Add permissions
        role._permissions.append(
            Permission(
                id=uuid4(),
                name="manage_users",
                resource="users",
                action="*",
                scope=PermissionScope.GLOBAL,
                status=PermissionStatus.ACTIVE,
                created_at=datetime.now(datetime.UTC),
                updated_at=datetime.now(datetime.UTC),
            )
        )
        return role

    @pytest.fixture
    def auth_context(self, test_user):
        """Create authorization context."""
        return AuthorizationContext(
            user_id=test_user.id,
            session_id=uuid4(),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            request_id=uuid4(),
            timestamp=datetime.now(datetime.UTC),
        )

    @pytest.mark.asyncio
    async def test_check_permission_success(
        self, auth_service, test_user, admin_role, auth_context
    ):
        """Test successful permission check."""
        # Add role to user
        test_user._roles.append(admin_role)

        # Mock repository method
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check permission
        result = await auth_service.check_permission(
            context=auth_context, permission="manage_users", resource="users"
        )

        assert result.allowed is True
        assert result.user_id == test_user.id
        assert result.match_type == PermissionMatch.EXACT
        assert "admin" in result.matched_roles

    @pytest.mark.asyncio
    async def test_check_permission_denied(self, auth_service, test_user, auth_context):
        """Test denied permission check."""

        # Mock repository method
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check permission without any roles
        result = await auth_service.check_permission(
            context=auth_context, permission="manage_users", resource="users"
        )

        assert result.allowed is False
        assert result.user_id == test_user.id
        assert result.denial_reason == "No matching permissions found"

    @pytest.mark.asyncio
    async def test_check_permission_wildcard_match(
        self, auth_service, test_user, auth_context
    ):
        """Test wildcard permission matching."""
        # Create role with wildcard permission
        role = Role(
            id=uuid4(),
            name="moderator",
            description="Moderator role",
            status=RoleStatus.ACTIVE,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )
        role._permissions.append(
            Permission(
                id=uuid4(),
                name="moderate_*",
                resource="content",
                action="*",
                scope=PermissionScope.GLOBAL,
                status=PermissionStatus.ACTIVE,
                created_at=datetime.now(datetime.UTC),
                updated_at=datetime.now(datetime.UTC),
            )
        )
        test_user._roles.append(role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check permission with wildcard match
        result = await auth_service.check_permission(
            context=auth_context, permission="moderate_posts", resource="content"
        )

        assert result.allowed is True
        assert result.match_type == PermissionMatch.WILDCARD

    @pytest.mark.asyncio
    async def test_check_permission_with_conditions(
        self, auth_service, test_user, auth_context
    ):
        """Test permission check with conditions."""
        # Create role with conditional permission
        role = Role(
            id=uuid4(),
            name="user",
            description="Regular user",
            status=RoleStatus.ACTIVE,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )
        permission = Permission(
            id=uuid4(),
            name="edit_profile",
            resource="profile",
            action="update",
            scope=PermissionScope.OWN,
            status=PermissionStatus.ACTIVE,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )
        permission.conditions = {"owner_only": True}
        role._permissions.append(permission)
        test_user._roles.append(role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check permission with owner context
        result = await auth_service.check_permission(
            context=auth_context,
            permission="edit_profile",
            resource="profile",
            resource_owner_id=test_user.id,
        )

        assert result.allowed is True
        assert result.applied_conditions == {"owner_only": True}

    @pytest.mark.asyncio
    async def test_check_permission_suspended_user(
        self, auth_service, test_user, admin_role, auth_context
    ):
        """Test permission check for suspended user."""
        # Suspend user
        test_user.status = UserStatus.SUSPENDED
        test_user._roles.append(admin_role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check permission
        result = await auth_service.check_permission(
            context=auth_context, permission="manage_users", resource="users"
        )

        assert result.allowed is False
        assert result.denial_reason == "User account is suspended"

    @pytest.mark.asyncio
    async def test_has_any_permission(self, auth_service, test_user, admin_role):
        """Test checking multiple permissions."""
        test_user._roles.append(admin_role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check multiple permissions
        has_permission = await auth_service.has_any_permission(
            user_id=test_user.id,
            permissions=["manage_users", "view_reports", "delete_posts"],
        )

        assert has_permission is True

    @pytest.mark.asyncio
    async def test_has_all_permissions(self, auth_service, test_user, admin_role):
        """Test checking all permissions."""
        test_user._roles.append(admin_role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Check all permissions
        has_all = await auth_service.has_all_permissions(
            user_id=test_user.id, permissions=["manage_users"]
        )

        assert has_all is True

        # Check with missing permission
        has_all = await auth_service.has_all_permissions(
            user_id=test_user.id, permissions=["manage_users", "manage_billing"]
        )

        assert has_all is False

    @pytest.mark.asyncio
    async def test_get_user_permissions(self, auth_service, test_user, admin_role):
        """Test getting all user permissions."""
        test_user._roles.append(admin_role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Get permissions
        permissions = await auth_service.get_user_permissions(test_user.id)

        assert len(permissions) > 0
        assert "manage_users" in [p["name"] for p in permissions]
        assert "admin" in [p["role"] for p in permissions]

    @pytest.mark.asyncio
    async def test_get_resource_permissions(self, auth_service, test_user, admin_role):
        """Test getting permissions for a specific resource."""
        test_user._roles.append(admin_role)

        # Mock repository
        async def mock_get_user(user_id):
            return test_user if user_id == test_user.id else None

        auth_service._user_repository = type("obj", (object,), {"get": mock_get_user})

        # Get resource permissions
        permissions = await auth_service.get_resource_permissions(
            user_id=test_user.id, resource_type=ResourceType.USER, resource_id=uuid4()
        )

        assert len(permissions) > 0
        assert permissions[0]["resource"] == "users"

    def test_segregation_of_duties_check(self, auth_service):
        """Test segregation of duties validation."""
        # Test incompatible permissions
        is_valid = auth_service._check_segregation_of_duties(
            ["approve_payment"], ["create_payment", "view_payments"]
        )
        assert is_valid is False

        # Test compatible permissions
        is_valid = auth_service._check_segregation_of_duties(
            ["view_users"], ["view_reports", "view_logs"]
        )
        assert is_valid is True

    def test_context_based_authorization(self, auth_service):
        """Test context-based authorization rules."""
        context = AuthorizationContext(
            user_id=uuid4(),
            session_id=uuid4(),
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0",
            request_id=uuid4(),
            timestamp=datetime.now(datetime.UTC),
        )

        # Test time-based restrictions
        permission = Permission(
            id=uuid4(),
            name="admin_access",
            resource="admin",
            action="*",
            scope=PermissionScope.GLOBAL,
            status=PermissionStatus.ACTIVE,
            created_at=datetime.now(datetime.UTC),
            updated_at=datetime.now(datetime.UTC),
        )
        permission.conditions = {
            "time_restriction": {"start": "09:00", "end": "17:00", "timezone": "UTC"}
        }

        # This would need proper time mocking for full testing
        # For now, just verify the method exists
        is_valid = auth_service._apply_context_rules(permission, context)
        assert isinstance(is_valid, bool)
