"""
Test cases for authorization command and query handlers.

Tests all authorization-related handlers including role and permission management,
access control, and authorization checks.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.authorization import (
    AssignRoleCommand,
    AssignRoleCommandHandler,
    CheckPermissionCommand,
    CheckPermissionCommandHandler,
    CreateRoleCommand,
    CreateRoleCommandHandler,
    GrantPermissionCommand,
    GrantPermissionCommandHandler,
)
from app.modules.identity.application.queries.authorization import (
    GetRolePermissionsQuery,
    GetRolePermissionsQueryHandler,
    GetUserAccessQuery,
    GetUserAccessQueryHandler,
)
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities import Permission, Role
from app.modules.identity.domain.enums import PermissionScope
from app.modules.identity.domain.exceptions import (
    InsufficientPermissionsError,
    RoleAlreadyAssignedError,
    RoleNotFoundError,
    UserNotFoundError,
)


class TestAssignRoleCommandHandler:
    """Test assign role command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_role_repo = Mock()
        mock_permission_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return AssignRoleCommandHandler(
            user_repository=mock_user_repo,
            role_repository=mock_role_repo,
            permission_service=mock_permission_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_role_assignment(self, handler):
        """Test successful role assignment."""
        # Arrange
        user_id = str(uuid4())
        role_id = str(uuid4())
        assigned_by = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.assign_role = Mock()

        role = Mock(spec=Role)
        role.id = role_id
        role.name = "Manager"
        role.is_active = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.role_repository.find_by_id = AsyncMock(return_value=role)
        handler.permission_service.can_assign_role = AsyncMock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = AssignRoleCommand(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
            reason="Promotion to manager",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.user_id == user_id
        assert result.role_id == role_id
        user.assign_role.assert_called_once_with(
            role, assigned_by, "Promotion to manager"
        )
        handler.user_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_assign_role_user_not_found(self, handler):
        """Test role assignment when user not found."""
        # Arrange
        handler.user_repository.find_by_id = AsyncMock(return_value=None)

        command = AssignRoleCommand(
            user_id=str(uuid4()), role_id=str(uuid4()), assigned_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_assign_role_role_not_found(self, handler):
        """Test role assignment when role not found."""
        # Arrange
        user = Mock(spec=User)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.role_repository.find_by_id = AsyncMock(return_value=None)

        command = AssignRoleCommand(
            user_id=str(uuid4()), role_id=str(uuid4()), assigned_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(RoleNotFoundError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_assign_role_insufficient_permissions(self, handler):
        """Test role assignment with insufficient permissions."""
        # Arrange
        user = Mock(spec=User)
        role = Mock(spec=Role)
        role.is_active = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.role_repository.find_by_id = AsyncMock(return_value=role)
        handler.permission_service.can_assign_role = AsyncMock(return_value=False)

        command = AssignRoleCommand(
            user_id=str(uuid4()), role_id=str(uuid4()), assigned_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(InsufficientPermissionsError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_assign_role_already_assigned(self, handler):
        """Test assigning role that user already has."""
        # Arrange
        user = Mock(spec=User)
        role = Mock(spec=Role)
        role.is_active = True
        user.assign_role = Mock(
            side_effect=RoleAlreadyAssignedError("Role already assigned")
        )

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.role_repository.find_by_id = AsyncMock(return_value=role)
        handler.permission_service.can_assign_role = AsyncMock(return_value=True)

        command = AssignRoleCommand(
            user_id=str(uuid4()), role_id=str(uuid4()), assigned_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(RoleAlreadyAssignedError):
            await handler.handle(command)


class TestCreateRoleCommandHandler:
    """Test create role command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_role_repo = Mock()
        mock_permission_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return CreateRoleCommandHandler(
            role_repository=mock_role_repo,
            permission_service=mock_permission_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_role_creation(self, handler):
        """Test successful role creation."""
        # Arrange
        created_by = str(uuid4())

        handler.role_repository.exists_by_name = AsyncMock(return_value=False)
        handler.permission_service.can_create_role = AsyncMock(return_value=True)
        handler.role_repository.save = AsyncMock()

        command = CreateRoleCommand(
            name="Senior Developer",
            description="Senior software developer role",
            permissions=["user:read", "user:write", "project:read"],
            created_by=created_by,
            priority=50,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.role_id is not None
        assert result.name == "Senior Developer"
        handler.role_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(self, handler):
        """Test creating role with duplicate name."""
        # Arrange
        handler.role_repository.exists_by_name = AsyncMock(return_value=True)

        command = CreateRoleCommand(
            name="Existing Role", description="Description", created_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(ValueError, match="already exists"):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_create_role_insufficient_permissions(self, handler):
        """Test creating role with insufficient permissions."""
        # Arrange
        handler.role_repository.exists_by_name = AsyncMock(return_value=False)
        handler.permission_service.can_create_role = AsyncMock(return_value=False)

        command = CreateRoleCommand(
            name="New Role", description="Description", created_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(InsufficientPermissionsError):
            await handler.handle(command)


class TestCheckPermissionCommandHandler:
    """Test check permission command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_permission_service = Mock()
        mock_cache = Mock()

        return CheckPermissionCommandHandler(
            user_repository=mock_user_repo,
            permission_service=mock_permission_service,
            cache=mock_cache,
        )

    @pytest.mark.asyncio
    async def test_check_permission_allowed(self, handler):
        """Test permission check that is allowed."""
        # Arrange
        user_id = str(uuid4())

        handler.cache.get = Mock(return_value=None)
        handler.permission_service.has_permission = AsyncMock(return_value=True)
        handler.cache.set = Mock()

        command = CheckPermissionCommand(
            user_id=user_id,
            resource="user",
            action="read",
            context={"tenant_id": "123"},
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.allowed is True
        assert result.user_id == user_id
        assert result.resource == "user"
        assert result.action == "read"
        handler.permission_service.has_permission.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_permission_denied(self, handler):
        """Test permission check that is denied."""
        # Arrange
        user_id = str(uuid4())

        handler.cache.get = Mock(return_value=None)
        handler.permission_service.has_permission = AsyncMock(return_value=False)
        handler.cache.set = Mock()

        command = CheckPermissionCommand(
            user_id=user_id, resource="admin", action="write"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.allowed is False
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_check_permission_from_cache(self, handler):
        """Test permission check from cache."""
        # Arrange
        user_id = str(uuid4())
        cached_result = {"allowed": True, "cached_at": datetime.now(UTC).isoformat()}

        handler.cache.get = Mock(return_value=cached_result)

        command = CheckPermissionCommand(
            user_id=user_id, resource="user", action="read"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.allowed is True
        assert result.from_cache is True
        handler.permission_service.has_permission.assert_not_called()


class TestGetUserAccessQueryHandler:
    """Test get user access query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_role_repo = Mock()
        mock_permission_service = Mock()
        mock_cache = Mock()

        return GetUserAccessQueryHandler(
            user_repository=mock_user_repo,
            role_repository=mock_role_repo,
            permission_service=mock_permission_service,
            cache=mock_cache,
        )

    @pytest.mark.asyncio
    async def test_get_user_access_comprehensive(self, handler):
        """Test getting comprehensive user access information."""
        # Arrange
        user_id = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.roles = []

        roles = []
        for i in range(2):
            role = Mock(spec=Role)
            role.id = str(uuid4())
            role.name = f"Role {i}"
            role.permissions = []
            roles.append(role)

        permissions = []
        for i in range(3):
            permission = Mock(spec=Permission)
            permission.id = str(uuid4())
            permission.name = f"permission_{i}"
            permission.resource = f"resource_{i}"
            permission.action = "read"
            permissions.append(permission)

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.role_repository.get_user_roles = AsyncMock(return_value=roles)
        handler.permission_service.get_effective_permissions = AsyncMock(
            return_value=permissions
        )
        handler.cache.set = Mock()

        query = GetUserAccessQuery(user_id=user_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.user_id == user_id
        assert len(result.roles) == 2
        assert len(result.permissions) == 3
        assert result.total_permissions == 3

    @pytest.mark.asyncio
    async def test_get_user_access_with_context_filtering(self, handler):
        """Test getting user access with context filtering."""
        # Arrange
        user_id = str(uuid4())
        context = {"tenant_id": "123", "department": "engineering"}

        filtered_permissions = [Mock(spec=Permission) for _ in range(2)]

        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=Mock(spec=User))
        handler.role_repository.get_user_roles = AsyncMock(return_value=[])
        handler.permission_service.get_effective_permissions = AsyncMock(
            return_value=filtered_permissions
        )
        handler.cache.set = Mock()

        query = GetUserAccessQuery(
            user_id=user_id, context=context, include_inherited=True
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.permissions) == 2
        # Verify context was passed to permission service
        call_args = handler.permission_service.get_effective_permissions.call_args
        assert call_args[1]["context"] == context

    @pytest.mark.asyncio
    async def test_get_user_access_user_not_found(self, handler):
        """Test getting access for non-existent user."""
        # Arrange
        handler.cache.get = Mock(return_value=None)
        handler.user_repository.find_by_id = AsyncMock(return_value=None)

        query = GetUserAccessQuery(user_id=str(uuid4()))

        # Act & Assert
        with pytest.raises(UserNotFoundError):
            await handler.handle(query)


class TestGetRolePermissionsQueryHandler:
    """Test get role permissions query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_role_repo = Mock()
        mock_permission_repo = Mock()
        mock_cache = Mock()

        return GetRolePermissionsQueryHandler(
            role_repository=mock_role_repo,
            permission_repository=mock_permission_repo,
            cache=mock_cache,
        )

    @pytest.mark.asyncio
    async def test_get_role_permissions_success(self, handler):
        """Test getting role permissions successfully."""
        # Arrange
        role_id = str(uuid4())

        role = Mock(spec=Role)
        role.id = role_id
        role.name = "Manager"
        role.description = "Manager role"

        permissions = []
        for i in range(5):
            permission = Mock(spec=Permission)
            permission.id = str(uuid4())
            permission.name = f"manage_{i}"
            permission.resource = f"resource_{i}"
            permission.action = "manage"
            permission.scope = PermissionScope.DEPARTMENT
            permissions.append(permission)

        handler.cache.get = Mock(return_value=None)
        handler.role_repository.find_by_id = AsyncMock(return_value=role)
        handler.permission_repo.get_role_permissions = AsyncMock(
            return_value=permissions
        )
        handler.cache.set = Mock()

        query = GetRolePermissionsQuery(role_id=role_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.role_id == role_id
        assert result.role_name == "Manager"
        assert len(result.permissions) == 5
        assert result.total_permissions == 5

    @pytest.mark.asyncio
    async def test_get_role_permissions_with_inheritance(self, handler):
        """Test getting role permissions including inherited ones."""
        # Arrange
        role_id = str(uuid4())
        parent_role_id = str(uuid4())

        role = Mock(spec=Role)
        role.id = role_id
        role.parent_role_id = parent_role_id

        direct_permissions = [Mock(spec=Permission) for _ in range(3)]
        inherited_permissions = [Mock(spec=Permission) for _ in range(2)]
        all_permissions = direct_permissions + inherited_permissions

        handler.cache.get = Mock(return_value=None)
        handler.role_repository.find_by_id = AsyncMock(return_value=role)
        handler.permission_repo.get_role_permissions = AsyncMock(
            return_value=all_permissions
        )
        handler.cache.set = Mock()

        query = GetRolePermissionsQuery(role_id=role_id, include_inherited=True)

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.permissions) == 5
        assert result.has_inherited_permissions is True

    @pytest.mark.asyncio
    async def test_get_role_permissions_role_not_found(self, handler):
        """Test getting permissions for non-existent role."""
        # Arrange
        handler.cache.get = Mock(return_value=None)
        handler.role_repository.find_by_id = AsyncMock(return_value=None)

        query = GetRolePermissionsQuery(role_id=str(uuid4()))

        # Act & Assert
        with pytest.raises(RoleNotFoundError):
            await handler.handle(query)

    @pytest.mark.asyncio
    async def test_get_role_permissions_from_cache(self, handler):
        """Test getting role permissions from cache."""
        # Arrange
        role_id = str(uuid4())
        cached_data = {
            "role_id": role_id,
            "role_name": "Cached Role",
            "permissions": [
                {
                    "id": str(uuid4()),
                    "name": "cached_permission",
                    "resource": "cache",
                    "action": "read",
                }
            ],
            "total_permissions": 1,
        }

        handler.cache.get = Mock(return_value=cached_data)

        query = GetRolePermissionsQuery(role_id=role_id)

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.role_name == "Cached Role"
        assert len(result.permissions) == 1
        handler.role_repository.find_by_id.assert_not_called()


class TestGrantPermissionCommandHandler:
    """Test grant permission command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_permission_repo = Mock()
        mock_permission_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return GrantPermissionCommandHandler(
            user_repository=mock_user_repo,
            permission_repository=mock_permission_repo,
            permission_service=mock_permission_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_permission_grant(self, handler):
        """Test successful permission grant."""
        # Arrange
        user_id = str(uuid4())
        permission_id = str(uuid4())
        granted_by = str(uuid4())

        user = Mock(spec=User)
        user.id = user_id
        user.grant_direct_permission = Mock()

        permission = Mock(spec=Permission)
        permission.id = permission_id
        permission.name = "user:manage"
        permission.is_active = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.permission_repository.find_by_id = AsyncMock(return_value=permission)
        handler.permission_service.can_grant_permission = AsyncMock(return_value=True)
        handler.user_repository.save = AsyncMock()

        command = GrantPermissionCommand(
            user_id=user_id,
            permission_id=permission_id,
            granted_by=granted_by,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.user_id == user_id
        assert result.permission_id == permission_id
        user.grant_direct_permission.assert_called_once()
        handler.user_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_grant_permission_insufficient_permissions(self, handler):
        """Test granting permission with insufficient permissions."""
        # Arrange
        user = Mock(spec=User)
        permission = Mock(spec=Permission)
        permission.is_active = True

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.permission_repository.find_by_id = AsyncMock(return_value=permission)
        handler.permission_service.can_grant_permission = AsyncMock(return_value=False)

        command = GrantPermissionCommand(
            user_id=str(uuid4()), permission_id=str(uuid4()), granted_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(InsufficientPermissionsError):
            await handler.handle(command)

    @pytest.mark.asyncio
    async def test_grant_permission_already_granted(self, handler):
        """Test granting permission that user already has."""
        # Arrange
        user = Mock(spec=User)
        permission = Mock(spec=Permission)
        permission.is_active = True
        user.grant_direct_permission = Mock(
            side_effect=ValueError("Permission already granted")
        )

        handler.user_repository.find_by_id = AsyncMock(return_value=user)
        handler.permission_repository.find_by_id = AsyncMock(return_value=permission)
        handler.permission_service.can_grant_permission = AsyncMock(return_value=True)

        command = GrantPermissionCommand(
            user_id=str(uuid4()), permission_id=str(uuid4()), granted_by=str(uuid4())
        )

        # Act & Assert
        with pytest.raises(ValueError, match="already granted"):
            await handler.handle(command)
