"""
Role Domain Tests

Pure domain tests for Role entity isolated from infrastructure.
Tests business rules and domain logic without external dependencies.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.modules.identity.domain.entities.role.permission import Permission
from app.modules.identity.domain.entities.role.role import Role
from app.modules.identity.domain.exceptions import (
    RoleInvalidError,
)


@pytest.mark.unit
class TestRoleDomainCreation:
    """Test role domain entity creation."""
    
    def test_create_role_with_valid_data(self):
        """Test creating role with valid data."""
        role_id = uuid4()
        permissions = [
            Permission(name="user:read", description="Read user data"),
            Permission(name="user:write", description="Write user data"),
        ]
        
        role = Role(
            id=role_id,
            name="admin",
            description="Administrator role",
            level=100,
            permissions=permissions,
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.id == role_id
        assert role.name == "admin"
        assert role.description == "Administrator role"
        assert role.level == 100
        assert len(role.permissions) == 2
        assert role.is_system is False
        assert role.is_active is True
    
    def test_create_role_with_minimal_data(self):
        """Test creating role with minimal required data."""
        role = Role(
            id=uuid4(),
            name="user",
            description="Basic user role",
            level=1,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.name == "user"
        assert role.description == "Basic user role"
        assert role.level == 1
        assert len(role.permissions) == 0
        assert role.is_system is False
        assert role.is_active is True
    
    def test_create_system_role(self):
        """Test creating system role."""
        role = Role(
            id=uuid4(),
            name="system",
            description="System role",
            level=1000,
            permissions=[],
            is_system=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.name == "system"
        assert role.is_system is True
        assert role.level == 1000


@pytest.mark.unit
class TestRoleDomainBusinessRules:
    """Test role domain business rules."""
    
    def test_role_hierarchy_by_level(self):
        """Test role hierarchy is determined by level."""
        admin_role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        user_role = Role(
            id=uuid4(),
            name="user",
            description="User role",
            level=10,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert admin_role.is_higher_than(user_role)
        assert not user_role.is_higher_than(admin_role)
        assert not admin_role.is_higher_than(admin_role)
    
    def test_role_permission_check(self):
        """Test role permission checking."""
        permissions = [
            Permission(name="user:read", description="Read user data"),
            Permission(name="user:write", description="Write user data"),
        ]
        
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=permissions,
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.has_permission("user:read")
        assert role.has_permission("user:write")
        assert not role.has_permission("admin:delete")
    
    def test_active_role_can_be_used(self):
        """Test active role can be used."""
        role = Role(
            id=uuid4(),
            name="user",
            description="User role",
            level=10,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.can_be_used()
    
    def test_inactive_role_cannot_be_used(self):
        """Test inactive role cannot be used."""
        role = Role(
            id=uuid4(),
            name="user",
            description="User role",
            level=10,
            permissions=[],
            is_system=False,
            is_active=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert not role.can_be_used()
    
    def test_system_role_cannot_be_deleted(self):
        """Test system role cannot be deleted."""
        role = Role(
            id=uuid4(),
            name="system",
            description="System role",
            level=1000,
            permissions=[],
            is_system=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert not role.can_be_deleted()
    
    def test_non_system_role_can_be_deleted(self):
        """Test non-system role can be deleted."""
        role = Role(
            id=uuid4(),
            name="custom",
            description="Custom role",
            level=50,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.can_be_deleted()


@pytest.mark.unit
class TestRoleDomainOperations:
    """Test role domain operations."""
    
    def test_add_permission_to_role(self):
        """Test adding permission to role."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        permission = Permission(name="user:read", description="Read user data")
        
        assert len(role.permissions) == 0
        assert not role.has_permission("user:read")
        
        role.add_permission(permission)
        
        assert len(role.permissions) == 1
        assert role.has_permission("user:read")
    
    def test_remove_permission_from_role(self):
        """Test removing permission from role."""
        permission = Permission(name="user:read", description="Read user data")
        
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[permission],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert len(role.permissions) == 1
        assert role.has_permission("user:read")
        
        role.remove_permission("user:read")
        
        assert len(role.permissions) == 0
        assert not role.has_permission("user:read")
    
    def test_update_role_details(self):
        """Test updating role details."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        old_updated_at = role.updated_at
        
        role.update_details(
            name="super_admin",
            description="Super administrator role"
        )
        
        assert role.name == "super_admin"
        assert role.description == "Super administrator role"
        assert role.updated_at > old_updated_at
    
    def test_activate_role(self):
        """Test activating role."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.is_active is False
        
        role.activate()
        
        assert role.is_active is True
    
    def test_deactivate_role(self):
        """Test deactivating role."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role.is_active is True
        
        role.deactivate()
        
        assert role.is_active is False
    
    def test_cannot_deactivate_system_role(self):
        """Test cannot deactivate system role."""
        role = Role(
            id=uuid4(),
            name="system",
            description="System role",
            level=1000,
            permissions=[],
            is_system=True,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        with pytest.raises(RoleInvalidError):
            role.deactivate()
    
    def test_get_permission_names(self):
        """Test getting permission names."""
        permissions = [
            Permission(name="user:read", description="Read user data"),
            Permission(name="user:write", description="Write user data"),
            Permission(name="user:delete", description="Delete user data"),
        ]
        
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=permissions,
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        permission_names = role.get_permission_names()
        
        assert len(permission_names) == 3
        assert "user:read" in permission_names
        assert "user:write" in permission_names
        assert "user:delete" in permission_names


@pytest.mark.unit
class TestRoleDomainValidation:
    """Test role domain validation rules."""
    
    def test_role_name_cannot_be_empty(self):
        """Test role name cannot be empty."""
        with pytest.raises(RoleInvalidError):
            Role(
                id=uuid4(),
                name="",
                description="Empty name role",
                level=10,
                permissions=[],
                is_system=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
    
    def test_role_name_cannot_be_none(self):
        """Test role name cannot be None."""
        with pytest.raises(RoleInvalidError):
            Role(
                id=uuid4(),
                name=None,
                description="None name role",
                level=10,
                permissions=[],
                is_system=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
    
    def test_role_level_must_be_positive(self):
        """Test role level must be positive."""
        with pytest.raises(RoleInvalidError):
            Role(
                id=uuid4(),
                name="invalid",
                description="Invalid level role",
                level=-1,
                permissions=[],
                is_system=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
    
    def test_role_level_cannot_be_zero(self):
        """Test role level cannot be zero."""
        with pytest.raises(RoleInvalidError):
            Role(
                id=uuid4(),
                name="invalid",
                description="Zero level role",
                level=0,
                permissions=[],
                is_system=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
    
    def test_role_permissions_must_be_list(self):
        """Test role permissions must be a list."""
        with pytest.raises(RoleInvalidError):
            Role(
                id=uuid4(),
                name="invalid",
                description="Invalid permissions role",
                level=10,
                permissions=None,
                is_system=False,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
    
    def test_role_requires_valid_timestamps(self):
        """Test role requires valid timestamps."""
        with pytest.raises(ValueError):
            Role(
                id=uuid4(),
                name="invalid",
                description="Invalid timestamps role",
                level=10,
                permissions=[],
                is_system=False,
                is_active=True,
                created_at=None,
                updated_at=datetime.now(UTC)
            )


@pytest.mark.unit
class TestRoleDomainEquality:
    """Test role domain equality and identity."""
    
    def test_roles_with_same_id_are_equal(self):
        """Test roles with same ID are equal."""
        role_id = uuid4()
        
        role1 = Role(
            id=role_id,
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        role2 = Role(
            id=role_id,
            name="different",
            description="Different role",
            level=50,
            permissions=[],
            is_system=True,
            is_active=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role1 == role2
        assert hash(role1) == hash(role2)
    
    def test_roles_with_different_id_are_not_equal(self):
        """Test roles with different IDs are not equal."""
        role1 = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        role2 = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        assert role1 != role2
        assert hash(role1) != hash(role2)
    
    def test_role_string_representation(self):
        """Test role string representation."""
        role = Role(
            id=uuid4(),
            name="admin",
            description="Administrator role",
            level=100,
            permissions=[],
            is_system=False,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        role_str = str(role)
        assert "Role" in role_str
        assert "admin" in role_str
        assert "100" in role_str