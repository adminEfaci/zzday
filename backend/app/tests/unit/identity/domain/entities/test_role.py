"""
Comprehensive unit tests for Role entity.

Tests cover:
- Role creation and validation
- Permission management
- Business rules enforcement
- State transitions
"""

from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.entities.permission import Permission
from app.modules.identity.domain.entities.role import Role
from app.modules.identity.domain.errors import (
    BusinessRuleViolation,
    DomainError,
)
from app.modules.identity.domain.value_objects.permission_id import PermissionId
from app.modules.identity.domain.value_objects.role_id import RoleId


class TestRole:
    """Test suite for Role entity."""

    @pytest.fixture
    def test_permissions(self):
        """Create test permissions."""
        return [
            Permission.create(
                code="users.read",
                name="Read Users",
                description="Can read user data",
                resource="users",
                action="read",
            ),
            Permission.create(
                code="users.write",
                name="Write Users",
                description="Can write user data",
                resource="users",
                action="write",
            ),
            Permission.create(
                code="users.delete",
                name="Delete Users",
                description="Can delete users",
                resource="users",
                action="delete",
            ),
        ]

    def test_create_role_with_valid_data(self, test_permissions):
        """Test creating a role with valid data."""
        role = Role.create(
            name="Admin",
            description="Administrator role with full access",
            permissions=[test_permissions[0].id, test_permissions[1].id],
        )
        
        assert role.id is not None
        assert isinstance(role.id, RoleId)
        assert role.name == "Admin"
        assert role.description == "Administrator role with full access"
        assert len(role.permissions) == 2
        assert role.is_active is True
        assert role.is_system is False
        assert role.created_at is not None
        assert role.updated_at is not None

    def test_create_role_without_permissions(self):
        """Test creating a role without initial permissions."""
        role = Role.create(
            name="Guest",
            description="Guest role with no permissions",
        )
        
        assert role.name == "Guest"
        assert len(role.permissions) == 0

    def test_create_system_role(self):
        """Test creating a system role."""
        role = Role.create(
            name="SuperAdmin",
            description="System super administrator",
            is_system=True,
        )
        
        assert role.is_system is True
        assert role.is_active is True

    def test_role_name_validation(self):
        """Test role name validation."""
        # Empty name
        with pytest.raises(DomainError) as exc_info:
            Role.create(name="", description="Test")
        assert "Role name cannot be empty" in str(exc_info.value)
        
        # Too short
        with pytest.raises(DomainError) as exc_info:
            Role.create(name="AB", description="Test")
        assert "at least 3 characters" in str(exc_info.value)
        
        # Too long
        with pytest.raises(DomainError) as exc_info:
            Role.create(name="A" * 51, description="Test")
        assert "exceed 50 characters" in str(exc_info.value)

    def test_role_name_format_validation(self):
        """Test role name format requirements."""
        # Valid names
        valid_names = [
            "Admin",
            "User Manager",
            "Content-Editor",
            "API_User",
            "Role123",
        ]
        
        for name in valid_names:
            role = Role.create(name=name, description="Test")
            assert role.name == name
        
        # Invalid names
        invalid_names = [
            "Admin!",  # Special chars
            "@Admin",  # Special chars
            "Role#1",  # Special chars
            "123Role",  # Starts with number
            "_Role",  # Starts with underscore
        ]
        
        for name in invalid_names:
            with pytest.raises(DomainError):
                Role.create(name=name, description="Test")

    def test_add_permission_to_role(self, test_permissions):
        """Test adding permissions to a role."""
        role = Role.create(
            name="Editor",
            description="Content editor role",
        )
        
        # Add single permission
        role.add_permission(test_permissions[0].id)
        
        assert len(role.permissions) == 1
        assert test_permissions[0].id in role.permissions
        
        # Add another permission
        role.add_permission(test_permissions[1].id)
        
        assert len(role.permissions) == 2

    def test_add_duplicate_permission(self, test_permissions):
        """Test adding duplicate permission is idempotent."""
        role = Role.create(
            name="Editor",
            description="Content editor role",
            permissions=[test_permissions[0].id],
        )
        
        # Add same permission again
        role.add_permission(test_permissions[0].id)
        
        # Should still have only one permission
        assert len(role.permissions) == 1

    def test_add_multiple_permissions(self, test_permissions):
        """Test adding multiple permissions at once."""
        role = Role.create(
            name="Manager",
            description="Manager role",
        )
        
        permission_ids = [p.id for p in test_permissions]
        role.add_permissions(permission_ids)
        
        assert len(role.permissions) == 3
        for perm_id in permission_ids:
            assert perm_id in role.permissions

    def test_remove_permission_from_role(self, test_permissions):
        """Test removing permissions from a role."""
        role = Role.create(
            name="Admin",
            description="Admin role",
            permissions=[p.id for p in test_permissions],
        )
        
        # Remove one permission
        role.remove_permission(test_permissions[1].id)
        
        assert len(role.permissions) == 2
        assert test_permissions[1].id not in role.permissions
        assert test_permissions[0].id in role.permissions
        assert test_permissions[2].id in role.permissions

    def test_remove_non_existent_permission(self, test_permissions):
        """Test removing non-existent permission is safe."""
        role = Role.create(
            name="User",
            description="User role",
            permissions=[test_permissions[0].id],
        )
        
        non_existent = PermissionId.generate()
        
        # Should not raise error
        role.remove_permission(non_existent)
        
        # Permissions unchanged
        assert len(role.permissions) == 1

    def test_clear_all_permissions(self, test_permissions):
        """Test clearing all permissions from a role."""
        role = Role.create(
            name="Admin",
            description="Admin role",
            permissions=[p.id for p in test_permissions],
        )
        
        role.clear_permissions()
        
        assert len(role.permissions) == 0

    def test_has_permission_check(self, test_permissions):
        """Test checking if role has specific permission."""
        role = Role.create(
            name="Editor",
            description="Editor role",
            permissions=[test_permissions[0].id, test_permissions[1].id],
        )
        
        assert role.has_permission(test_permissions[0].id) is True
        assert role.has_permission(test_permissions[1].id) is True
        assert role.has_permission(test_permissions[2].id) is False

    def test_deactivate_role(self):
        """Test deactivating a role."""
        role = Role.create(
            name="TempRole",
            description="Temporary role",
        )
        
        assert role.is_active is True
        
        role.deactivate()
        
        assert role.is_active is False
        assert role.deactivated_at is not None

    def test_activate_role(self):
        """Test activating a deactivated role."""
        role = Role.create(
            name="TempRole",
            description="Temporary role",
        )
        role.deactivate()
        
        assert role.is_active is False
        
        role.activate()
        
        assert role.is_active is True
        assert role.deactivated_at is None

    def test_cannot_modify_system_role(self, test_permissions):
        """Test that system roles cannot be modified."""
        role = Role.create(
            name="SystemAdmin",
            description="System admin role",
            is_system=True,
        )
        
        # Cannot add permissions
        with pytest.raises(BusinessRuleViolation) as exc_info:
            role.add_permission(test_permissions[0].id)
        assert "Cannot modify system role" in str(exc_info.value)
        
        # Cannot remove permissions
        with pytest.raises(BusinessRuleViolation):
            role.remove_permission(test_permissions[0].id)
        
        # Cannot clear permissions
        with pytest.raises(BusinessRuleViolation):
            role.clear_permissions()
        
        # Cannot deactivate
        with pytest.raises(BusinessRuleViolation):
            role.deactivate()

    def test_update_role_details(self):
        """Test updating role name and description."""
        role = Role.create(
            name="OldName",
            description="Old description",
        )
        
        role.update_details(
            name="NewName",
            description="New description",
        )
        
        assert role.name == "NewName"
        assert role.description == "New description"
        assert role.updated_at > role.created_at

    def test_update_role_with_invalid_name(self):
        """Test updating role with invalid name."""
        role = Role.create(
            name="ValidName",
            description="Description",
        )
        
        with pytest.raises(DomainError):
            role.update_details(name="", description="New description")
        
        # Name should remain unchanged
        assert role.name == "ValidName"

    def test_role_equality(self):
        """Test role equality comparison."""
        role_id = RoleId.generate()
        
        role1 = Role(
            id=role_id,
            name="Admin",
            description="Admin role",
            permissions=[],
            is_active=True,
            is_system=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        
        role2 = Role(
            id=role_id,
            name="Admin",
            description="Admin role",
            permissions=[],
            is_active=True,
            is_system=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        
        role3 = Role.create(name="Admin", description="Different role")
        
        assert role1 == role2  # Same ID
        assert role1 != role3  # Different ID

    def test_role_string_representation(self):
        """Test string representation of role."""
        role = Role.create(
            name="Administrator",
            description="System administrator",
        )
        
        str_repr = str(role)
        repr_repr = repr(role)
        
        assert "Administrator" in str_repr
        assert "Role" in repr_repr
        assert str(role.id) in repr_repr

    def test_role_permission_limit(self):
        """Test role permission limit enforcement."""
        role = Role.create(
            name="SuperRole",
            description="Role with many permissions",
        )
        
        # Try to add more than limit (e.g., 100)
        permission_ids = [PermissionId.generate() for _ in range(101)]
        
        with pytest.raises(BusinessRuleViolation) as exc_info:
            role.add_permissions(permission_ids)
        
        assert "cannot exceed" in str(exc_info.value).lower()

    def test_role_clone(self, test_permissions):
        """Test cloning a role."""
        original = Role.create(
            name="Original",
            description="Original role",
            permissions=[test_permissions[0].id],
        )
        
        cloned = original.clone(
            new_name="Cloned",
            new_description="Cloned role",
        )
        
        assert cloned.id != original.id
        assert cloned.name == "Cloned"
        assert cloned.description == "Cloned role"
        assert cloned.permissions == original.permissions
        assert cloned.is_system is False  # Never clone system flag

    def test_role_audit_fields(self):
        """Test role audit fields are properly set."""
        role = Role.create(
            name="AuditTest",
            description="Test audit fields",
        )
        
        assert role.created_at is not None
        assert role.updated_at is not None
        assert role.created_at == role.updated_at
        
        # Update role
        original_updated = role.updated_at
        role.update_details(name="UpdatedAudit", description="Updated")
        
        assert role.updated_at > original_updated
        assert role.created_at < role.updated_at

    def test_role_domain_events(self, test_permissions):
        """Test that role operations generate domain events."""
        role = Role.create(
            name="EventRole",
            description="Role for testing events",
        )
        
        # Clear initial events
        role.pull_domain_events()
        
        # Add permission
        role.add_permission(test_permissions[0].id)
        events = role.pull_domain_events()
        
        assert len(events) == 1
        assert events[0].__class__.__name__ == "RolePermissionAddedEvent"
        
        # Remove permission
        role.remove_permission(test_permissions[0].id)
        events = role.pull_domain_events()
        
        assert len(events) == 1
        assert events[0].__class__.__name__ == "RolePermissionRemovedEvent"
        
        # Deactivate
        role.deactivate()
        events = role.pull_domain_events()
        
        assert len(events) == 1
        assert events[0].__class__.__name__ == "RoleDeactivatedEvent"