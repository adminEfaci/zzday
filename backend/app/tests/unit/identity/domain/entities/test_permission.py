"""
Comprehensive unit tests for Permission entity.

Tests cover:
- Permission creation and validation
- Resource and action management
- Permission matching and checking
- Immutability of permissions
"""

from datetime import UTC, datetime

import pytest

from app.modules.identity.domain.entities.permission import Permission
from app.modules.identity.domain.errors import BusinessRuleViolation, DomainError
from app.modules.identity.domain.value_objects.permission_id import PermissionId


class TestPermission:
    """Test suite for Permission entity."""

    def test_create_permission_with_valid_data(self):
        """Test creating a permission with valid data."""
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            description="Can read user data",
            resource="users",
            action="read",
        )
        
        assert permission.id is not None
        assert isinstance(permission.id, PermissionId)
        assert permission.code == "users.read"
        assert permission.name == "Read Users"
        assert permission.description == "Can read user data"
        assert permission.resource == "users"
        assert permission.action == "read"
        assert permission.is_active is True
        assert permission.created_at is not None

    def test_create_permission_without_description(self):
        """Test creating a permission without description."""
        permission = Permission.create(
            code="posts.write",
            name="Write Posts",
            resource="posts",
            action="write",
        )
        
        assert permission.description == ""

    def test_permission_code_validation(self):
        """Test permission code validation."""
        # Empty code
        with pytest.raises(DomainError) as exc_info:
            Permission.create(
                code="",
                name="Test",
                resource="test",
                action="read",
            )
        assert "Permission code cannot be empty" in str(exc_info.value)
        
        # Invalid format
        invalid_codes = [
            "users read",  # Space
            "users@read",  # Special char
            "users#read",  # Special char
            "Users.Read",  # Uppercase
            ".users.read",  # Leading dot
            "users.read.",  # Trailing dot
            "users..read",  # Double dot
        ]
        
        for code in invalid_codes:
            with pytest.raises(DomainError):
                Permission.create(
                    code=code,
                    name="Test",
                    resource="test",
                    action="read",
                )

    def test_valid_permission_codes(self):
        """Test valid permission code formats."""
        valid_codes = [
            "users.read",
            "users.write",
            "admin.users.delete",
            "api.v1.users.list",
            "system.config.update",
            "reports_analytics.view",
        ]
        
        for code in valid_codes:
            permission = Permission.create(
                code=code,
                name="Test Permission",
                resource="test",
                action="test",
            )
            assert permission.code == code

    def test_permission_name_validation(self):
        """Test permission name validation."""
        # Empty name
        with pytest.raises(DomainError) as exc_info:
            Permission.create(
                code="test.read",
                name="",
                resource="test",
                action="read",
            )
        assert "Permission name cannot be empty" in str(exc_info.value)
        
        # Too long
        with pytest.raises(DomainError) as exc_info:
            Permission.create(
                code="test.read",
                name="A" * 101,
                resource="test",
                action="read",
            )
        assert "exceed 100 characters" in str(exc_info.value)

    def test_resource_validation(self):
        """Test resource validation."""
        # Empty resource
        with pytest.raises(DomainError) as exc_info:
            Permission.create(
                code="test.read",
                name="Test",
                resource="",
                action="read",
            )
        assert "Resource cannot be empty" in str(exc_info.value)
        
        # Valid resources
        valid_resources = ["users", "posts", "admin", "*", "api.users"]
        
        for resource in valid_resources:
            permission = Permission.create(
                code=f"{resource}.read",
                name="Test",
                resource=resource,
                action="read",
            )
            assert permission.resource == resource

    def test_action_validation(self):
        """Test action validation."""
        # Empty action
        with pytest.raises(DomainError) as exc_info:
            Permission.create(
                code="test.action",
                name="Test",
                resource="test",
                action="",
            )
        assert "Action cannot be empty" in str(exc_info.value)
        
        # Valid actions
        valid_actions = ["read", "write", "delete", "create", "update", "*", "execute"]
        
        for action in valid_actions:
            permission = Permission.create(
                code=f"test.{action}",
                name="Test",
                resource="test",
                action=action,
            )
            assert permission.action == action

    def test_wildcard_permissions(self):
        """Test wildcard permissions."""
        # Wildcard resource
        permission1 = Permission.create(
            code="admin.all",
            name="Admin All",
            resource="*",
            action="*",
        )
        
        assert permission1.is_wildcard()
        assert permission1.matches("users", "read")
        assert permission1.matches("posts", "delete")
        assert permission1.matches("anything", "anything")

    def test_permission_matching(self):
        """Test permission matching logic."""
        # Specific permission
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        assert permission.matches("users", "read") is True
        assert permission.matches("users", "write") is False
        assert permission.matches("posts", "read") is False
        assert permission.matches("users", "*") is False

    def test_wildcard_action_matching(self):
        """Test wildcard action matching."""
        permission = Permission.create(
            code="users.all",
            name="All User Actions",
            resource="users",
            action="*",
        )
        
        assert permission.matches("users", "read") is True
        assert permission.matches("users", "write") is True
        assert permission.matches("users", "delete") is True
        assert permission.matches("posts", "read") is False

    def test_wildcard_resource_matching(self):
        """Test wildcard resource matching."""
        permission = Permission.create(
            code="all.read",
            name="Read Everything",
            resource="*",
            action="read",
        )
        
        assert permission.matches("users", "read") is True
        assert permission.matches("posts", "read") is True
        assert permission.matches("admin", "read") is True
        assert permission.matches("users", "write") is False

    def test_hierarchical_resource_matching(self):
        """Test hierarchical resource matching."""
        permission = Permission.create(
            code="api.users.read",
            name="Read API Users",
            resource="api.users",
            action="read",
        )
        
        # Exact match
        assert permission.matches("api.users", "read") is True
        
        # Parent/child don't match without wildcards
        assert permission.matches("api", "read") is False
        assert permission.matches("api.users.profile", "read") is False

    def test_permission_deactivation(self):
        """Test permission deactivation."""
        permission = Permission.create(
            code="test.read",
            name="Test",
            resource="test",
            action="read",
        )
        
        assert permission.is_active is True
        
        permission.deactivate()
        
        assert permission.is_active is False
        assert permission.deactivated_at is not None

    def test_permission_activation(self):
        """Test permission activation."""
        permission = Permission.create(
            code="test.read",
            name="Test",
            resource="test",
            action="read",
        )
        permission.deactivate()
        
        permission.activate()
        
        assert permission.is_active is True
        assert permission.deactivated_at is None

    def test_permission_immutability(self):
        """Test that core permission attributes are immutable."""
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        # Should not be able to change code, resource, or action
        with pytest.raises(BusinessRuleViolation) as exc_info:
            permission.code = "users.write"
        assert "immutable" in str(exc_info.value).lower()

    def test_permission_equality(self):
        """Test permission equality comparison."""
        perm_id = PermissionId.generate()
        
        perm1 = Permission(
            id=perm_id,
            code="users.read",
            name="Read Users",
            description="",
            resource="users",
            action="read",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        
        perm2 = Permission(
            id=perm_id,
            code="users.read",
            name="Read Users",
            description="",
            resource="users",
            action="read",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        
        perm3 = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        assert perm1 == perm2  # Same ID
        assert perm1 != perm3  # Different ID

    def test_permission_string_representation(self):
        """Test string representation of permission."""
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        str_repr = str(permission)
        repr_repr = repr(permission)
        
        assert "users.read" in str_repr
        assert "Permission" in repr_repr
        assert permission.code in repr_repr

    def test_permission_to_dict(self):
        """Test converting permission to dictionary."""
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            description="Can read user data",
            resource="users",
            action="read",
        )
        
        perm_dict = permission.to_dict()
        
        assert perm_dict["id"] == str(permission.id)
        assert perm_dict["code"] == "users.read"
        assert perm_dict["name"] == "Read Users"
        assert perm_dict["description"] == "Can read user data"
        assert perm_dict["resource"] == "users"
        assert perm_dict["action"] == "read"
        assert perm_dict["is_active"] is True

    def test_system_permissions(self):
        """Test system permissions cannot be modified."""
        permission = Permission.create(
            code="system.admin",
            name="System Admin",
            resource="system",
            action="*",
            is_system=True,
        )
        
        assert permission.is_system is True
        
        # Cannot deactivate system permissions
        with pytest.raises(BusinessRuleViolation) as exc_info:
            permission.deactivate()
        assert "Cannot modify system permission" in str(exc_info.value)

    def test_permission_categories(self):
        """Test permission categories/groups."""
        permission = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
            category="user_management",
        )
        
        assert permission.category == "user_management"

    def test_permission_metadata(self):
        """Test permission metadata."""
        permission = Permission.create(
            code="api.users.read",
            name="API Read Users",
            resource="api.users",
            action="read",
            metadata={
                "rate_limit": 100,
                "requires_mfa": True,
                "api_version": "v1",
            }
        )
        
        assert permission.metadata["rate_limit"] == 100
        assert permission.metadata["requires_mfa"] is True
        assert permission.metadata["api_version"] == "v1"

    def test_permission_implies(self):
        """Test permission implication logic."""
        # Admin permission implies specific permissions
        admin_perm = Permission.create(
            code="users.admin",
            name="User Admin",
            resource="users",
            action="*",
        )
        
        read_perm = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        write_perm = Permission.create(
            code="posts.write",
            name="Write Posts",
            resource="posts",
            action="write",
        )
        
        assert admin_perm.implies(read_perm) is True
        assert admin_perm.implies(write_perm) is False
        assert read_perm.implies(admin_perm) is False

    def test_permission_code_uniqueness(self):
        """Test that permission codes should be unique."""
        perm1 = Permission.create(
            code="users.read",
            name="Read Users",
            resource="users",
            action="read",
        )
        
        perm2 = Permission.create(
            code="users.read",
            name="Different Name",
            resource="users",
            action="read",
        )
        
        # Both can be created (uniqueness enforced at repository level)
        assert perm1.code == perm2.code
        assert perm1.id != perm2.id