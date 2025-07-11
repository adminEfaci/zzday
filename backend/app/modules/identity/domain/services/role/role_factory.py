"""Role Factory Domain Service

Factory for creating role entities with various configurations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...entities.role.permission import Permission
from ...entities.role.role import Role
from ..enums import PermissionAction, ResourceType


class RoleFactory:
    """Factory for creating Role entities with specific configurations."""

    # Predefined permission sets
    ADMIN_PERMISSIONS = [
        (ResourceType.USER, PermissionAction.CREATE),
        (ResourceType.USER, PermissionAction.READ),
        (ResourceType.USER, PermissionAction.UPDATE),
        (ResourceType.USER, PermissionAction.DELETE),
        (ResourceType.ROLE, PermissionAction.CREATE),
        (ResourceType.ROLE, PermissionAction.READ),
        (ResourceType.ROLE, PermissionAction.UPDATE),
        (ResourceType.ROLE, PermissionAction.DELETE),
        (ResourceType.PERMISSION, PermissionAction.CREATE),
        (ResourceType.PERMISSION, PermissionAction.READ),
        (ResourceType.PERMISSION, PermissionAction.UPDATE),
        (ResourceType.PERMISSION, PermissionAction.DELETE),
        (ResourceType.AUDIT_LOG, PermissionAction.READ),
        (ResourceType.SYSTEM_CONFIG, PermissionAction.READ),
        (ResourceType.SYSTEM_CONFIG, PermissionAction.UPDATE),
    ]

    MODERATOR_PERMISSIONS = [
        (ResourceType.USER, PermissionAction.READ),
        (ResourceType.USER, PermissionAction.UPDATE),
        (ResourceType.CONTENT, PermissionAction.READ),
        (ResourceType.CONTENT, PermissionAction.UPDATE),
        (ResourceType.CONTENT, PermissionAction.DELETE),
        (ResourceType.REPORT, PermissionAction.READ),
        (ResourceType.REPORT, PermissionAction.UPDATE),
        (ResourceType.AUDIT_LOG, PermissionAction.READ),
    ]

    USER_PERMISSIONS = [
        (ResourceType.PROFILE, PermissionAction.READ),
        (ResourceType.PROFILE, PermissionAction.UPDATE),
        (ResourceType.CONTENT, PermissionAction.CREATE),
        (ResourceType.CONTENT, PermissionAction.READ),
        (ResourceType.CONTENT, PermissionAction.UPDATE),
        (ResourceType.CONTENT, PermissionAction.DELETE),
        (ResourceType.PREFERENCE, PermissionAction.READ),
        (ResourceType.PREFERENCE, PermissionAction.UPDATE),
    ]

    @staticmethod
    def create_admin_role(
        name: str = "Administrator",
        description: str | None = None
    ) -> Role:
        """Create an administrator role with full permissions."""
        role = Role.create(
            name=name,
            description=description or "Full system administration privileges",
            is_system=True,
            metadata={
                "role_type": "admin",
                "priority": 100,
                "created_by": "system"
            }
        )

        # Add admin permissions
        for resource, action in RoleFactory.ADMIN_PERMISSIONS:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value}"
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_moderator_role(
        name: str = "Moderator",
        description: str | None = None
    ) -> Role:
        """Create a moderator role with content management permissions."""
        role = Role.create(
            name=name,
            description=description or "Content moderation and user management",
            is_system=True,
            metadata={
                "role_type": "moderator",
                "priority": 50,
                "created_by": "system"
            }
        )

        # Add moderator permissions
        for resource, action in RoleFactory.MODERATOR_PERMISSIONS:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value}"
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_user_role(
        name: str = "User",
        description: str | None = None
    ) -> Role:
        """Create a standard user role with basic permissions."""
        role = Role.create(
            name=name,
            description=description or "Standard user permissions",
            is_system=True,
            is_default=True,  # Assigned to new users by default
            metadata={
                "role_type": "user",
                "priority": 10,
                "created_by": "system"
            }
        )

        # Add user permissions
        for resource, action in RoleFactory.USER_PERMISSIONS:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value}"
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_guest_role() -> Role:
        """Create a guest role with minimal read-only permissions."""
        role = Role.create(
            name="Guest",
            description="Limited read-only access",
            is_system=True,
            metadata={
                "role_type": "guest",
                "priority": 0,
                "created_by": "system"
            }
        )

        # Add minimal permissions
        guest_permissions = [
            (ResourceType.CONTENT, PermissionAction.READ),
            (ResourceType.PROFILE, PermissionAction.READ),
        ]

        for resource, action in guest_permissions:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value}"
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_service_role(
        service_name: str,
        allowed_resources: list[ResourceType],
        allowed_actions: list[PermissionAction]
    ) -> Role:
        """Create a service account role with specific API permissions."""
        role = Role.create(
            name=f"{service_name}_service",
            description=f"Service account role for {service_name}",
            is_system=True,
            metadata={
                "role_type": "service",
                "service_name": service_name,
                "created_by": "system"
            }
        )

        # Add service-specific permissions
        for resource in allowed_resources:
            for action in allowed_actions:
                permission = Permission.create(
                    name=f"{resource.value}:{action.value}",
                    resource=resource,
                    action=action,
                    description=f"Service permission: {action.value} on {resource.value}"
                )
                role.add_permission(permission)

        return role

    @staticmethod
    def create_custom_role(
        name: str,
        description: str,
        permissions: list[tuple[ResourceType, PermissionAction]],
        metadata: dict[str, Any] | None = None
    ) -> Role:
        """Create a custom role with specific permissions."""
        role = Role.create(
            name=name,
            description=description,
            is_system=False,
            metadata=metadata or {"created_by": "admin"}
        )

        # Add custom permissions
        for resource, action in permissions:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value}"
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_department_role(
        department: str,
        level: str = "member"
    ) -> Role:
        """Create a department-specific role."""
        level_permissions = {
            "member": [
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.READ),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.CREATE),
            ],
            "lead": [
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.READ),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.CREATE),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.UPDATE),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.APPROVE),
            ],
            "manager": [
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.READ),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.CREATE),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.UPDATE),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.DELETE),
                (ResourceType.DEPARTMENT_RESOURCE, PermissionAction.APPROVE),
                (ResourceType.USER, PermissionAction.READ),
                (ResourceType.USER, PermissionAction.UPDATE),
            ]
        }

        role = Role.create(
            name=f"{department}_{level}",
            description=f"{level.title()} role for {department} department",
            is_system=False,
            metadata={
                "department": department,
                "level": level,
                "created_by": "system"
            }
        )

        # Add level-specific permissions
        permissions = level_permissions.get(level, [])
        for resource, action in permissions:
            permission = Permission.create(
                name=f"{resource.value}:{action.value}:{department}",
                resource=resource,
                action=action,
                description=f"Allow {action.value} on {resource.value} in {department}",
                metadata={"department": department}
            )
            role.add_permission(permission)

        return role

    @staticmethod
    def create_time_limited_role(
            base_role: Role,
            duration_days: int
        ) -> Role:
            """Create a time-limited version of an existing role."""
            from datetime import timedelta

            role = Role.create(
                name=f"{base_role.name}_temporary",
                description=f"{base_role.description} (temporary - {duration_days} days)",
                is_system=False,
                metadata={
                    "base_role_id": str(base_role.id),
                    "duration_days": duration_days,
                    "expires_at": (datetime.now(UTC) + timedelta(days=duration_days)).isoformat(),
                    "created_by": "system"
                }
            )

            # Copy permissions from base role
            if hasattr(base_role, 'permissions'):
                for perm in base_role.permissions:
                    role.add_permission(perm)

            return role

    @staticmethod
    def get_default_roles() -> list[Role]:
        """Get all default system roles."""
        return [
            RoleFactory.create_admin_role(),
            RoleFactory.create_moderator_role(),
            RoleFactory.create_user_role(),
            RoleFactory.create_guest_role()
        ]
