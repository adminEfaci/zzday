"""Resource identifier value object.

This module defines the ResourceIdentifier value object that uniquely
identifies resources being audited in the system.
"""

from typing import Any
from uuid import UUID

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.utils.validation import validate_string


class ResourceIdentifier(ValueObject):
    """
    Uniquely identifies a resource in the audit trail.

    This value object provides a consistent way to identify any resource
    in the system, supporting both UUID-based and string-based identifiers.

    Attributes:
        resource_type: Type of the resource (e.g., 'user', 'order', 'payment')
        resource_id: Unique identifier of the resource
        resource_name: Optional human-readable name
        parent_type: Optional parent resource type for hierarchical resources
        parent_id: Optional parent resource identifier
        attributes: Additional identifying attributes

    Usage:
        # Simple resource
        resource = ResourceIdentifier(
            resource_type="user",
            resource_id="550e8400-e29b-41d4-a716-446655440000"
        )

        # Hierarchical resource
        resource = ResourceIdentifier(
            resource_type="comment",
            resource_id="123",
            parent_type="post",
            parent_id="456"
        )
    """

    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        resource_name: str | None = None,
        parent_type: str | None = None,
        parent_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ):
        """
        Initialize resource identifier.

        Args:
            resource_type: Type of the resource
            resource_id: Unique identifier
            resource_name: Optional human-readable name
            parent_type: Optional parent resource type
            parent_id: Optional parent identifier
            attributes: Additional attributes

        Raises:
            ValidationError: If required fields are invalid
        """
        super().__init__()

        # Validate and set resource type
        self.validate_not_empty(resource_type, "resource_type")
        self.resource_type = self._validate_resource_type(resource_type.lower().strip())

        # Validate and set resource ID
        self.validate_not_empty(resource_id, "resource_id")
        self.resource_id = self._validate_resource_id(str(resource_id).strip())

        # Set optional resource name
        if resource_name:
            self.resource_name = resource_name.strip()
        else:
            self.resource_name = None

        # Validate parent relationship if provided
        if parent_type or parent_id:
            if not (parent_type and parent_id):
                raise ValidationError(
                    "Both parent_type and parent_id must be provided for hierarchical resources"
                )
            self.parent_type = parent_type.lower().strip()
            self.parent_id = str(parent_id).strip()
        else:
            self.parent_type = None
            self.parent_id = None

        # Set additional attributes (immutable)
        if attributes:
            self.attributes = frozenset(attributes.items())
        else:
            self.attributes = frozenset()

        # Freeze the value object
        self._freeze()

    def _validate_resource_type(self, resource_type: str) -> str:
        """
        Validate resource type format.

        Args:
            resource_type: Resource type to validate

        Returns:
            Validated resource type

        Raises:
            ValidationError: If resource type is invalid
        """
        return validate_string(
            resource_type,
            "resource_type",
            required=True,
            max_length=50,
            pattern=r'^[a-zA-Z0-9_]+$'
        )

    def _validate_resource_id(self, resource_id: str) -> str:
        """
        Validate resource ID format.

        Args:
            resource_id: Resource ID to validate

        Returns:
            Validated resource ID

        Raises:
            ValidationError: If resource ID is invalid
        """
        return validate_string(
            resource_id,
            "resource_id",
            required=True,
            max_length=255
        )

    def get_full_path(self) -> str:
        """
        Get the full resource path including parent hierarchy.

        Returns:
            Full path string
        """
        if self.parent_type and self.parent_id:
            return f"{self.parent_type}/{self.parent_id}/{self.resource_type}/{self.resource_id}"
        return f"{self.resource_type}/{self.resource_id}"

    def get_display_name(self) -> str:
        """
        Get a human-readable display name for the resource.

        Returns:
            Display name string
        """
        if self.resource_name:
            return f"{self.resource_name} ({self.resource_type}:{self.resource_id})"
        return f"{self.resource_type}:{self.resource_id}"

    def is_hierarchical(self) -> bool:
        """Check if this resource has a parent."""
        return bool(self.parent_type and self.parent_id)

    def is_uuid_based(self) -> bool:
        """Check if the resource ID is a UUID."""
        try:
            UUID(self.resource_id)
            return True
        except ValueError:
            return False

    def matches_type(self, resource_type: str) -> bool:
        """Check if this resource matches the given type."""
        return self.resource_type == resource_type.lower()

    def with_name(self, name: str) -> "ResourceIdentifier":
        """
        Create a new identifier with the given name.

        Args:
            name: Resource name

        Returns:
            New ResourceIdentifier with name
        """
        return ResourceIdentifier(
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            resource_name=name,
            parent_type=self.parent_type,
            parent_id=self.parent_id,
            attributes=self.attributes,
        )

    def with_attribute(self, key: str, value: Any) -> "ResourceIdentifier":
        """
        Create a new identifier with an additional attribute.

        Args:
            key: Attribute key
            value: Attribute value

        Returns:
            New ResourceIdentifier with added attribute
        """
        new_attributes = dict(self.attributes)
        new_attributes[key] = value

        return ResourceIdentifier(
            resource_type=self.resource_type,
            resource_id=self.resource_id,
            resource_name=self.resource_name,
            parent_type=self.parent_type,
            parent_id=self.parent_id,
            attributes=new_attributes,
        )

    def to_audit_string(self) -> str:
        """
        Get a string representation suitable for audit logs.

        Returns:
            Audit-friendly string representation
        """
        parts = [f"type={self.resource_type}", f"id={self.resource_id}"]

        if self.resource_name:
            parts.append(f"name={self.resource_name}")

        if self.is_hierarchical():
            parts.append(f"parent={self.parent_type}:{self.parent_id}")

        if self.attributes:
            attributes_dict = dict(self.attributes)
            for key, value in attributes_dict.items():
                parts.append(f"{key}={value}")

        return ", ".join(parts)

    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get atomic values for equality comparison."""
        return (
            self.resource_type,
            self.resource_id,
            self.resource_name,
            self.parent_type,
            self.parent_id,
            self.attributes,
        )

    def __str__(self) -> str:
        """String representation of the resource identifier."""
        return self.get_full_path()

    @classmethod
    def create_for_user(
        cls, user_id: UUID, username: str | None = None
    ) -> "ResourceIdentifier":
        """
        Factory method for user resources.

        Args:
            user_id: User UUID
            username: Optional username

        Returns:
            ResourceIdentifier for user
        """
        return cls(
            resource_type="user", resource_id=str(user_id), resource_name=username
        )

    @classmethod
    def create_for_aggregate(
        cls, aggregate_type: str, aggregate_id: UUID, name: str | None = None
    ) -> "ResourceIdentifier":
        """
        Factory method for domain aggregates.

        Args:
            aggregate_type: Type of aggregate
            aggregate_id: Aggregate UUID
            name: Optional aggregate name

        Returns:
            ResourceIdentifier for aggregate
        """
        return cls(
            resource_type=aggregate_type,
            resource_id=str(aggregate_id),
            resource_name=name,
            attributes={"aggregate": True},
        )

    @classmethod
    def create_hierarchical(
        cls,
        resource_type: str,
        resource_id: str,
        parent_identifier: "ResourceIdentifier",
        resource_name: str | None = None,
    ) -> "ResourceIdentifier":
        """
        Factory method for hierarchical resources.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            parent_identifier: Parent resource identifier
            resource_name: Optional resource name

        Returns:
            ResourceIdentifier with parent relationship
        """
        return cls(
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            parent_type=parent_identifier.resource_type,
            parent_id=parent_identifier.resource_id,
        )

    @classmethod
    def create_for_session(
        cls, session_id: UUID, user_id: UUID | None = None
    ) -> "ResourceIdentifier":
        """Factory method for session resources."""
        attributes = {}
        if user_id:
            attributes["user_id"] = str(user_id)
            
        return cls(
            resource_type="session",
            resource_id=str(session_id),
            attributes=attributes,
        )

    @classmethod
    def create_for_role(
        cls, role_id: UUID, role_name: str | None = None
    ) -> "ResourceIdentifier":
        """Factory method for role resources."""
        return cls(
            resource_type="role",
            resource_id=str(role_id),
            resource_name=role_name,
        )

    @classmethod
    def create_for_permission(
        cls, permission_id: UUID, permission_name: str | None = None
    ) -> "ResourceIdentifier":
        """Factory method for permission resources."""
        return cls(
            resource_type="permission",
            resource_id=str(permission_id),
            resource_name=permission_name,
        )

    @classmethod
    def create_for_api_key(
        cls, api_key_id: UUID, key_name: str | None = None, user_id: UUID | None = None
    ) -> "ResourceIdentifier":
        """Factory method for API key resources."""
        attributes = {}
        if user_id:
            attributes["owner_id"] = str(user_id)
            
        return cls(
            resource_type="api_key",
            resource_id=str(api_key_id),
            resource_name=key_name,
            attributes=attributes,
        )

    @classmethod
    def create_for_device(
        cls, device_id: UUID, device_name: str | None = None, user_id: UUID | None = None
    ) -> "ResourceIdentifier":
        """Factory method for device resources."""
        attributes = {}
        if user_id:
            attributes["owner_id"] = str(user_id)
            
        return cls(
            resource_type="device",
            resource_id=str(device_id),
            resource_name=device_name,
            attributes=attributes,
        )

    @classmethod
    def create_for_organization(
        cls, org_id: UUID, org_name: str | None = None
    ) -> "ResourceIdentifier":
        """Factory method for organization resources."""
        return cls(
            resource_type="organization",
            resource_id=str(org_id),
            resource_name=org_name,
        )

    @classmethod
    def create_for_audit_log(
        cls, log_id: UUID, log_type: str | None = None
    ) -> "ResourceIdentifier":
        """Factory method for audit log resources."""
        attributes = {}
        if log_type:
            attributes["log_type"] = log_type
            
        return cls(
            resource_type="audit_log",
            resource_id=str(log_id),
            attributes=attributes,
        )

    @classmethod
    def create_system_resource(
        cls, resource_type: str, resource_id: str
    ) -> "ResourceIdentifier":
        """Factory method for system resources."""
        return cls(
            resource_type=resource_type,
            resource_id=resource_id,
            attributes={"system": True},
        )


__all__ = ["ResourceIdentifier"]
