"""
Type-Safe Schema Definitions

Provides base classes for type-safe data models and schemas.
"""

import logging
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime
from typing import Any, Generic, TypeVar, get_type_hints
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T")
ModelT = TypeVar("ModelT", bound="TypedModel")


class TypedModel(BaseModel):
    """
    Base class for type-safe Pydantic models.

    Provides enhanced type validation, serialization,
    and utility methods.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        str_strip_whitespace=True,
        validate_default=True,
        extra="forbid",
    )

    def to_dict(self, exclude_none: bool = True) -> dict[str, Any]:
        """
        Convert model to dictionary.

        Args:
            exclude_none: Whether to exclude None values

        Returns:
            Dictionary representation
        """
        return self.model_dump(exclude_none=exclude_none, by_alias=True)

    @classmethod
    def from_dict(cls: type[ModelT], data: dict[str, Any]) -> ModelT:
        """
        Create model from dictionary.

        Args:
            data: Dictionary data

        Returns:
            Model instance

        Raises:
            ValidationError: If validation fails
        """
        return cls.model_validate(data)

    def to_json(self, exclude_none: bool = True) -> str:
        """
        Convert model to JSON string.

        Args:
            exclude_none: Whether to exclude None values

        Returns:
            JSON string
        """
        return self.model_dump_json(exclude_none=exclude_none, by_alias=True)

    @classmethod
    def from_json(cls: type[ModelT], json_str: str) -> ModelT:
        """
        Create model from JSON string.

        Args:
            json_str: JSON string

        Returns:
            Model instance

        Raises:
            ValidationError: If validation fails
        """
        return cls.model_validate_json(json_str)

    def update(self, **kwargs: Any) -> "TypedModel":
        """
        Create updated copy of model.

        Args:
            **kwargs: Fields to update

        Returns:
            Updated model instance
        """
        data = self.to_dict()
        data.update(kwargs)
        return self.__class__.from_dict(data)

    def merge(self, other: "TypedModel") -> "TypedModel":
        """
        Merge with another model instance.

        Args:
            other: Other model to merge with

        Returns:
            Merged model instance
        """
        if not isinstance(other, self.__class__):
            raise TypeError(f"Cannot merge {type(other)} with {type(self)}")

        self_data = self.to_dict()
        other_data = other.to_dict()
        self_data.update(other_data)

        return self.__class__.from_dict(self_data)

    def get_field_info(self, field_name: str) -> dict[str, Any] | None:
        """
        Get information about a field.

        Args:
            field_name: Name of the field

        Returns:
            Field information or None if field doesn't exist
        """
        if field_name in self.model_fields:
            field_info = self.model_fields[field_name]
            return {
                "annotation": field_info.annotation,
                "default": field_info.default,
                "required": field_info.is_required(),
                "alias": field_info.alias,
                "description": field_info.description,
            }
        return None

    def validate_field(self, field_name: str, value: Any) -> Any:
        """
        Validate a single field value.

        Args:
            field_name: Name of the field
            value: Value to validate

        Returns:
            Validated value

        Raises:
            ValidationError: If validation fails
        """
        if field_name not in self.model_fields:
            raise ValueError(f"Field '{field_name}' does not exist")

        # Create a temporary instance to validate the field
        temp_data = self.to_dict()
        temp_data[field_name] = value

        try:
            temp_instance = self.__class__.from_dict(temp_data)
            return getattr(temp_instance, field_name)
        except ValidationError as e:
            # Re-raise with field-specific error
            field_errors = [error for error in e.errors() if field_name in error["loc"]]
            if field_errors:
                raise ValidationError.from_exception_data(
                    self.__class__.__name__, field_errors
                )
            raise


class StrictModel(TypedModel):
    """
    Strict model that disallows extra fields and validates strictly.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=False,
        str_strip_whitespace=True,
        validate_default=True,
        extra="forbid",
        frozen=True,  # Immutable
    )


@dataclass(frozen=True)
class ImmutableDataclass:
    """
    Base class for immutable dataclasses with type safety.
    """

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        if not is_dataclass(self):
            raise TypeError("Object is not a dataclass")

        result = {}
        for field_info in fields(self):
            value = getattr(self, field_info.name)
            if hasattr(value, "to_dict"):
                result[field_info.name] = value.to_dict()
            elif isinstance(value, list | tuple):
                result[field_info.name] = [
                    item.to_dict() if hasattr(item, "to_dict") else item
                    for item in value
                ]
            elif isinstance(value, dict):
                result[field_info.name] = {
                    k: (v.to_dict() if hasattr(v, "to_dict") else v)
                    for k, v in value.items()
                }
            else:
                result[field_info.name] = value

        return result

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        """Create from dictionary."""
        if not is_dataclass(cls):
            raise TypeError("Class is not a dataclass")

        # Get field types
        type_hints = get_type_hints(cls)

        # Convert data to appropriate types
        converted_data = {}
        for field_info in fields(cls):
            field_name = field_info.name
            if field_name in data:
                value = data[field_name]
                field_type = type_hints.get(field_name)

                # Basic type conversion
                if (
                    field_type
                    and hasattr(field_type, "from_dict")
                    and isinstance(value, dict)
                ):
                    converted_data[field_name] = field_type.from_dict(value)
                else:
                    converted_data[field_name] = value
            elif field_info.default != field_info.default_factory:
                # Use default value
                pass

        return cls(**converted_data)


@dataclass
class BaseEntity:
    """
    Base entity class with common fields.
    """

    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(datetime.UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(datetime.UTC))
    version: int = field(default=1)

    def update(self, **kwargs: Any) -> None:
        """Update entity fields."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.now(datetime.UTC)
        self.version += 1


class VersionedModel(TypedModel):
    """
    Model with version tracking.
    """

    version: int = Field(default=1, description="Model version")
    created_at: datetime = Field(default_factory=lambda: datetime.now(datetime.UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(datetime.UTC))

    def increment_version(self) -> "VersionedModel":
        """Increment version and update timestamp."""
        return self.update(
            version=self.version + 1, updated_at=datetime.now(datetime.UTC)
        )


class IdentifiableModel(TypedModel):
    """
    Model with unique identifier.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique identifier")

    def get_id(self) -> UUID:
        """Get the model ID."""
        return self.id


class TimestampedModel(TypedModel):
    """
    Model with timestamp tracking.
    """

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(datetime.UTC),
        description="Creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(datetime.UTC),
        description="Last update timestamp",
    )

    def touch(self) -> "TimestampedModel":
        """Update the timestamp."""
        return self.update(updated_at=datetime.now(datetime.UTC))


class AuditableModel(IdentifiableModel, TimestampedModel):
    """
    Model with full audit trail.
    """

    created_by: UUID | None = Field(default=None, description="Created by user ID")
    updated_by: UUID | None = Field(default=None, description="Updated by user ID")

    def audit_update(self, updated_by: UUID, **kwargs: Any) -> "AuditableModel":
        """Update with audit information."""
        return self.update(
            updated_by=updated_by, updated_at=datetime.now(datetime.UTC), **kwargs
        )


class SoftDeletableModel(AuditableModel):
    """
    Model that supports soft deletion.
    """

    deleted_at: datetime | None = Field(default=None, description="Deletion timestamp")
    deleted_by: UUID | None = Field(default=None, description="Deleted by user ID")

    @property
    def is_deleted(self) -> bool:
        """Check if model is soft deleted."""
        return self.deleted_at is not None

    def soft_delete(self, deleted_by: UUID) -> "SoftDeletableModel":
        """Soft delete the model."""
        if self.is_deleted:
            return self

        return self.update(
            deleted_at=datetime.now(datetime.UTC),
            deleted_by=deleted_by,
            updated_at=datetime.now(datetime.UTC),
            updated_by=deleted_by,
        )

    def restore(self, restored_by: UUID) -> "SoftDeletableModel":
        """Restore soft deleted model."""
        if not self.is_deleted:
            return self

        return self.update(
            deleted_at=None,
            deleted_by=None,
            updated_at=datetime.now(datetime.UTC),
            updated_by=restored_by,
        )


class ConfigurationModel(TypedModel):
    """
    Model for configuration settings.
    """

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a configuration setting."""
        return getattr(self, key, default)

    def set_setting(self, key: str, value: Any) -> "ConfigurationModel":
        """Set a configuration setting."""
        if not hasattr(self, key):
            raise ValueError(f"Unknown setting: {key}")

        return self.update(**{key: value})

    def get_all_settings(self) -> dict[str, Any]:
        """Get all configuration settings."""
        return self.to_dict()


# Generic schema types for common use cases
ResponseSchema = TypeVar("ResponseSchema", bound=TypedModel)
RequestSchema = TypeVar("RequestSchema", bound=TypedModel)
EntitySchema = TypeVar("EntitySchema", bound=AuditableModel)


class APIResponse(Generic[T], TypedModel):
    """
    Generic API response wrapper.
    """

    success: bool = Field(description="Whether the request was successful")
    data: T | None = Field(default=None, description="Response data")
    message: str | None = Field(default=None, description="Response message")
    errors: list[str] | None = Field(default=None, description="Error messages")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(datetime.UTC),
        description="Response timestamp",
    )

    @classmethod
    def success_response(cls, data: T, message: str | None = None) -> "APIResponse[T]":
        """Create successful response."""
        return cls(success=True, data=data, message=message)

    @classmethod
    def error_response(
        cls, errors: list[str], message: str | None = None
    ) -> "APIResponse[T]":
        """Create error response."""
        return cls(success=False, errors=errors, message=message)


class PaginatedResponse(Generic[T], TypedModel):
    """
    Generic paginated response.
    """

    items: list[T] = Field(description="List of items")
    total: int = Field(description="Total number of items")
    page: int = Field(description="Current page number")
    size: int = Field(description="Page size")
    pages: int = Field(description="Total number of pages")

    @classmethod
    def create(
        cls, items: list[T], total: int, page: int, size: int
    ) -> "PaginatedResponse[T]":
        """Create paginated response."""
        pages = (total + size - 1) // size if size > 0 else 0
        return cls(items=items, total=total, page=page, size=size, pages=pages)
