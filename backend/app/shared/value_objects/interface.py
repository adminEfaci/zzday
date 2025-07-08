"""Domain interfaces and protocols following DDD principles.

This module provides Protocol-based interfaces that define contracts for common
domain entity behaviors. These interfaces follow Domain-Driven Design principles
and support composition for rich domain models.

The interfaces are designed to be:
- Framework-agnostic (pure Python protocols)
- Composable (can be mixed and matched)
- Type-safe (full type hints)
- Business-focused (express domain concepts)
- Production-ready (comprehensive method signatures)

Design Patterns:
- Single Responsibility: Each interface has one concern
- Interface Segregation: Specific interfaces rather than monolithic ones
- Dependency Inversion: Depend on abstractions, not concretions
- Composition over Inheritance: Mix interfaces as needed

Usage Examples:
    # Basic auditable entity
    class BlogPost(IAuditable):
        def update_audit_fields(self, user_id: UUID) -> None:
            self.updated_at = datetime.now()
            self.updated_by = user_id
    
    # Rich content entity
    class Article(IContent):  # Combines audit, versioning, tagging, search, soft delete
        pass
    
    # User-generated content
    class Comment(IUserContent):  # Adds ownership and notifications to content
        pass
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import datetime
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

# Type aliases
EntityId = UUID


# =====================================================================================
# CORE DOMAIN INTERFACES
# =====================================================================================

@runtime_checkable
class IAuditable(Protocol):
    """Interface for entities with audit trail functionality.
    
    Provides creation and modification tracking with user attribution.
    Essential for compliance, debugging, and business intelligence.
    
    Attributes:
        created_at: When the entity was first created
        created_by: User who created the entity
        updated_at: When the entity was last modified
        updated_by: User who last modified the entity
    """
    
    created_at: datetime
    created_by: UUID | None
    updated_at: datetime
    updated_by: UUID | None
    
    @abstractmethod
    def update_audit_fields(self, user_id: UUID) -> None:
        """Update audit fields for modification tracking.
        
        Args:
            user_id: ID of the user making the change
            
        Business Rules:
            - Must update updated_at to current timestamp
            - Must set updated_by to provided user_id
            - Should preserve created_at and created_by
        """
        ...


@runtime_checkable
class ISoftDeletable(Protocol):
    """Interface for entities supporting logical deletion.
    
    Enables marking entities as deleted without physical removal,
    supporting data recovery, audit trails, and referential integrity.
    
    Attributes:
        deleted_at: When the entity was deleted (None if active)
        deleted_by: User who deleted the entity (None if active)
        is_deleted: Computed property for deletion status
    """
    
    deleted_at: datetime | None
    deleted_by: UUID | None
    
    @property
    @abstractmethod
    def is_deleted(self) -> bool:
        """Check if entity is logically deleted."""
        ...
    
    @abstractmethod
    def soft_delete(self, user_id: UUID) -> None:
        """Mark entity as deleted without physical removal.
        
        Args:
            user_id: ID of the user performing deletion
            
        Business Rules:
            - Must set deleted_at to current timestamp
            - Must set deleted_by to provided user_id
            - Should not affect already deleted entities
        """
        ...
    
    @abstractmethod
    def restore(self, user_id: UUID) -> None:
        """Restore a soft-deleted entity.
        
        Args:
            user_id: ID of the user performing restoration
            
        Business Rules:
            - Must clear deleted_at and deleted_by
            - Should update audit fields if implementing IAuditable
            - Should only work on deleted entities
        """
        ...


@runtime_checkable
class IVersionable(Protocol):
    """Interface for entities with optimistic locking support.
    
    Prevents lost updates in concurrent environments by tracking
    entity versions and detecting concurrent modifications.
    
    Attributes:
        version: Current version number (incremented on each update)
    """
    
    version: int
    
    @abstractmethod
    def increment_version(self) -> None:
        """Increment the version number for optimistic locking.
        
        Business Rules:
            - Must increment version by 1
            - Should be called on every modification
            - Used to detect concurrent modifications
        """
        ...
    
    @abstractmethod
    def check_version(self, expected_version: int) -> bool:
        """Check if current version matches expected version.
        
        Args:
            expected_version: Version expected by the caller
            
        Returns:
            True if versions match, False if there's a conflict
            
        Business Rules:
            - Used to detect concurrent modifications
            - Should return False if versions don't match
            - Enables optimistic locking strategies
        """
        ...


@runtime_checkable
class ITaggable(Protocol):
    """Interface for entities that can be tagged for categorization.
    
    Supports flexible categorization, filtering, and organization
    through a tag-based system with bulk operations.
    
    Attributes:
        tags: Set of string tags associated with the entity
    """
    
    tags: set[str]
    
    @abstractmethod
    def add_tag(self, tag: str) -> None:
        """Add a single tag to the entity.
        
        Args:
            tag: Tag to add (case-insensitive, trimmed)
            
        Business Rules:
            - Tags should be normalized (lowercase, trimmed)
            - Duplicate tags should be ignored
            - Empty or whitespace-only tags should be rejected
        """
        ...
    
    @abstractmethod
    def remove_tag(self, tag: str) -> None:
        """Remove a single tag from the entity.
        
        Args:
            tag: Tag to remove (case-insensitive)
            
        Business Rules:
            - Should handle non-existent tags gracefully
            - Tag matching should be case-insensitive
        """
        ...
    
    @abstractmethod
    def add_tags(self, tags: set[str]) -> None:
        """Add multiple tags in a single operation.
        
        Args:
            tags: Set of tags to add
            
        Business Rules:
            - Should apply same normalization as add_tag
            - Should be atomic (all or nothing)
            - Should handle empty sets gracefully
        """
        ...
    
    @abstractmethod
    def remove_tags(self, tags: set[str]) -> None:
        """Remove multiple tags in a single operation.
        
        Args:
            tags: Set of tags to remove
            
        Business Rules:
            - Should handle non-existent tags gracefully
            - Should be atomic (all or nothing)
            - Should handle empty sets gracefully
        """
        ...
    
    @abstractmethod
    def has_tag(self, tag: str) -> bool:
        """Check if entity has a specific tag.
        
        Args:
            tag: Tag to check for (case-insensitive)
            
        Returns:
            True if entity has the tag, False otherwise
        """
        ...
    
    @abstractmethod
    def has_any_tags(self, tags: set[str]) -> bool:
        """Check if entity has any of the specified tags.
        
        Args:
            tags: Set of tags to check for
            
        Returns:
            True if entity has at least one of the tags
        """
        ...
    
    @abstractmethod
    def has_all_tags(self, tags: set[str]) -> bool:
        """Check if entity has all of the specified tags.
        
        Args:
            tags: Set of tags to check for
            
        Returns:
            True if entity has all of the tags
        """
        ...


@runtime_checkable
class ISearchable(Protocol):
    """Interface for entities supporting full-text search functionality.
    
    Enables search indexing and retrieval with metadata extraction
    and relevance scoring for business intelligence and user experience.
    
    Methods support both automated indexing and manual search optimization.
    """
    
    @abstractmethod
    def get_search_content(self) -> str:
        """Extract searchable text content from the entity.
        
        Returns:
            Combined text content suitable for full-text search
            
        Business Rules:
            - Should include all relevant searchable fields
            - Should return clean, indexable text
            - Should handle None/empty values gracefully
        """
        ...
    
    @abstractmethod
    def get_search_metadata(self) -> dict[str, Any]:
        """Extract metadata for search indexing and filtering.
        
        Returns:
            Dictionary of metadata for search and faceting
            
        Business Rules:
            - Should include filterable attributes
            - Should use consistent key naming
            - Should handle nested objects appropriately
        """
        ...
    
    @abstractmethod
    def get_search_keywords(self) -> set[str]:
        """Extract keywords for enhanced search matching.
        
        Returns:
            Set of keywords for improved search relevance
            
        Business Rules:
            - Should include domain-specific terms
            - Should normalize keywords (lowercase, trimmed)
            - Should handle abbreviations and synonyms
        """
        ...


@runtime_checkable
class IActivatable(Protocol):
    """Interface for entities with activation/deactivation lifecycle.
    
    Supports controlled activation state with timestamps and user tracking
    for business processes requiring explicit activation.
    
    Attributes:
        is_active: Current activation state
        activated_at: When entity was activated (None if never activated)
        deactivated_at: When entity was deactivated (None if active)
    """
    
    is_active: bool
    activated_at: datetime | None
    deactivated_at: datetime | None
    
    @abstractmethod
    def activate(self, user_id: UUID) -> None:
        """Activate the entity.
        
        Args:
            user_id: ID of the user performing activation
            
        Business Rules:
            - Must set is_active to True
            - Must set activated_at to current timestamp
            - Must clear deactivated_at
            - Should update audit fields if implementing IAuditable
        """
        ...
    
    @abstractmethod
    def deactivate(self, user_id: UUID) -> None:
        """Deactivate the entity.
        
        Args:
            user_id: ID of the user performing deactivation
            
        Business Rules:
            - Must set is_active to False
            - Must set deactivated_at to current timestamp
            - Should update audit fields if implementing IAuditable
        """
        ...


@runtime_checkable
class ISlugifiable(Protocol):
    """Interface for entities that can generate URL-friendly slugs.
    
    Supports SEO-friendly URLs and human-readable identifiers
    with uniqueness checking and customization options.
    
    Attributes:
        slug: Current URL-friendly slug
    """
    
    slug: str | None
    
    @abstractmethod
    def generate_slug(self, base_text: str | None = None) -> str:
        """Generate a URL-friendly slug from entity data.
        
        Args:
            base_text: Optional base text for slug generation
                      If None, should use appropriate entity field(s)
            
        Returns:
            URL-friendly slug
            
        Business Rules:
            - Should be lowercase and URL-safe
            - Should replace spaces with hyphens
            - Should remove special characters
            - Should handle Unicode characters appropriately
        """
        ...
    
    @abstractmethod
    def update_slug(self, new_slug: str) -> None:
        """Update the entity's slug.
        
        Args:
            new_slug: New slug value
            
        Business Rules:
            - Should validate slug format
            - Should check uniqueness if required
            - Should update audit fields if implementing IAuditable
        """
        ...


@runtime_checkable
class ICacheable(Protocol):
    """Interface for entities supporting caching optimization.
    
    Provides cache key generation, TTL management, and invalidation
    signals for performance optimization and data consistency.
    """
    
    @abstractmethod
    def get_cache_key(self) -> str:
        """Generate cache key for this entity.
        
        Returns:
            Unique cache key for this entity
            
        Business Rules:
            - Should be unique across all entities
            - Should include entity type and ID
            - Should be stable unless entity changes significantly
        """
        ...
    
    @abstractmethod
    def get_cache_ttl(self) -> int:
        """Get cache time-to-live in seconds.
        
        Returns:
            TTL in seconds, or 0 for no expiration
            
        Business Rules:
            - Should reflect how often entity changes
            - Should consider business requirements
            - Should balance performance vs freshness
        """
        ...
    
    @abstractmethod
    def should_invalidate_cache(self, field_name: str) -> bool:
        """Check if cache should be invalidated for field change.
        
        Args:
            field_name: Name of the field that changed
            
        Returns:
            True if cache should be invalidated
            
        Business Rules:
            - Should return True for significant changes
            - Should return False for audit-only changes
            - Should consider downstream dependencies
        """
        ...


@runtime_checkable
class IExportable(Protocol):
    """Interface for entities supporting data export functionality.
    
    Enables export to multiple formats for reporting, integration,
    and data migration with customizable field selection.
    """
    
    @abstractmethod
    def to_dict(self, include_private: bool = False) -> dict[str, Any]:
        """Export entity to dictionary format.
        
        Args:
            include_private: Whether to include private/internal fields
            
        Returns:
            Dictionary representation of the entity
            
        Business Rules:
            - Should handle nested objects appropriately
            - Should respect privacy settings
            - Should use consistent key naming
        """
        ...
    
    @abstractmethod
    def to_csv_row(self, fields: list[str] | None = None) -> list[str]:
        """Export entity as CSV row data.
        
        Args:
            fields: Optional list of fields to include
                   If None, should include all exportable fields
            
        Returns:
            List of string values for CSV export
            
        Business Rules:
            - Should maintain consistent field order
            - Should handle None values appropriately
            - Should escape CSV special characters
        """
        ...
    
    @abstractmethod
    def get_export_headers(self, fields: list[str] | None = None) -> list[str]:
        """Get export headers for CSV/table formats.
        
        Args:
            fields: Optional list of fields to include
            
        Returns:
            List of human-readable headers
            
        Business Rules:
            - Should match order of to_csv_row output
            - Should use human-readable names
            - Should be consistent across entities
        """
        ...


@runtime_checkable
class INotifiable(Protocol):
    """Interface for entities that can receive notifications.
    
    Supports notification preferences, delivery methods, and
    subscription management for business communication.
    
    Attributes:
        notification_preferences: User preferences for notifications
    """
    
    notification_preferences: dict[str, Any]
    
    @abstractmethod
    def can_receive_notification(self, notification_type: str) -> bool:
        """Check if entity can receive a specific notification type.
        
        Args:
            notification_type: Type of notification to check
            
        Returns:
            True if notification can be received
            
        Business Rules:
            - Should check user preferences
            - Should respect opt-out settings
            - Should handle unknown notification types gracefully
        """
        ...
    
    @abstractmethod
    def get_notification_address(self, method: str) -> str | None:
        """Get notification address for delivery method.
        
        Args:
            method: Delivery method (email, sms, push, etc.)
            
        Returns:
            Address for notification delivery, or None if not available
            
        Business Rules:
            - Should validate address format
            - Should respect privacy settings
            - Should handle multiple addresses appropriately
        """
        ...
    
    @abstractmethod
    def update_notification_preferences(self, preferences: dict[str, Any]) -> None:
        """Update notification preferences.
        
        Args:
            preferences: New preference settings
            
        Business Rules:
            - Should validate preference keys and values
            - Should merge with existing preferences
            - Should update audit fields if implementing IAuditable
        """
        ...


@runtime_checkable
class IOwnable(Protocol):
    """Interface for entities with ownership tracking.
    
    Supports ownership assignment, transfer, and access control
    for multi-tenant and collaborative applications.
    
    Attributes:
        owner_id: ID of the entity owner
        owner_type: Type of owner (user, organization, etc.)
    """
    
    owner_id: UUID
    owner_type: str
    
    @abstractmethod
    def transfer_ownership(self, new_owner_id: UUID, new_owner_type: str, transferred_by: UUID) -> None:
        """Transfer ownership to a new owner.
        
        Args:
            new_owner_id: ID of the new owner
            new_owner_type: Type of the new owner
            transferred_by: ID of the user performing the transfer
            
        Business Rules:
            - Should validate new owner exists
            - Should check transfer permissions
            - Should update audit fields if implementing IAuditable
            - Should trigger ownership change events
        """
        ...
    
    @abstractmethod
    def is_owned_by(self, user_id: UUID, user_type: str = "user") -> bool:
        """Check if entity is owned by specific user.
        
        Args:
            user_id: ID of the user to check
            user_type: Type of the user (default: "user")
            
        Returns:
            True if entity is owned by the user
            
        Business Rules:
            - Should handle exact ownership matches
            - Should consider organization ownership if applicable
            - Should respect inheritance rules
        """
        ...


@runtime_checkable
class ISecurable(Protocol):
    """Interface for entities with permission-based access control.
    
    Supports role-based and permission-based security with
    fine-grained access control for enterprise applications.
    
    Attributes:
        permissions: Dictionary of permissions for this entity
    """
    
    permissions: dict[str, set[str]]
    
    @abstractmethod
    def grant_permission(self, user_id: UUID, permission: str) -> None:
        """Grant a permission to a user.
        
        Args:
            user_id: ID of the user receiving permission
            permission: Permission to grant
            
        Business Rules:
            - Should validate permission exists
            - Should check granting user has authority
            - Should update audit fields if implementing IAuditable
        """
        ...
    
    @abstractmethod
    def revoke_permission(self, user_id: UUID, permission: str) -> None:
        """Revoke a permission from a user.
        
        Args:
            user_id: ID of the user losing permission
            permission: Permission to revoke
            
        Business Rules:
            - Should handle non-existent permissions gracefully
            - Should check revoking user has authority
            - Should update audit fields if implementing IAuditable
        """
        ...
    
    @abstractmethod
    def has_permission(self, user_id: UUID, permission: str) -> bool:
        """Check if user has a specific permission.
        
        Args:
            user_id: ID of the user to check
            permission: Permission to check for
            
        Returns:
            True if user has the permission
            
        Business Rules:
            - Should check direct permissions
            - Should consider inherited permissions
            - Should respect role-based permissions
        """
        ...
    
    @abstractmethod
    def get_user_permissions(self, user_id: UUID) -> set[str]:
        """Get all permissions for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            Set of all permissions for the user
            
        Business Rules:
            - Should include direct permissions
            - Should include inherited permissions
            - Should include role-based permissions
        """
        ...


@runtime_checkable
class IValidatable(Protocol):
    """Interface for entities with self-validation capabilities.
    
    Supports comprehensive validation with field-level checking,
    business rule enforcement, and detailed error reporting.
    """
    
    @abstractmethod
    def validate(self) -> dict[str, list[str]]:
        """Validate the entity and return validation errors.
        
        Returns:
            Dictionary mapping field names to lists of error messages
            Empty dictionary if no validation errors
            
        Business Rules:
            - Should validate all business rules
            - Should check field constraints
            - Should validate relationships
            - Should return user-friendly error messages
        """
        ...
    
    @abstractmethod
    def is_valid(self) -> bool:
        """Check if entity is currently valid.
        
        Returns:
            True if entity passes all validation rules
            
        Business Rules:
            - Should return True only if validate() returns empty dict
            - Should be efficient for frequent checking
            - Should include all validation rules
        """
        ...
    
    @abstractmethod
    def validate_field(self, field_name: str, value: Any) -> list[str]:
        """Validate a specific field value.
        
        Args:
            field_name: Name of the field to validate
            value: Value to validate
            
        Returns:
            List of validation error messages (empty if valid)
            
        Business Rules:
            - Should validate field-specific rules
            - Should check data type constraints
            - Should validate business rules for the field
        """
        ...


@runtime_checkable
class IComparable(Protocol):
    """Interface for entities supporting comparison and sorting.
    
    Enables ordering, ranking, and comparison operations
    for business logic and user interface requirements.
    """
    
    @abstractmethod
    def compare_to(self, other: Any) -> int:
        """Compare this entity to another entity.
        
        Args:
            other: Entity to compare against
            
        Returns:
            Negative if this < other, 0 if equal, positive if this > other
            
        Business Rules:
            - Should implement consistent comparison logic
            - Should handle type mismatches gracefully
            - Should respect business ordering rules
        """
        ...
    
    @abstractmethod
    def equals(self, other: Any) -> bool:
        """Check if this entity equals another entity.
        
        Args:
            other: Entity to compare against
            
        Returns:
            True if entities are considered equal
            
        Business Rules:
            - Should use business equality rules
            - Should handle None values appropriately
            - Should be consistent with compare_to
        """
        ...
    
    @abstractmethod
    def get_sort_key(self) -> Any:
        """Get sort key for ordering operations.
        
        Returns:
            Sortable key for this entity
            
        Business Rules:
            - Should return sortable type (str, int, datetime, etc.)
            - Should be consistent across entity instances
            - Should reflect business ordering requirements
        """
        ...


# =====================================================================================
# COMPOSITE INTERFACES
# =====================================================================================

@runtime_checkable
class IEntity(IAuditable, IVersionable, Protocol):
    """Base interface for domain entities.
    
    Combines audit trail and versioning for standard entity behavior.
    Provides foundation for all persistent domain entities.
    
    This interface represents the minimum requirements for entities
    in a DDD system with proper audit trails and optimistic locking.
    """
    
    id: EntityId
    
    @abstractmethod
    def get_entity_id(self) -> EntityId:
        """Get the unique identifier for this entity.
        
        Returns:
            Unique entity identifier
            
        Business Rules:
            - Should return immutable identifier
            - Should be unique within entity type
            - Should remain stable throughout entity lifetime
        """
        ...


@runtime_checkable  
class IContent(IEntity, ITaggable, ISearchable, ISoftDeletable, Protocol):
    """Interface for content entities.
    
    Combines entity behavior with content-specific capabilities:
    tagging, search, and soft deletion for content management systems.
    
    Ideal for articles, posts, documents, and other content types.
    """
    
    title: str
    content: str
    
    @abstractmethod
    def get_content_summary(self, max_length: int = 150) -> str:
        """Get a summary of the content.
        
        Args:
            max_length: Maximum length of summary
            
        Returns:
            Truncated content summary
            
        Business Rules:
            - Should truncate at word boundaries
            - Should add ellipsis if truncated
            - Should handle empty content gracefully
        """
        ...


@runtime_checkable
class IUserContent(IContent, IOwnable, INotifiable, Protocol):
    """Interface for user-generated content.
    
    Extends content interface with ownership and notification capabilities
    for social features, collaboration, and user engagement.
    
    Perfect for comments, reviews, posts, and collaborative content.
    """
    
    @abstractmethod
    def notify_owner(self, event_type: str, data: dict[str, Any]) -> None:
        """Notify the content owner of an event.
        
        Args:
            event_type: Type of event (comment, like, share, etc.)
            data: Event-specific data
            
        Business Rules:
            - Should check notification preferences
            - Should respect privacy settings
            - Should handle notification delivery failures gracefully
        """
        ...
    
    @abstractmethod
    def can_be_modified_by(self, user_id: UUID) -> bool:
        """Check if user can modify this content.
        
        Args:
            user_id: ID of the user to check
            
        Returns:
            True if user can modify the content
            
        Business Rules:
            - Should check ownership
            - Should check permissions
            - Should consider administrative rights
        """
        ...