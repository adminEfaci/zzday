"""Shared value objects with comprehensive exports.

This module provides rich value objects following Domain-Driven Design principles.
All value objects are immutable, framework-agnostic, and provide comprehensive
validation and behavior.

Value Objects:
- EmailAddress: Rich email validation and analysis
- Money: Currency handling with arithmetic operations
- Address: Comprehensive address validation and formatting
- PhoneNumber: International phone number handling
- Location: GPS coordinates with distance calculations

Enumerations:
- Country: ISO country codes with enhanced functionality
- Currency: Currency codes with symbols and formatting
- Language: Supported language codes
- DayOfWeek: Days with weekday/weekend detection
- TimeZone: Timezone handling with offset calculations
- Status: Common status enumerations
- Priority: Priority levels with numeric values

Interfaces:
- IAuditable: Audit trail functionality
- ISoftDeletable: Soft deletion support
- IVersionable: Optimistic locking support
- ITaggable: Tagging functionality
- ISearchable: Full-text search support
- IActivatable: Activation/deactivation support
- ISlugifiable: URL slug generation
- ICacheable: Caching support
- IExportable: Data export functionality
- INotifiable: Notification support
- IOwnable: Ownership tracking
- ISecurable: Permission controls
- IValidatable: Self-validation
- IComparable: Comparison and sorting
- IEntity: Base entity interface
- IContent: Content entity interface
- IUserContent: User-generated content interface

Design Principles:
- Rich behavior with methods and properties
- Immutable by design (where appropriate)
- Framework-agnostic implementation
- Comprehensive validation with detailed error messages
- Self-contained business logic
"""

# Core value objects
from app.shared.value_objects.address import Address
from app.shared.value_objects.email import EmailAddress

# Enumerations
from app.shared.value_objects.enums import (
    Country,
    Currency,
    DayOfWeek,
    Language,
    Priority,
    Status,
    TimeZone,
)

# Interfaces and protocols
from app.shared.value_objects.interface import (  # Type aliases; Core interfaces; Composite interfaces
    EntityId,
    IActivatable,
    IAuditable,
    ICacheable,
    IComparable,
    IContent,
    IEntity,
    IExportable,
    INotifiable,
    IOwnable,
    ISearchable,
    ISecurable,
    ISlugifiable,
    ISoftDeletable,
    ITaggable,
    IUserContent,
    IValidatable,
    IVersionable,
)
from app.shared.value_objects.location import Location
from app.shared.value_objects.money import Money
from app.shared.value_objects.phone import PhoneNumber

__all__ = [
    # Core value objects
    "Address",
    # Enumerations
    "Country",
    "Currency",
    "DayOfWeek",
    "EmailAddress",
    # Type aliases
    "EntityId",
    "IActivatable",
    # Core interfaces
    "IAuditable",
    "ICacheable",
    "IComparable",
    "IContent",
    # Composite interfaces
    "IEntity",
    "IExportable",
    "INotifiable",
    "IOwnable",
    "ISearchable",
    "ISecurable",
    "ISlugifiable",
    "ISoftDeletable",
    "ITaggable",
    "IUserContent",
    "IValidatable",
    "IVersionable",
    "Language",
    "Location",
    "Money",
    "PhoneNumber",
    "Priority",
    "Status",
    "TimeZone",
]
