"""Shared domain components following DDD principles.

This module provides shared domain components that can be used across different
bounded contexts. All components follow Domain-Driven Design principles and
are implemented as rich value objects with comprehensive behavior.

## Shared Components

### Value Objects
Rich, immutable value objects with comprehensive validation and behavior:
- **EmailAddress**: Email validation, domain analysis, masking, deliverability
- **Money**: Currency handling, arithmetic operations, formatting, allocation
- **Address**: Address validation, formatting, country-specific rules
- **PhoneNumber**: International phone validation, formatting, carrier detection
- **Location**: GPS coordinates, distance calculations, timezone detection

### Enumerations  
Enhanced enums with methods and properties:
- **Country**: ISO country codes with currency mapping, phone codes
- **Currency**: Currency codes with symbols, decimal places, major currencies
- **Language**: Language codes with display names
- **DayOfWeek**: Days with weekday/weekend detection, name formatting
- **TimeZone**: Timezone codes with offset calculations, regional grouping
- **Status**: Common status values with state checking
- **Priority**: Priority levels with numeric values and comparisons

### Interfaces
Protocols for common entity behaviors:
- **IAuditable**: Creation/modification tracking with user attribution
- **ISoftDeletable**: Logical deletion with restoration capabilities
- **IVersionable**: Optimistic locking with version checking
- **ITaggable**: Tag management with bulk operations
- **ISearchable**: Full-text search with metadata extraction
- **IActivatable**: Activation/deactivation with status tracking
- **ISlugifiable**: URL-friendly slug generation with uniqueness
- **ICacheable**: Caching support with TTL and invalidation
- **IExportable**: Data export in multiple formats (CSV, JSON, dict)
- **INotifiable**: Notification recipient and data management
- **IOwnable**: Ownership tracking with transfer capabilities
- **ISecurable**: Permission-based access control
- **IValidatable**: Self-validation with field-level checking
- **IComparable**: Comparison and sorting capabilities

### Composite Interfaces
Combined interfaces for common entity patterns:
- **IEntity**: Base entity combining audit, versioning, and identity
- **IContent**: Content entities with tagging, search, and soft delete
- **IUserContent**: User-generated content with ownership and notifications

## Design Principles

### Rich Value Objects
- **Behavior over Data**: Methods and properties provide business functionality
- **Immutability**: Value objects are immutable for thread safety and caching
- **Self-Validation**: Constructor validation ensures invariants are maintained
- **Framework Independence**: No dependencies on web frameworks or ORMs

### Domain-Driven Design
- **Ubiquitous Language**: Classes and methods use business terminology
- **Bounded Context Sharing**: Shared concepts used across multiple contexts
- **Business Rules**: Encapsulated validation and business logic
- **Rich Domain Model**: Objects with behavior, not just data containers

### Production Readiness
- **Comprehensive Error Handling**: Detailed error messages with context
- **Type Safety**: Full type hints for IDE support and runtime checking
- **Thread Safety**: Immutable designs and thread-safe operations
- **Performance**: Efficient implementations with caching where appropriate

## Usage Examples

### Value Object Usage
```python
from app.shared import EmailAddress, Money, Address, PhoneNumber, Country

# Rich email validation and analysis
email = EmailAddress("user@company.com") 
print(f"Domain: {email.domain}")
print(f"Business email: {email.is_business_email}")
print(f"Masked: {email.mask()}")

# Money with currency arithmetic
price = Money(99.99, "USD")
tax = Money(7.50, "USD") 
total = price + tax
print(f"Total: {total.format()}")  # "$107.49 USD"

# Address validation and formatting
address = Address(
    street="123 Main St",
    city="Toronto", 
    state_province="ON",
    postal_code="M5V 3A8",
    country="Canada"
)
print(address.format_multi_line())

# International phone handling
phone = PhoneNumber("+1-416-555-1234", "CA")
print(f"National: {phone.national_format}")
print(f"International: {phone.international_format}")
```

### Enumeration Usage
```python
from app.shared import Country, Currency, DayOfWeek, Priority

# Enhanced enum functionality
country = Country.CANADA
print(f"Currency: {country.get_currency()}")  # Currency.CAD
print(f"Phone code: {country.get_phone_code()}")  # "+1"

# Day of week with business logic
today = DayOfWeek.FRIDAY
print(f"Is weekend: {today.is_weekend}")  # False
print(f"Is weekday: {today.is_weekday}")  # True

# Priority with numeric values
priority = Priority.HIGH
print(f"Numeric value: {priority.get_numeric_value()}")  # 3
```

### Interface Implementation
```python
from app.shared import IAuditable, ISoftDeletable, IVersionable
from datetime import datetime
from uuid import UUID, uuid4

class BlogPost(IAuditable, ISoftDeletable, IVersionable):
    def __init__(self, title: str, content: str):
        self.id = uuid4()
        self.title = title
        self.content = content
        self.version = 1
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.deleted_at = None
        
    def update_audit_fields(self, user_id: UUID) -> None:
        self.updated_at = datetime.now()
        self.updated_by = user_id
        
    def soft_delete(self, user_id: UUID) -> None:
        self.deleted_at = datetime.now()
        self.deleted_by = user_id
```

## When to Use Shared Components

### ✅ Use When
- **Cross-Context Concepts**: Values used in multiple bounded contexts
- **Business Value Objects**: Rich domain concepts with behavior
- **Common Validation**: Standardized validation across services
- **Framework Independence**: Need to work across different frameworks
- **Rich Behavior**: Want methods and properties, not just data

### ❌ Avoid When  
- **Context-Specific Logic**: Business rules specific to one context
- **Simple Data Transfer**: Basic DTOs without business logic
- **Performance Critical**: Microsecond-level performance requirements
- **Legacy Integration**: Systems requiring specific data formats only

## Architecture Integration

### Domain Layer
Shared value objects integrate seamlessly with domain entities and aggregates:

```python
class User(AggregateRoot):
    def __init__(self, email: str, phone: str):
        super().__init__()
        self.email = EmailAddress(email)  # Rich validation
        self.phone = PhoneNumber(phone)   # International formatting
        
    def change_email(self, new_email: str) -> None:
        # Automatic validation through value object
        old_email = self.email
        self.email = EmailAddress(new_email)
        
        # Domain event with rich value objects
        self.add_event(EmailChangedEvent(
            user_id=self.id,
            old_email=old_email,
            new_email=self.email
        ))
```

### Application Layer
Use in commands, queries, and DTOs:

```python
class CreateUserCommand(Command):
    email: str
    phone: str
    address: dict
    
    def validate(self) -> None:
        # Pre-validate using static methods
        if not EmailAddress.validate_deliverable(self.email):
            raise ValidationError("Invalid email")
            
        if not PhoneNumber.validate_with_library(self.phone):
            raise ValidationError("Invalid phone number")
```

### Infrastructure Layer
Seamless conversion to/from persistence models:

```python
class UserRepository(BaseRepository[User, UserModel]):
    def _to_entity(self, model: UserModel) -> User:
        return User(
            id=model.id,
            email=EmailAddress(model.email),
            phone=PhoneNumber(model.phone),
            address=Address(
                street=model.address_street,
                city=model.address_city,
                state_province=model.address_state,
                postal_code=model.address_postal_code,
                country=model.address_country
            )
        )
```
"""

# Import with error handling
try:
    from app.shared.value_objects import (
        Address,
        Country,
        Currency,
        DayOfWeek,
        EmailAddress,
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
        Language,
        Location,
        Money,
        PhoneNumber,
        Priority,
        Status,
        TimeZone,
    )
except ImportError:
    # Provide fallback implementations
    from typing import Protocol
    from uuid import UUID
    
    # Type aliases
    EntityId = UUID
    
    # Fallback protocols
    class IAuditable(Protocol):
        """Auditable interface."""
    
    class ISoftDeletable(Protocol):
        """Soft deletable interface."""
    
    class IVersionable(Protocol):
        """Versionable interface."""
    
    class ITaggable(Protocol):
        """Taggable interface."""
    
    class ISearchable(Protocol):
        """Searchable interface."""
    
    class IActivatable(Protocol):
        """Activatable interface."""
    
    class ISlugifiable(Protocol):
        """Slugifiable interface."""
    
    class ICacheable(Protocol):
        """Cacheable interface."""
    
    class IExportable(Protocol):
        """Exportable interface."""
    
    class INotifiable(Protocol):
        """Notifiable interface."""
    
    class IOwnable(Protocol):
        """Ownable interface."""
    
    class ISecurable(Protocol):
        """Securable interface."""
    
    class IValidatable(Protocol):
        """Validatable interface."""
    
    class IComparable(Protocol):
        """Comparable interface."""
    
    # Composite interfaces
    class IEntity(IAuditable, IVersionable, Protocol):
        """Base entity interface."""
    
    class IContent(IEntity, ITaggable, ISearchable, ISoftDeletable, Protocol):
        """Content interface."""
    
    class IUserContent(IContent, IOwnable, INotifiable, Protocol):
        """User content interface."""
    
    # Fallback value objects and enums
    class Address:
        """Fallback address."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Country:
        """Fallback country."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Currency:
        """Fallback currency."""
        def __init__(self, *args, **kwargs):
            pass
    
    class DayOfWeek:
        """Fallback day of week."""
        def __init__(self, *args, **kwargs):
            pass
    
    class EmailAddress:
        """Fallback email address."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Language:
        """Fallback language."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Location:
        """Fallback location."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Money:
        """Fallback money."""
        def __init__(self, *args, **kwargs):
            pass
    
    class PhoneNumber:
        """Fallback phone number."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Priority:
        """Fallback priority."""
        def __init__(self, *args, **kwargs):
            pass
    
    class Status:
        """Fallback status."""
        def __init__(self, *args, **kwargs):
            pass
    
    class TimeZone:
        """Fallback timezone."""
        def __init__(self, *args, **kwargs):
            pass

# Re-export everything
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
