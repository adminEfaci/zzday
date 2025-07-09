# 🔗 Cross-Module Presentation Patterns

**Document Version**: 1.0  
**Author**: Agent-4  
**Date**: 2025-07-09  
**Purpose**: Document consistent patterns across all presentation layers

## Overview

This document captures the presentation layer patterns observed across all modules, providing a blueprint for consistent GraphQL API development using Strawberry framework with DDD/Hexagonal Architecture.

## Architectural Patterns

### 1. Module Schema Structure

Each module follows a consistent directory structure:

```
module/
└── presentation/
    └── graphql/
        ├── schema.py           # Main schema aggregation
        ├── resolvers/
        │   ├── queries/       # Query resolvers
        │   ├── mutations/     # Mutation resolvers
        │   └── subscriptions/ # Subscription resolvers
        └── schema/            # Type definitions
```

### 2. Schema Aggregation Pattern

**Standard Pattern** (Audit/Integration):
```python
@strawberry.type
class ModuleQueries:
    """Combined module queries."""
    entity: EntityQueries = strawberry.field(
        resolver=lambda: EntityQueries(),
        description="Entity-specific queries"
    )

@strawberry.type
class ModuleMutations:
    """Combined module mutations."""
    entity: EntityMutations = strawberry.field(
        resolver=lambda: EntityMutations(),
        description="Entity-specific mutations"
    )
```

**Inheritance Pattern** (Integration):
```python
@strawberry.type
class IntegrationQuery(
    IntegrationQueries,
    HealthQueries,
    MappingQueries,
    WebhookQueries
):
    """Combined using multiple inheritance."""
    pass
```

### 3. Resolver Organization

#### Query Resolvers
- One file per domain concept
- Static methods for simple queries
- Instance methods for complex queries
- DataLoader integration for N+1 prevention

```python
@strawberry.type
class UserQueries:
    @strawberry.field
    async def user(self, id: strawberry.ID, info: Info) -> UserType:
        """Single entity query."""
        service = info.context["container"].get(UserService)
        return await service.get_by_id(id)
    
    @strawberry.field
    async def users(
        self,
        filter: UserFilter | None = None,
        pagination: PaginationInput | None = None,
        info: Info
    ) -> UserConnection:
        """Collection query with filtering and pagination."""
        service = info.context["container"].get(UserService)
        return await service.list(filter, pagination)
```

#### Mutation Resolvers
- Grouped by aggregate root
- Command pattern integration
- Explicit error handling
- Transaction boundaries

```python
@strawberry.type
class UserMutations:
    @strawberry.mutation
    @require_authentication
    async def create_user(
        self,
        input: CreateUserInput,
        info: Info
    ) -> Union[UserType, ErrorType]:
        """Create user with validation."""
        try:
            command = CreateUserCommand(**input.__dict__)
            handler = info.context["container"].get(CreateUserHandler)
            user = await handler.handle(command)
            return UserType.from_domain(user)
        except DomainError as e:
            return ErrorType(message=str(e), code=e.code)
```

#### Subscription Resolvers
- Event-driven architecture
- Authentication required
- Connection management
- Rate limiting built-in

```python
@strawberry.type
class UserSubscriptions(BaseSubscriptionResolver):
    @strawberry.subscription
    @require_authentication
    async def user_status_changed(
        self,
        user_id: strawberry.ID,
        info: Info
    ) -> AsyncGenerator[UserStatusEvent, None]:
        """Subscribe to user status changes."""
        async for event in self._listen_to_events("user.status", user_id):
            yield UserStatusEvent.from_domain(event)
```

## Common Design Patterns

### 1. Type Conversion Pattern

**Domain to GraphQL**:
```python
@strawberry.type
class UserType:
    id: strawberry.ID
    email: str
    name: str
    
    @classmethod
    def from_domain(cls, user: User) -> "UserType":
        return cls(
            id=strawberry.ID(str(user.id.value)),
            email=user.email.value,
            name=user.name
        )
```

### 2. Error Handling Pattern

**Union Types for Mutations**:
```python
@strawberry.type
class SuccessType:
    message: str
    data: UserType

@strawberry.type
class ErrorType:
    message: str
    code: str
    field: str | None = None

UserMutationResult = Union[SuccessType, ErrorType]
```

### 3. Pagination Pattern

**Connection/Edge Pattern**:
```python
@strawberry.type
class PageInfo:
    has_next_page: bool
    has_previous_page: bool
    start_cursor: str | None
    end_cursor: str | None

@strawberry.type
class UserEdge:
    cursor: str
    node: UserType

@strawberry.type
class UserConnection:
    edges: list[UserEdge]
    page_info: PageInfo
    total_count: int
```

### 4. Filter Pattern

**Input Types for Filtering**:
```python
@strawberry.input
class UserFilter:
    email_contains: str | None = None
    name_contains: str | None = None
    status_in: list[UserStatus] | None = None
    created_after: datetime | None = None
    
    def to_specification(self) -> Specification:
        """Convert to domain specification."""
        specs = []
        if self.email_contains:
            specs.append(EmailContainsSpec(self.email_contains))
        # ... more specs
        return CompositeSpec.all_of(specs)
```

### 5. Authentication/Authorization Pattern

**Decorators for Access Control**:
```python
def require_authentication(func):
    """Require authenticated user."""
    @functools.wraps(func)
    async def wrapper(self, info: Info, *args, **kwargs):
        if not info.context.get("user"):
            raise AuthenticationError("Authentication required")
        return await func(self, info, *args, **kwargs)
    return wrapper

def require_permission(permission: str):
    """Require specific permission."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, info: Info, *args, **kwargs):
            user = info.context.get("user")
            if not user or not user.has_permission(permission):
                raise AuthorizationError(f"Permission '{permission}' required")
            return await func(self, info, *args, **kwargs)
        return wrapper
    return decorator
```

## Module-Specific Patterns

### Identity Module Patterns
- Complex subscription system with base classes
- Rate limiting configuration per subscription
- MFA decorators for sensitive operations
- Session-based authentication context

### Audit Module Patterns
- Analytics queries with aggregation
- Report generation with async processing
- Compliance-focused types
- Time-range based filtering

### Notification Module Patterns
- Multi-channel delivery types
- Template management
- Delivery status tracking
- Real-time delivery subscriptions

### Integration Module Patterns
- Webhook signature validation
- External system health monitoring
- Transformation specifications
- Sync status tracking

## Anti-Patterns to Avoid

### 1. ❌ Business Logic in Resolvers
```python
# BAD
@strawberry.mutation
async def create_user(self, input: CreateUserInput) -> UserType:
    # Direct validation and business logic
    if len(input.password) < 8:
        raise ValueError("Password too short")
    # ... more business logic
```

### 2. ❌ Direct Database Access
```python
# BAD
@strawberry.field
async def user(self, id: strawberry.ID) -> UserType:
    # Direct database query
    result = await db.query("SELECT * FROM users WHERE id = ?", id)
    return UserType(**result)
```

### 3. ❌ Synchronous Blocking Operations
```python
# BAD
@strawberry.field
def expensive_calculation(self) -> int:
    # Blocking operation
    time.sleep(5)
    return calculate_something()
```

### 4. ❌ Exposing Domain Models Directly
```python
# BAD
@strawberry.type
class User(DomainUser):  # Inheriting from domain model
    pass
```

## Best Practices Checklist

### Schema Design
- [ ] Use clear, consistent naming
- [ ] Provide descriptions for all fields
- [ ] Use enums for fixed value sets
- [ ] Implement proper pagination
- [ ] Use union types for error handling

### Resolver Implementation
- [ ] Keep resolvers thin
- [ ] Delegate to application services
- [ ] Use DataLoader for batch loading
- [ ] Implement proper error handling
- [ ] Add authentication where needed

### Type Safety
- [ ] Use proper GraphQL scalar types
- [ ] Avoid nullable fields unless necessary
- [ ] Use input types for mutations
- [ ] Implement custom scalars carefully
- [ ] Validate at the edge

### Performance
- [ ] Implement query complexity analysis
- [ ] Use DataLoader to prevent N+1
- [ ] Add caching where appropriate
- [ ] Limit query depth
- [ ] Monitor resolver performance

### Security
- [ ] Disable introspection in production
- [ ] Implement rate limiting
- [ ] Use query whitelisting
- [ ] Validate all inputs
- [ ] Log security events

## Testing Patterns

### Unit Tests
```python
@pytest.mark.asyncio
async def test_user_query():
    schema = strawberry.Schema(query=UserQueries)
    result = await schema.execute(
        '{ user(id: "123") { id email name } }',
        context_value={"container": mock_container}
    )
    assert not result.errors
    assert result.data["user"]["id"] == "123"
```

### Integration Tests
```python
@pytest.mark.asyncio
async def test_create_user_flow():
    async with TestClient(app) as client:
        response = await client.post(
            "/graphql",
            json={
                "query": CREATE_USER_MUTATION,
                "variables": {"input": {...}}
            }
        )
        assert response.status_code == 200
        assert response.json()["data"]["createUser"]["__typename"] == "SuccessType"
```

## Migration Guidelines

### From REST to GraphQL
1. Map REST endpoints to GraphQL operations
2. Convert request/response to types
3. Implement resolvers calling existing services
4. Add GraphQL-specific features (subscriptions, etc.)
5. Deprecate REST endpoints gradually

### From Graphene to Strawberry
1. Convert type definitions
2. Update decorator syntax
3. Migrate resolvers
4. Update context handling
5. Test thoroughly

## Monitoring and Observability

### Key Metrics
- Query execution time
- Resolver performance
- Error rates by operation
- Subscription connection count
- Query complexity scores

### Logging Standards
```python
logger.info(
    "GraphQL operation executed",
    operation_name=info.operation_name,
    operation_type=info.operation.operation,
    user_id=info.context.get("user", {}).get("id"),
    duration_ms=duration,
    complexity=complexity_score
)
```

## Future Considerations

### GraphQL Federation
- Consider splitting into federated services
- Implement @key directives
- Plan entity resolution
- Design shared types carefully

### Schema Evolution
- Use @deprecated directive
- Version through field additions
- Maintain backward compatibility
- Document breaking changes

### Performance Optimization
- Implement persisted queries
- Add response caching
- Use query batching
- Consider GraphQL subscriptions over SSE

---

**Document Status**: Living document  
**Next Update**: As patterns evolve  
**Maintained By**: Agent-4