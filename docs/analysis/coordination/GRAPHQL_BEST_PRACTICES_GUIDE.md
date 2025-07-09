# 📘 GraphQL Best Practices Guide

**Version**: 1.0  
**Framework**: Strawberry GraphQL  
**Architecture**: DDD + Hexagonal  
**Author**: Agent-4  
**Last Updated**: 2025-07-09

## Table of Contents

1. [Schema Design](#schema-design)
2. [Type System](#type-system)
3. [Resolver Patterns](#resolver-patterns)
4. [Error Handling](#error-handling)
5. [Performance Optimization](#performance-optimization)
6. [Security Best Practices](#security-best-practices)
7. [Testing Strategies](#testing-strategies)
8. [Documentation Standards](#documentation-standards)
9. [Monitoring & Observability](#monitoring--observability)
10. [Common Pitfalls](#common-pitfalls)

## Schema Design

### 1. Naming Conventions

**✅ DO:**
```graphql
type User {
  id: ID!
  email: String!
  firstName: String!
  createdAt: DateTime!
  isActive: Boolean!
}

type Query {
  user(id: ID!): User
  users(filter: UserFilter): UserConnection!
}

type Mutation {
  createUser(input: CreateUserInput!): CreateUserPayload!
  updateUser(id: ID!, input: UpdateUserInput!): UpdateUserPayload!
}
```

**❌ DON'T:**
```graphql
type user_type {
  ID: String
  Email_Address: String
  first_name: String
  created: String
  active: String
}
```

### 2. Schema Organization

**Module-Based Structure:**
```python
# identity/presentation/graphql/schema.py
@strawberry.type
class IdentityQueries:
    user: UserQueries = strawberry.field(resolver=lambda: UserQueries())
    role: RoleQueries = strawberry.field(resolver=lambda: RoleQueries())
    session: SessionQueries = strawberry.field(resolver=lambda: SessionQueries())

@strawberry.type
class IdentityMutations:
    auth: AuthMutations = strawberry.field(resolver=lambda: AuthMutations())
    user: UserMutations = strawberry.field(resolver=lambda: UserMutations())
    admin: AdminMutations = strawberry.field(resolver=lambda: AdminMutations())
```

### 3. Field Descriptions

**Always Include Descriptions:**
```python
@strawberry.type
class User:
    id: strawberry.ID = strawberry.field(
        description="Unique identifier for the user"
    )
    email: str = strawberry.field(
        description="User's email address (unique)"
    )
    roles: list[Role] = strawberry.field(
        description="Roles assigned to the user for access control"
    )
```

## Type System

### 1. Use Strong Types

**✅ GOOD:**
```python
@strawberry.type
class Email:
    value: str
    verified: bool
    verifiedAt: datetime | None

@strawberry.type
class User:
    id: strawberry.ID
    email: Email  # Strong typing
    profile: UserProfile
```

**❌ BAD:**
```python
@strawberry.type
class User:
    id: str  # Should be ID
    email: str  # Lost email metadata
    profile: dict  # No type safety
```

### 2. Input Types for Mutations

**Always Use Input Types:**
```python
@strawberry.input
class CreateUserInput:
    email: str
    password: str
    firstName: str
    lastName: str
    roles: list[strawberry.ID] | None = None

@strawberry.input
class UpdateUserInput:
    email: str | None = None
    firstName: str | None = None
    lastName: str | None = None
    roles: list[strawberry.ID] | None = None
```

### 3. Enums for Fixed Values

```python
@strawberry.enum
class UserStatus(Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    DELETED = "DELETED"

@strawberry.enum
class SortDirection(Enum):
    ASC = "ASC"
    DESC = "DESC"
```

### 4. Interfaces for Shared Behavior

```python
@strawberry.interface
class Node:
    id: strawberry.ID

@strawberry.interface
class Timestamped:
    createdAt: datetime
    updatedAt: datetime

@strawberry.type
class User(Node, Timestamped):
    email: str
    name: str
```

## Resolver Patterns

### 1. Keep Resolvers Thin

**✅ GOOD:**
```python
@strawberry.type
class UserQueries:
    @strawberry.field
    async def user(self, id: strawberry.ID, info: Info) -> User | None:
        """Thin resolver delegating to service layer."""
        service = info.context["container"].get(UserService)
        domain_user = await service.get_by_id(UUID(id))
        return User.from_domain(domain_user) if domain_user else None
```

**❌ BAD:**
```python
@strawberry.field
async def user(self, id: strawberry.ID, info: Info) -> User | None:
    """Fat resolver with business logic."""
    # Business logic in resolver
    if not id:
        raise ValueError("ID required")
    
    # Direct database access
    db = info.context["db"]
    result = await db.query(f"SELECT * FROM users WHERE id = {id}")
    
    # Data transformation
    if result:
        return User(
            id=result["id"],
            email=result["email"],
            # ... more mapping
        )
```

### 2. Use DataLoader for N+1 Prevention

```python
from strawberry.dataloader import DataLoader

class UserLoader(DataLoader):
    async def batch_load_fn(self, user_ids: list[str]) -> list[User | None]:
        # Batch load users
        users = await user_repository.get_by_ids(user_ids)
        # Return in same order as requested
        user_map = {str(user.id): user for user in users}
        return [user_map.get(uid) for uid in user_ids]

# In resolver
@strawberry.field
async def user(self, id: strawberry.ID, info: Info) -> User | None:
    loader = info.context["loaders"]["user"]
    return await loader.load(id)
```

### 3. Context Pattern for Dependencies

```python
async def get_context(request, response):
    return {
        "request": request,
        "user": request.state.user if hasattr(request.state, "user") else None,
        "container": request.app.state.container,
        "loaders": {
            "user": UserLoader(),
            "role": RoleLoader(),
        }
    }
```

## Error Handling

### 1. Use Union Types for Mutations

```python
@strawberry.type
class UserSuccess:
    user: User
    message: str = "User created successfully"

@strawberry.type
class ValidationError:
    field: str
    message: str

@strawberry.type
class UserError:
    message: str
    code: str
    validationErrors: list[ValidationError] | None = None

CreateUserResult = strawberry.union("CreateUserResult", [UserSuccess, UserError])

@strawberry.mutation
async def create_user(self, input: CreateUserInput, info: Info) -> CreateUserResult:
    try:
        # ... create user
        return UserSuccess(user=created_user)
    except ValidationException as e:
        return UserError(
            message="Validation failed",
            code="VALIDATION_ERROR",
            validationErrors=[ValidationError(field=f, message=m) for f, m in e.errors.items()]
        )
```

### 2. Consistent Error Codes

```python
@strawberry.enum
class ErrorCode(Enum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
```

### 3. Field-Level Errors

```python
@strawberry.type
class FieldError:
    field: str
    message: str
    code: ErrorCode

@strawberry.type
class MutationResponse:
    success: bool
    errors: list[FieldError] | None = None
```

## Performance Optimization

### 1. Query Complexity Analysis

```python
from strawberry.extensions import QueryDepthLimiter

schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[
        QueryDepthLimiter(max_depth=10),
    ]
)
```

### 2. Implement Pagination

```python
@strawberry.type
class PageInfo:
    hasNextPage: bool
    hasPreviousPage: bool
    startCursor: str | None = None
    endCursor: str | None = None

@strawberry.type
class UserEdge:
    cursor: str
    node: User

@strawberry.type
class UserConnection:
    edges: list[UserEdge]
    pageInfo: PageInfo
    totalCount: int

@strawberry.field
async def users(
    self,
    first: int | None = None,
    after: str | None = None,
    last: int | None = None,
    before: str | None = None,
    filter: UserFilter | None = None,
    info: Info
) -> UserConnection:
    # Implement cursor-based pagination
    pass
```

### 3. Caching Strategies

```python
from functools import lru_cache
from strawberry.extensions import Extension

class CacheExtension(Extension):
    def resolve(self, _next, root, info, **kwargs):
        # Check cache before resolution
        cache_key = self._generate_cache_key(info)
        cached = cache.get(cache_key)
        if cached:
            return cached
            
        result = _next(root, info, **kwargs)
        
        # Cache successful results
        if not isinstance(result, Exception):
            cache.set(cache_key, result, ttl=300)
            
        return result
```

### 4. Batch Operations

```python
@strawberry.mutation
async def bulk_create_users(
    self,
    inputs: list[CreateUserInput],
    info: Info
) -> list[CreateUserResult]:
    # Process in batches for efficiency
    batch_size = 100
    results = []
    
    for i in range(0, len(inputs), batch_size):
        batch = inputs[i:i + batch_size]
        batch_results = await process_batch(batch)
        results.extend(batch_results)
    
    return results
```

## Security Best Practices

### 1. Authentication & Authorization

```python
def require_auth(func):
    @functools.wraps(func)
    async def wrapper(*args, info: Info, **kwargs):
        if not info.context.get("user"):
            raise AuthenticationError("Authentication required")
        return await func(*args, info=info, **kwargs)
    return wrapper

def require_permission(permission: str):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, info: Info, **kwargs):
            user = info.context.get("user")
            if not user or not await user.has_permission(permission):
                raise PermissionError(f"Permission '{permission}' required")
            return await func(*args, info=info, **kwargs)
        return wrapper
    return decorator
```

### 2. Input Validation

```python
@strawberry.input
class CreateUserInput:
    email: str
    password: str
    
    def validate(self) -> list[ValidationError]:
        errors = []
        
        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", self.email):
            errors.append(ValidationError(
                field="email",
                message="Invalid email format"
            ))
            
        if len(self.password) < 8:
            errors.append(ValidationError(
                field="password",
                message="Password must be at least 8 characters"
            ))
            
        return errors
```

### 3. Rate Limiting

```python
from strawberry.extensions import Extension

class RateLimitExtension(Extension):
    def resolve(self, _next, root, info, **kwargs):
        user = info.context.get("user")
        if user:
            key = f"rate_limit:{user.id}:{info.field_name}"
            count = cache.incr(key)
            if count == 1:
                cache.expire(key, 60)  # 1 minute window
            if count > 100:  # 100 requests per minute
                raise RateLimitError("Rate limit exceeded")
        return _next(root, info, **kwargs)
```

### 4. Query Whitelisting

```python
ALLOWED_QUERIES = {
    "GetUser": "query GetUser($id: ID!) { user(id: $id) { ... } }",
    "ListUsers": "query ListUsers { users { ... } }",
}

def validate_query(query: str) -> bool:
    # In production, only allow whitelisted queries
    return query in ALLOWED_QUERIES.values()
```

## Testing Strategies

### 1. Schema Testing

```python
import pytest
from strawberry import Schema

@pytest.fixture
def schema():
    return Schema(query=Query, mutation=Mutation)

def test_schema_builds():
    """Test that schema builds without errors."""
    schema = Schema(query=Query, mutation=Mutation)
    assert schema is not None

def test_introspection(schema):
    """Test schema introspection."""
    result = schema.execute_sync("{ __schema { types { name } } }")
    assert not result.errors
    type_names = [t["name"] for t in result.data["__schema"]["types"]]
    assert "User" in type_names
```

### 2. Resolver Testing

```python
@pytest.mark.asyncio
async def test_user_query(schema, mock_user_service):
    query = """
        query GetUser($id: ID!) {
            user(id: $id) {
                id
                email
                name
            }
        }
    """
    
    mock_user_service.get_by_id.return_value = User(
        id="123",
        email="test@example.com",
        name="Test User"
    )
    
    result = await schema.execute(
        query,
        variable_values={"id": "123"},
        context_value={"container": {"UserService": mock_user_service}}
    )
    
    assert not result.errors
    assert result.data["user"]["email"] == "test@example.com"
```

### 3. Integration Testing

```python
@pytest.mark.asyncio
async def test_create_user_flow(client):
    mutation = """
        mutation CreateUser($input: CreateUserInput!) {
            createUser(input: $input) {
                ... on UserSuccess {
                    user {
                        id
                        email
                    }
                }
                ... on UserError {
                    message
                    code
                }
            }
        }
    """
    
    response = await client.post(
        "/graphql",
        json={
            "query": mutation,
            "variables": {
                "input": {
                    "email": "new@example.com",
                    "password": "securepassword",
                    "firstName": "New",
                    "lastName": "User"
                }
            }
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["createUser"]["__typename"] == "UserSuccess"
```

## Documentation Standards

### 1. Schema Documentation

```python
@strawberry.type(description="Represents a system user with authentication capabilities")
class User:
    id: strawberry.ID = strawberry.field(
        description="Unique identifier for the user"
    )
    email: str = strawberry.field(
        description="User's email address (must be unique)"
    )
    roles: list[Role] = strawberry.field(
        description="Roles assigned to the user for access control"
    )
    
    @strawberry.field(description="Check if user has a specific permission")
    async def has_permission(self, permission: str) -> bool:
        # Implementation
        pass
```

### 2. Deprecation

```python
@strawberry.type
class User:
    id: strawberry.ID
    
    @strawberry.field(
        deprecation_reason="Use 'email' field instead. Will be removed in v2.0"
    )
    def email_address(self) -> str:
        return self.email
    
    email: str
```

### 3. Example Queries

```markdown
# User Queries

## Get User by ID
```graphql
query GetUser($id: ID!) {
  user(id: $id) {
    id
    email
    profile {
      firstName
      lastName
    }
    roles {
      name
      permissions
    }
  }
}
```

## List Users with Pagination
```graphql
query ListUsers($first: Int!, $after: String) {
  users(first: $first, after: $after) {
    edges {
      node {
        id
        email
        createdAt
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```
```

## Monitoring & Observability

### 1. Operation Logging

```python
class LoggingExtension(Extension):
    def resolve(self, _next, root, info, **kwargs):
        start_time = time.time()
        
        try:
            result = _next(root, info, **kwargs)
            duration = time.time() - start_time
            
            logger.info(
                "GraphQL operation completed",
                operation_name=info.operation.name,
                operation_type=info.operation.operation,
                field_name=info.field_name,
                duration_ms=duration * 1000,
                user_id=info.context.get("user", {}).get("id")
            )
            
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "GraphQL operation failed",
                operation_name=info.operation.name,
                field_name=info.field_name,
                duration_ms=duration * 1000,
                error=str(e),
                exc_info=True
            )
            raise
```

### 2. Metrics Collection

```python
from prometheus_client import Counter, Histogram

graphql_requests = Counter(
    "graphql_requests_total",
    "Total GraphQL requests",
    ["operation_type", "operation_name", "status"]
)

graphql_duration = Histogram(
    "graphql_request_duration_seconds",
    "GraphQL request duration",
    ["operation_type", "operation_name"]
)

class MetricsExtension(Extension):
    def resolve(self, _next, root, info, **kwargs):
        start_time = time.time()
        
        try:
            result = _next(root, info, **kwargs)
            status = "success"
        except Exception as e:
            status = "error"
            raise
        finally:
            duration = time.time() - start_time
            graphql_requests.labels(
                operation_type=info.operation.operation,
                operation_name=info.operation.name or "anonymous",
                status=status
            ).inc()
            graphql_duration.labels(
                operation_type=info.operation.operation,
                operation_name=info.operation.name or "anonymous"
            ).observe(duration)
```

## Common Pitfalls

### 1. ❌ Over-fetching in Resolvers

**Problem:**
```python
@strawberry.field
async def users(self) -> list[User]:
    # Fetches ALL users every time
    all_users = await user_repository.get_all()
    return [User.from_domain(u) for u in all_users]
```

**Solution:**
```python
@strawberry.field
async def users(
    self,
    first: int = 10,
    filter: UserFilter | None = None
) -> UserConnection:
    # Paginated and filtered
    return await user_service.get_paginated(first, filter)
```

### 2. ❌ Circular Type References

**Problem:**
```python
@strawberry.type
class User:
    posts: list["Post"]

@strawberry.type
class Post:
    author: User  # Circular reference
```

**Solution:**
```python
from __future__ import annotations

@strawberry.type
class User:
    id: strawberry.ID
    
    @strawberry.field
    async def posts(self, info: Info) -> list[Post]:
        # Lazy load posts
        loader = info.context["loaders"]["posts_by_user"]
        return await loader.load(self.id)

@strawberry.type
class Post:
    author_id: strawberry.ID
    
    @strawberry.field
    async def author(self, info: Info) -> User:
        # Lazy load author
        loader = info.context["loaders"]["user"]
        return await loader.load(self.author_id)
```

### 3. ❌ Nullable Fields Everywhere

**Problem:**
```python
@strawberry.type
class User:
    id: str | None
    email: str | None
    name: str | None
    # Everything is nullable!
```

**Solution:**
```python
@strawberry.type
class User:
    id: strawberry.ID  # Required
    email: str  # Required
    name: str  # Required
    bio: str | None = None  # Optional with reason
    avatar_url: str | None = None  # Optional with reason
```

### 4. ❌ Business Logic in Types

**Problem:**
```python
@strawberry.type
class User:
    email: str
    
    @strawberry.field
    def is_valid_email(self) -> bool:
        # Business logic in GraphQL type
        return "@" in self.email and len(self.email) > 5
```

**Solution:**
```python
@strawberry.type
class User:
    email: str
    email_verified: bool
    
    @classmethod
    def from_domain(cls, user: DomainUser) -> User:
        # Let domain handle validation
        return cls(
            email=user.email.value,
            email_verified=user.email.is_verified
        )
```

## Migration Guide

### From REST to GraphQL

1. **Map Endpoints to Operations**
   - GET /users → query users
   - GET /users/:id → query user(id)
   - POST /users → mutation createUser
   - PUT /users/:id → mutation updateUser
   - DELETE /users/:id → mutation deleteUser

2. **Convert Responses to Types**
   - JSON responses → GraphQL types
   - Error codes → Error union types
   - Links/HATEOAS → GraphQL relationships

3. **Implement Incrementally**
   - Start with read operations
   - Add mutations gradually
   - Implement subscriptions last
   - Run GraphQL alongside REST

### From Graphene to Strawberry

1. **Update Imports**
   ```python
   # From
   import graphene
   
   # To
   import strawberry
   ```

2. **Convert Types**
   ```python
   # From
   class UserType(graphene.ObjectType):
       id = graphene.ID()
       email = graphene.String()
   
   # To
   @strawberry.type
   class User:
       id: strawberry.ID
       email: str
   ```

3. **Update Resolvers**
   ```python
   # From
   def resolve_user(self, info, id):
       return get_user(id)
   
   # To
   @strawberry.field
   async def user(self, id: strawberry.ID, info: Info) -> User:
       return await get_user(id)
   ```

## Conclusion

Following these best practices will help you build a robust, performant, and maintainable GraphQL API. Remember:

- **Keep it simple**: Don't over-engineer
- **Think in graphs**: Model relationships naturally
- **Fail fast**: Validate early and clearly
- **Monitor everything**: You can't improve what you don't measure
- **Document thoroughly**: Your future self will thank you

For more information, consult:
- [Strawberry GraphQL Documentation](https://strawberry.rocks/)
- [GraphQL Best Practices](https://graphql.org/learn/best-practices/)
- [Production Ready GraphQL](https://productionreadygraphql.com/)

---

**Guide Maintained By**: Agent-4  
**Contributions Welcome**: Submit PRs for improvements  
**Last Review**: 2025-07-09