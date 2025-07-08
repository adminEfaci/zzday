# Identity GraphQL Query Resolvers

This package provides comprehensive, production-ready GraphQL query resolvers for the identity module with advanced features including security, performance optimization, and comprehensive error handling.

## Features

### Security & Authorization
- **Field-level authorization**: Each field can have specific permission requirements
- **Role-based access control**: Integration with role and permission system
- **Self-access patterns**: Users can access their own data with reduced permissions
- **Admin overrides**: Admin users can bypass certain restrictions
- **Secure defaults**: Fields return empty/null for unauthorized access instead of errors

### Performance Optimization
- **DataLoader implementation**: Prevents N+1 queries through intelligent batching
- **Caching strategies**: Multiple levels of caching for frequently accessed data
- **Query complexity analysis**: Built-in monitoring and performance tracking
- **Pagination support**: Cursor-based and offset-based pagination
- **Field selection optimization**: Only resolve requested fields

### Error Handling
- **Comprehensive error types**: Structured error responses with codes and extensions
- **Graceful degradation**: Partial results when some fields fail
- **Performance monitoring**: Execution time tracking and logging
- **Audit logging**: All query executions are logged for security analysis

## Architecture

### Core Components

```
queries/
├── __init__.py                     # Package exports
├── base_query_resolver.py          # Base resolver with common functionality
├── dataloaders.py                  # DataLoader implementations for N+1 prevention
├── field_resolvers.py              # Field-level resolvers with authorization
├── query_resolver_factory.py       # Factory and main resolver class
├── user_queries.py                 # User-related query resolvers
├── role_queries.py                 # Role-related query resolvers
├── permission_queries.py           # Permission-related query resolvers
├── session_queries.py              # Session-related query resolvers
├── security_queries.py             # Security event and audit log resolvers
└── administrative_queries.py       # System administration resolvers
```

### Key Classes

- **`BaseQueryResolver`**: Common functionality for all resolvers
- **`IdentityDataLoaders`**: DataLoader implementations for efficient data loading
- **`QueryResolverFactory`**: Creates and configures all resolver instances
- **`IdentityQueryResolvers`**: Main resolver class that consolidates all operations
- **`FieldResolverRegistry`**: Field-level resolvers with authorization

## Usage

### Basic Setup

```python
from app.modules.identity.presentation.graphql.resolvers.queries import (
    QueryResolverFactory,
    IdentityQueryResolvers
)

# Create factory with repositories
factory = QueryResolverFactory(
    user_repository=user_repo,
    role_repository=role_repo,
    permission_repository=permission_repo,
    session_repository=session_repo,
    security_event_repository=security_event_repo,
    user_profile_repository=user_profile_repo,
    user_preference_repository=user_preference_repo,
    # ... other repositories
)

# Get main resolver
resolvers = IdentityQueryResolvers(factory)
```

### Query Examples

#### User Queries

```graphql
# Get current user
query Me {
    me {
        id
        email
        username
        profile {
            displayName
            avatar
        }
        roles {
            name
            permissions {
                name
                resource
                action
            }
        }
    }
}

# List users with filtering and pagination
query Users($filter: UserFilterInput, $pagination: PaginationInput) {
    users(filter: $filter, pagination: $pagination) {
        edges {
            node {
                id
                email
                username
                isActive
                lastLogin
            }
            cursor
        }
        pageInfo {
            hasNextPage
            hasPreviousPage
            totalCount
        }
    }
}

# User statistics (admin only)
query UserStatistics {
    userStatistics {
        totalUsers
        activeUsers
        verifiedUsers
        usersWithMfa
        newUsersToday
        loginCountToday
        averageSessionDuration
    }
}
```

#### Role & Permission Queries

```graphql
# Check user permission
query PermissionCheck($userId: ID!, $resource: String!, $action: String!) {
    permissionCheck(userId: $userId, resource: $resource, action: $action) {
        granted
        reason
        checkedAt
    }
}

# List roles with permissions
query Roles {
    roles {
        edges {
            node {
                id
                name
                description
                permissions {
                    name
                    resource
                    action
                }
            }
        }
    }
}
```

#### Session Queries

```graphql
# Get active sessions for a user
query ActiveSessions($userId: ID) {
    activeSessions(userId: $userId) {
        edges {
            node {
                id
                deviceType
                ipAddress
                location
                lastActivity
                user {
                    email
                }
            }
        }
    }
}

# Get suspicious sessions (security team)
query SuspiciousSessions($threshold: Float) {
    suspiciousSessions(severityThreshold: $threshold) {
        edges {
            node {
                id
                riskScore
                riskFactors
                user {
                    email
                }
                securityEvents {
                    type
                    severity
                    description
                }
            }
        }
    }
}
```

#### Security Queries

```graphql
# Security events
query SecurityEvents($filter: SecurityEventFilterInput) {
    securityEvents(filter: $filter) {
        edges {
            node {
                id
                eventType
                severity
                riskScore
                description
                user {
                    email
                }
            }
        }
    }
}

# Security statistics
query SecurityStatistics($days: Int) {
    securityStatistics(days: $days) {
        totalSecurityEvents
        highSeverityEvents
        successfulLoginsToday
        failedLoginsToday
        topThreatTypes {
            type
            count
            percentage
        }
        geographicDistribution {
            country
            count
            percentage
        }
    }
}
```

#### Administrative Queries

```graphql
# System health (admin only)
query SystemHealth {
    systemHealth {
        status
        uptimeSeconds
        memoryUsageMb
        cpuUsagePercent
        databaseStatus
        cacheStatus
        errorRatePercent
        responseTimeMs
    }
}

# Configuration settings (admin only)
query ConfigurationSettings($category: String, $includeSensitive: Boolean) {
    configurationSettings(category: $category, includeSensitive: $includeSensitive) {
        key
        value
        category
        description
        isSensitive
        lastModified
    }
}
```

## Authorization Patterns

### Permission Requirements

Each resolver method documents its required permissions:

```python
async def user_sessions(self, info: Info, user_id: UUID) -> List[dict]:
    """
    Get user sessions.
    
    Requires either:
    - User accessing their own sessions
    - 'user:sessions:read' permission
    """
```

### Self-Access Patterns

Many resolvers allow users to access their own data without special permissions:

```python
# Check authorization
self.require_self_or_permission(context, user_id, "user:sessions:read")
```

### Field-Level Security

Fields can be individually protected:

```python
async def resolve_profile(self, user: dict, info: Info) -> dict | None:
    context = await self.base_resolver.extract_context(info)
    
    if context.user_id != user["id"]:
        if "user:profile:read" not in context.permissions:
            return None  # Hide field for unauthorized users
```

## Performance Considerations

### DataLoader Usage

All resolvers use DataLoaders to prevent N+1 queries:

```python
# Efficient batch loading
users = await self.dataloaders.user_loader.load_many(user_ids)
roles = await self.dataloaders.user_roles_loader.load(user_id)
```

### Query Monitoring

All queries are monitored for performance:

```python
execution_time = (time.time() - start_time) * 1000
await self.log_query_execution(context, "users", parameters, execution_time)
```

### Caching Strategies

- **DataLoader caching**: Automatic request-level caching
- **Field-level caching**: Computed fields are cached
- **Performance tracking**: Execution times are tracked per field

## Error Handling

### Error Types

```python
# Structured error responses
class GraphQLError(Exception):
    def __init__(self, message: str, code: str, extensions: dict = None)

class UnauthorizedError(GraphQLError):
    # Specific error for authorization failures

class ValidationError(GraphQLError):
    # Input validation errors

class NotFoundError(GraphQLError):
    # Resource not found errors
```

### Error Responses

```json
{
  "errors": [
    {
      "message": "Permission 'user:read' required",
      "extensions": {
        "code": "UNAUTHORIZED",
        "requiredPermission": "user:read"
      }
    }
  ]
}
```

## Security Best Practices

1. **Principle of Least Privilege**: Each operation requires specific permissions
2. **Defense in Depth**: Multiple layers of authorization checks
3. **Audit Logging**: All operations are logged with context
4. **Secure Defaults**: Unauthorized access returns empty/null, not errors
5. **Input Validation**: All inputs are validated before processing
6. **Rate Limiting**: Built-in support for query complexity analysis

## Performance Best Practices

1. **Use DataLoaders**: Always use provided DataLoaders for related data
2. **Pagination**: Use pagination for large result sets
3. **Field Selection**: Only resolve requested GraphQL fields
4. **Monitoring**: Track query performance and optimize slow queries
5. **Caching**: Leverage multiple caching layers appropriately

## Testing

### Unit Testing

```python
# Test resolver authorization
async def test_user_query_authorization():
    context = QueryContext(user_id=user_id, permissions=["user:read"])
    resolver = UserQueries(repositories...)
    
    result = await resolver.user(mock_info, target_user_id)
    assert result is not None
```

### Integration Testing

```python
# Test with real GraphQL queries
async def test_user_query_graphql():
    query = '''
        query GetUser($id: ID!) {
            user(id: $id) {
                email
                roles { name }
            }
        }
    '''
    result = await execute_query(query, variables={"id": user_id})
    assert not result.errors
```

## Monitoring & Observability

### Metrics

- Query execution times
- Error rates by query type
- Permission denial rates
- DataLoader cache hit rates
- Field resolution performance

### Logging

All queries include structured logging:

```json
{
  "level": "INFO",
  "message": "GraphQL Query: users",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "session_id": "session_123",
  "execution_time_ms": 45.2,
  "result_count": 25,
  "timestamp": "2023-12-07T10:30:00Z"
}
```

## Migration & Deployment

### Database Requirements

Ensure repository implementations support:
- Batch loading methods (`find_by_ids`, `find_by_user_ids`)
- Filtering with complex parameters
- Pagination with offset and cursor support
- Count operations for pagination metadata

### Configuration

Required environment variables:
- Logging levels for query performance
- Rate limiting configuration
- Cache TTL settings
- Permission definitions

This comprehensive query resolver system provides a secure, performant, and maintainable foundation for GraphQL operations in the identity module.