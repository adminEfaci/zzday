# GraphQL Test Suite

This directory contains comprehensive test coverage for the GraphQL API layer of the application.

## Structure

```
graphql/
├── conftest.py                    # Base fixtures and utilities
├── queries/                       # Query tests
│   ├── test_user_queries.py      # User-related queries
│   └── test_audit_queries.py     # Audit log queries
├── mutations/                     # Mutation tests
│   ├── test_user_registration.py # User registration
│   ├── test_user_login.py        # User login
│   ├── test_authentication_flow.py # Auth flows (refresh, logout, etc.)
│   └── test_mfa_mutations.py     # Multi-factor authentication
├── subscriptions/                 # Subscription tests
│   └── test_real_time_subscriptions.py # Real-time updates
└── test_integration.py           # Cross-module integration tests
```

## Key Features

### Base Test Fixtures (conftest.py)

- **GraphQL Test Client**: Pre-configured async HTTP client for GraphQL endpoints
- **Authentication Helpers**: Fixtures for authenticated requests
- **Mock Data Factories**: Factories for generating test data
- **Response Assertions**: Helpers for validating GraphQL responses
- **Common Fragments**: Reusable GraphQL fragments
- **Mock Services**: Pre-configured mocks for testing

### Test Coverage

#### Identity Module
- User registration with validation
- Login with various scenarios (MFA, device tracking)
- Authentication flows (refresh tokens, logout)
- User queries and profile management
- Role and permission management
- Multi-factor authentication (MFA)

#### Audit Module
- Audit log creation and retrieval
- Filtering and searching audit logs
- Statistics and analytics
- Export functionality
- Real-time audit event subscriptions

#### Integration Tests
- Cross-module event propagation
- Cascade effects (e.g., user deletion)
- Notification triggers
- Concurrent operation handling
- Global search across modules

## Running Tests

### Run all GraphQL tests:
```bash
pytest app/tests/graphql/ -v
```

### Run specific test modules:
```bash
# Mutations only
pytest app/tests/graphql/mutations/ -v

# Queries only
pytest app/tests/graphql/queries/ -v

# Integration tests
pytest app/tests/graphql/test_integration.py -v
```

### Run with coverage:
```bash
pytest app/tests/graphql/ --cov=app.modules --cov-report=html
```

## Test Patterns

### 1. Making GraphQL Requests
```python
# Use the factory fixtures
request = make_graphql_request(
    query=login_mutation,
    variables={"input": {"username": "test", "password": "pass"}}
)
response = await graphql_client.post("", json=request)
```

### 2. Asserting Responses
```python
# Success assertions
assert_graphql_success(result, "login")

# Error assertions
assert_graphql_error(result, "Invalid credentials", "UNAUTHENTICATED")
```

### 3. Using Factories
```python
# Create test data
user_data = user_factory(username="testuser", email="test@example.com")
role_data = role_factory(name="admin")
```

### 4. Testing Subscriptions
```python
async with authenticated_graphql_client.websocket_connect("/graphql") as ws:
    await ws.send_json({
        "id": "1",
        "type": "subscribe",
        "payload": {"query": subscription}
    })
    message = await ws.receive_json()
```

## Best Practices

1. **Use Fixtures**: Leverage the provided fixtures for consistency
2. **Test Edge Cases**: Include tests for error conditions and edge cases
3. **Mock External Services**: Use mock services to isolate GraphQL layer
4. **Test Authorization**: Verify both authenticated and unauthenticated access
5. **Validate Response Structure**: Check both data content and structure
6. **Test Pagination**: Include tests for paginated responses
7. **Test Filters**: Verify filtering and search functionality

## Adding New Tests

1. Create test files following the naming convention: `test_*.py`
2. Use appropriate fixtures from `conftest.py`
3. Group related tests in classes
4. Include both positive and negative test cases
5. Document complex test scenarios
6. Ensure tests are independent and can run in any order

## Common Issues

### Authentication in Tests
- Use `authenticated_graphql_client` for authenticated requests
- Use regular `graphql_client` for unauthenticated tests

### Async Testing
- Always use `@pytest.mark.asyncio` decorator
- Use `await` for all async operations
- Handle timeouts appropriately

### WebSocket Testing
- Use context managers for WebSocket connections
- Handle connection lifecycle properly
- Set appropriate timeouts for subscriptions