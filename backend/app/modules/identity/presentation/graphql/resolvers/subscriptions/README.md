# GraphQL Subscription Resolvers for Identity Module

This module provides comprehensive real-time subscription capabilities for identity-related events with production-ready features including WebSocket connection management, authorization, rate limiting, and monitoring.

## Architecture

### Core Components

1. **BaseSubscriptionResolver** - Base class providing:
   - WebSocket connection management
   - Authentication and authorization
   - Rate limiting and throttling
   - Event filtering and delivery
   - Connection cleanup and monitoring

2. **SubscriptionManager** - Centralized management for:
   - Connection pooling and load balancing
   - Event publishing and distribution
   - Health monitoring and metrics
   - Resource cleanup

3. **Subscription Resolvers**:
   - `UserStatusSubscriptions` - User status, login/logout, profile updates
   - `SecurityEventSubscriptions` - Security events, threats, MFA changes
   - `SessionManagementSubscriptions` - Session lifecycle and activity
   - `AdministrativeSubscriptions` - User management, bulk operations
   - `AuditComplianceSubscriptions` - Audit logs, GDPR, data retention

## Features

### Real-time Event Subscriptions

1. **User Status Events**:
   - `userStatusChanged` - User status changes
   - `userLoggedIn/Out` - Authentication events
   - `userProfileUpdated` - Profile modifications
   - `userPreferencesChanged` - Preference updates
   - `userRoleAssigned` - Role assignments
   - `userPermissionChanged` - Permission changes
   - `userSessionCreated/Expired` - Session events

2. **Security Events**:
   - `securityEventCreated` - New security events
   - `suspiciousActivityDetected` - Threat alerts
   - `loginAttemptFailed` - Failed authentications
   - `accountLocked` - Account security locks
   - `passwordChanged` - Password modifications
   - `mfaDeviceAdded/Removed` - MFA device management
   - `securityEventResolved` - Event resolutions

3. **Session Management**:
   - `sessionCreated/Expired/Revoked` - Session lifecycle
   - `sessionActivity` - Real-time session activity
   - `concurrentSessionsDetected` - Multiple session alerts
   - `sessionSecurityAlert` - Session security events

4. **Administrative Events**:
   - `userCreated/Deleted/Suspended/Reactivated` - User lifecycle
   - `bulkOperationProgress` - Bulk operation status
   - `systemMaintenanceStatus` - System maintenance updates
   - `configurationChanged` - Configuration modifications

5. **Audit & Compliance**:
   - `auditLogCreated` - New audit entries
   - `complianceViolation` - Compliance issues
   - `gdprRequestCreated` - GDPR request events
   - `dataExportReady` - Data export completions
   - `dataRetentionEvent` - Data retention actions

### Authorization & Security

- **Multi-level Authorization**: Users can access their own events, admins can access all
- **Permission-based Access**: Fine-grained permissions for different event types
- **MFA Requirements**: High-security subscriptions require MFA verification
- **Risk-based Security**: Risk scoring and automatic security measures

### Performance & Scalability

- **Rate Limiting**: Configurable rate limits with burst protection
- **Event Batching**: Efficient event batching for high-throughput scenarios
- **Connection Pooling**: Managed connection pools with automatic cleanup
- **Redis Integration**: Scalable event distribution across multiple nodes

### Monitoring & Observability

- **Comprehensive Metrics**: Connection counts, event rates, error tracking
- **Health Checks**: Built-in health monitoring and diagnostics
- **Structured Logging**: Detailed logging with correlation IDs
- **Real-time Statistics**: Live monitoring of subscription performance

## Usage Examples

### Basic User Status Subscription

```graphql
subscription {
  userStatusChanged(userId: "123") {
    userId
    oldStatus
    newStatus
    timestamp
    reason
  }
}
```

### Security Event Monitoring

```graphql
subscription {
  securityEventCreated(severity: "high") {
    eventId
    eventType
    severity
    userId
    ipAddress
    details
    riskScore
    timestamp
  }
}
```

### Session Activity Monitoring

```graphql
subscription {
  sessionActivity(userId: "123") {
    sessionId
    userId
    activityType
    ipAddress
    riskScore
    anomalyDetected
    timestamp
  }
}
```

### Administrative Operations

```graphql
subscription {
  bulkOperationProgress(operationId: "bulk-123") {
    operationId
    operationType
    totalRecords
    processedRecords
    progressPercentage
    currentPhase
    timestamp
  }
}
```

## Configuration

### Rate Limiting

```python
RateLimitConfig(
    max_events=100,      # Maximum events per window
    window_seconds=60,   # Time window in seconds
    burst_limit=20,      # Burst limit for short periods
    burst_window_seconds=5
)
```

### Connection Management

```python
SubscriptionManager(
    connection_pool_size=100,  # Maximum concurrent connections
    cleanup_interval=300       # Cleanup interval in seconds
)
```

## Security Considerations

1. **Authentication Required**: All subscriptions require valid authentication
2. **Permission Checks**: Events are filtered based on user permissions
3. **Data Privacy**: Users can only access their own data unless authorized
4. **MFA Protection**: Sensitive subscriptions require MFA verification
5. **Rate Limiting**: Protection against abuse and resource exhaustion
6. **Connection Limits**: Prevents resource exhaustion attacks

## Production Deployment

### Redis Configuration

- Configure Redis for high availability and persistence
- Use Redis Cluster for horizontal scaling
- Set appropriate memory limits and eviction policies

### Monitoring

- Monitor connection counts and event rates
- Set up alerts for high error rates or resource usage
- Track subscription performance metrics

### Scaling

- Deploy multiple application instances behind a load balancer
- Use Redis for distributed event coordination
- Implement horizontal scaling for high-volume scenarios

## Error Handling

The system provides comprehensive error handling:

- **Connection Errors**: Automatic reconnection and cleanup
- **Rate Limiting**: Graceful degradation with user notifications
- **Authorization Failures**: Clear error messages and proper status codes
- **Network Issues**: Robust handling of network interruptions
- **Resource Exhaustion**: Connection limits and automatic cleanup

## Development & Testing

### Local Development

1. Start Redis server: `redis-server`
2. Configure application to use local Redis
3. Run subscription resolvers with development settings

### Testing

- Unit tests for individual subscription resolvers
- Integration tests for end-to-end subscription flows
- Load testing for performance validation
- Security testing for authorization and rate limiting

This implementation provides a robust, scalable, and secure foundation for real-time identity events in production environments.