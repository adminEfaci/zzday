# Notification Module - Application Layer

This directory contains the complete Application Layer implementation for the Notification module, following Domain-Driven Design (DDD) and Command Query Responsibility Segregation (CQRS) patterns.

## Architecture Overview

The application layer orchestrates domain operations and serves as the integration point between the domain layer and external systems. It implements use cases through command and query handlers while maintaining clean separation of concerns.

## Directory Structure

```
application/
├── __init__.py                 # Main application module
├── README.md                   # This documentation
├── commands/
│   ├── __init__.py            # Command definitions
│   └── handlers.py            # Command handlers
├── queries/
│   ├── __init__.py            # Query definitions
│   └── handlers.py            # Query handlers
├── dto/
│   └── __init__.py            # Data Transfer Objects
├── services/
│   └── __init__.py            # Application services
└── event_handlers/
    └── __init__.py            # Cross-module event handlers
```

## Components

### 1. Commands and Command Handlers

Commands represent intents to modify system state:

- **SendNotificationCommand** → SendNotificationCommandHandler
- **CreateTemplateCommand** → CreateTemplateCommandHandler
- **ScheduleNotificationCommand** → ScheduleNotificationCommandHandler
- **ProcessBatchCommand** → ProcessBatchCommandHandler
- **UpdateRecipientPreferencesCommand** → UpdateRecipientPreferencesCommandHandler
- **CancelScheduledNotificationCommand** → CancelScheduledNotificationCommandHandler
- **RetryNotificationCommand** → RetryNotificationCommandHandler
- **UpdateTemplateCommand** → UpdateTemplateCommandHandler

### 2. Queries and Query Handlers

Queries represent requests for information:

- **GetNotificationQuery** → GetNotificationQueryHandler
- **GetTemplateQuery** → GetTemplateQueryHandler
- **GetRecipientPreferencesQuery** → GetRecipientPreferencesQueryHandler
- **GetNotificationHistoryQuery** → GetNotificationHistoryQueryHandler
- **GetDeliveryStatusQuery** → GetDeliveryStatusQueryHandler
- **GetBatchStatusQuery** → GetBatchStatusQueryHandler
- **ListTemplatesQuery** → ListTemplatesQueryHandler
- **ListScheduledNotificationsQuery** → ListScheduledNotificationsQueryHandler
- **GetChannelStatusQuery** → GetChannelStatusQueryHandler
- **GetNotificationMetricsQuery** → GetNotificationMetricsQueryHandler
- **SearchNotificationsQuery** → SearchNotificationsQueryHandler

### 3. Data Transfer Objects (DTOs)

DTOs facilitate data transfer between layers:

- **NotificationRequestDTO** - Request data for sending notifications
- **NotificationResponseDTO** - Response data for notification operations
- **TemplateDTO** - Template information transfer
- **RecipientPreferencesDTO** - Recipient preference data
- **DeliveryReportDTO** - Detailed delivery status information
- **BatchStatusDTO** - Batch processing status
- **NotificationHistoryDTO** - Historical notification data
- **ChannelStatusDTO** - Channel health and configuration
- **ScheduledNotificationDTO** - Scheduled notification information

### 4. Application Services

Services orchestrate complex business operations:

- **NotificationService** - Core notification operations and coordination
- **TemplateService** - Template management and validation
- **DeliveryService** - Multi-channel delivery coordination
- **SchedulingService** - Notification scheduling operations
- **PreferenceService** - Recipient preference management

### 5. Event Handlers

Event handlers enable cross-module integration:

- **UserRegisteredEventHandler** - Sends welcome notifications
- **UserDeactivatedEventHandler** - Sends account closure notifications
- **SecurityIncidentDetectedEventHandler** - Alerts security team
- **ComplianceViolationEventHandler** - Notifies compliance officer
- **DataSyncCompletedEventHandler** - Sends completion reports

## Key Features

### Multi-Channel Delivery
- Email, SMS, Push, and In-App notifications
- Channel-specific content optimization
- Provider abstraction and failover

### Template System
- Mustache-style variable substitution
- Channel-optimized content rendering
- Version control and A/B testing support

### Advanced Scheduling
- One-time and recurring notifications
- Cron-like scheduling patterns
- Timezone-aware delivery

### Batch Processing
- High-volume notification processing
- Progress tracking and error reporting
- Parallel execution with rate limiting

### Recipient Preferences
- Granular channel and type preferences
- Quiet hours and timezone support
- Global and targeted unsubscribe

### Delivery Tracking
- Real-time status updates
- Provider webhook integration
- Comprehensive delivery analytics

### Rate Limiting
- Per-channel and per-recipient limits
- Sliding window algorithms
- Automatic retry with backoff

### Error Handling
- Comprehensive error classification
- Automatic retry for transient failures
- Dead letter queue for failed messages

## Integration Points

### Event Subscriptions
The notification module subscribes to events from other modules:

- **Identity Module**: User registration, deactivation, role changes
- **Audit Module**: Security incidents, compliance violations
- **Integration Module**: Data sync completion, external system events

### External Dependencies
- Message providers (SendGrid, Twilio, Firebase, etc.)
- Rate limiting service
- Metrics and monitoring service
- Search service for notification history

## Usage Examples

### Sending a Notification
```python
command = SendNotificationCommand(
    recipient_id=user_id,
    channel=NotificationChannel.EMAIL,
    template_code="welcome_email",
    variables={
        "user_name": "John Doe",
        "activation_url": "https://app.com/activate/token"
    },
    priority=NotificationPriority.HIGH
)

result = await command_bus.execute(command)
```

### Creating a Template
```python
command = CreateTemplateCommand(
    code="order_confirmation",
    name="Order Confirmation",
    channel=NotificationChannel.EMAIL,
    template_type=TemplateType.TRANSACTIONAL,
    subject_template="Your order {{order_id}} has been confirmed",
    body_template="Dear {{customer_name}}, your order {{order_id}} for {{total_amount}} has been confirmed.",
    variables=[
        {"name": "order_id", "type": "string", "required": True},
        {"name": "customer_name", "type": "string", "required": True},
        {"name": "total_amount", "type": "currency", "required": True}
    ]
)

template = await command_bus.execute(command)
```

### Querying Notification History
```python
query = GetNotificationHistoryQuery(
    recipient_id=user_id,
    channel=NotificationChannel.EMAIL,
    date_from=datetime.now() - timedelta(days=30),
    page=1,
    page_size=20
)

history = await query_bus.execute(query)
```

## Error Handling

The application layer implements comprehensive error handling:

- **Validation Errors**: Invalid command/query parameters
- **Business Rule Violations**: Domain constraint violations
- **Infrastructure Failures**: External service unavailability
- **Rate Limiting**: Quota exceeded scenarios
- **Template Errors**: Invalid templates or missing variables

All errors are properly logged and include correlation IDs for traceability.

## Performance Considerations

- **Async/Await**: All operations are asynchronous
- **Batch Operations**: Support for bulk processing
- **Caching**: Query results cached where appropriate
- **Rate Limiting**: Prevents system overload
- **Connection Pooling**: Efficient resource utilization

## Security Features

- **Input Validation**: All inputs thoroughly validated
- **Authorization**: User context propagated through commands
- **Audit Logging**: All operations logged for compliance
- **Rate Limiting**: Prevents abuse and DoS attacks
- **Data Encryption**: Sensitive data encrypted at rest and in transit

## Monitoring and Observability

- **Structured Logging**: Consistent log format with correlation IDs
- **Metrics Collection**: Performance and business metrics
- **Health Checks**: Component health monitoring
- **Distributed Tracing**: Request flow tracking
- **Error Tracking**: Centralized error reporting

## Testing Strategy

- **Unit Tests**: Individual component testing
- **Integration Tests**: Cross-component interaction testing
- **Contract Tests**: Interface compatibility testing
- **Performance Tests**: Load and stress testing
- **End-to-End Tests**: Complete workflow validation

## Configuration

The application layer is configured through dependency injection:

- Repository implementations
- External service clients
- Rate limiting parameters
- Template configurations
- Channel provider settings

## Deployment Considerations

- **Scalability**: Stateless design enables horizontal scaling
- **Resilience**: Circuit breakers and retry mechanisms
- **Monitoring**: Health endpoints and metrics exposure
- **Configuration**: Environment-specific settings
- **Security**: Secret management and encryption

This implementation provides a robust, scalable, and maintainable foundation for notification functionality within the EzzDay application.