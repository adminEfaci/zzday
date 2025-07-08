# Background Task Processing System

This document provides comprehensive information about the EzzDay background task processing system built with Celery and RabbitMQ.

## Overview

The background task system handles all asynchronous operations including:

- **Identity Tasks**: Password resets, MFA codes, account verification
- **Audit Tasks**: Report generation, log archival, compliance reporting
- **Notification Tasks**: Email, SMS, and push notifications
- **Integration Tasks**: External system synchronization, webhook delivery

## Architecture

### Components

1. **Celery Workers**: Process tasks in the background
2. **RabbitMQ**: Message broker for task queuing
3. **Redis**: Result backend for task status and results
4. **Flower**: Web-based monitoring interface
5. **Beat Scheduler**: Handles periodic tasks

### Queue Structure

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   High Priority │    │  Medium Priority │    │   Low Priority  │
│   - Emails      │    │  - Notifications │    │   - Reports     │
│   - SMS         │    │  - Webhooks      │    │   - Cleanup     │
│   - Security    │    │  - Sync Jobs     │    │   - Archive     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌──────────────────────┐
                    │     Dead Letter      │
                    │    Queue (Failed)    │
                    └──────────────────────┘
```

### Task Routing

- **High Priority Queue**: Email, SMS, security alerts
- **Medium Priority Queue**: Bulk notifications, webhook delivery
- **Low Priority Queue**: Reports, cleanup, archival
- **Specialized Queues**: Identity, audit, notifications, integrations
- **Dead Letter Queue**: Failed tasks for investigation

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- PostgreSQL database running

### Quick Start

1. **Start the task system:**
   ```bash
   ./scripts/start_tasks.sh start
   ```

2. **Check status:**
   ```bash
   ./scripts/start_tasks.sh status
   ```

3. **View logs:**
   ```bash
   ./scripts/start_tasks.sh logs
   ```

4. **Access monitoring:**
   - Flower: http://localhost:5555
   - RabbitMQ Management: http://localhost:15672

### Environment Configuration

Create or update your `.env` file with task-specific settings:

```env
# Celery Configuration
CELERY_BROKER_URL=amqp://ezzday:ezzday_rabbitmq_pass@localhost:5672/ezzday
CELERY_RESULT_BACKEND=redis://:ezzday_redis_pass@localhost:6379/0
CELERY_TASK_ALWAYS_EAGER=false

# RabbitMQ Settings
RABBITMQ_USER=ezzday
RABBITMQ_PASSWORD=ezzday_rabbitmq_pass
RABBITMQ_VHOST=ezzday

# Redis Settings
REDIS_PASSWORD=ezzday_redis_pass

# Flower Monitoring
FLOWER_USER=admin
FLOWER_PASSWORD=flower_admin_pass

# Email Configuration (required for notifications)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USERNAME=your-email@example.com
EMAIL_PASSWORD=your-email-password

# SMS Configuration (optional)
SMS_PROVIDER_API_KEY=your-sms-api-key
```

## Task Types

### Identity Tasks

Located in `app/tasks/identity_tasks.py`:

- **send_password_reset_email**: Send password reset emails
- **send_mfa_code**: Send MFA verification codes via SMS
- **send_account_verification_email**: Send account verification emails
- **send_security_alert**: Send security notifications
- **cleanup_expired_sessions**: Clean up old sessions
- **cleanup_expired_tokens**: Remove expired tokens

### Audit Tasks

Located in `app/tasks/audit_tasks.py`:

- **generate_daily_report**: Generate daily audit reports
- **generate_compliance_report**: Create GDPR/SOX compliance reports
- **archive_old_logs**: Archive old audit logs
- **detect_anomalies**: Detect suspicious patterns
- **send_security_alert_email**: Send security alerts to admins

### Notification Tasks

Located in `app/tasks/notification_tasks.py`:

- **send_email**: Send email notifications
- **send_sms**: Send SMS notifications
- **send_push_notification**: Send push notifications
- **send_bulk_notification**: Send notifications to multiple users
- **process_scheduled_notifications**: Process scheduled notifications
- **retry_failed_notifications**: Retry failed notifications

### Integration Tasks

Located in `app/tasks/integration_tasks.py`:

- **webhook_delivery**: Deliver webhooks to external systems
- **sync_external_system**: Synchronize with external APIs
- **sync_all_systems**: Sync all active integrations
- **health_check_integrations**: Check integration health

## Monitoring and Management

### Web Interfaces

1. **Flower (Celery Monitoring)**
   - URL: http://localhost:5555
   - Features: Worker status, task monitoring, statistics
   - Authentication: admin/flower_admin_pass (configurable)

2. **RabbitMQ Management**
   - URL: http://localhost:15672
   - Features: Queue management, message routing, cluster status
   - Authentication: ezzday/ezzday_rabbitmq_pass (configurable)

### API Endpoints

Task monitoring endpoints available at `/api/v1/tasks/`:

- `GET /api/v1/tasks/stats` - Overall task statistics
- `GET /api/v1/tasks/active` - Currently active tasks
- `GET /api/v1/tasks/scheduled` - Scheduled tasks
- `GET /api/v1/tasks/task/{task_id}` - Specific task status
- `POST /api/v1/tasks/task/{task_id}/revoke` - Cancel a task
- `GET /api/v1/tasks/health` - System health check

### Command Line Management

```bash
# Start all services
./scripts/start_tasks.sh start

# Stop all services
./scripts/start_tasks.sh stop

# Restart services
./scripts/start_tasks.sh restart

# View service status
./scripts/start_tasks.sh status

# View logs (all services)
./scripts/start_tasks.sh logs

# View logs for specific service
./scripts/start_tasks.sh logs celery-worker-general

# Health check
./scripts/start_tasks.sh health
```

## Development

### Running Tasks Locally

For development, you can run tasks synchronously:

```python
# In your .env file
CELERY_TASK_ALWAYS_EAGER=true

# Tasks will execute immediately instead of being queued
```

### Creating New Tasks

1. **Choose the appropriate module** based on task type:
   - Identity: `app/tasks/identity_tasks.py`
   - Audit: `app/tasks/audit_tasks.py`
   - Notification: `app/tasks/notification_tasks.py`
   - Integration: `app/tasks/integration_tasks.py`

2. **Create the task function**:
   ```python
   @celery_app.task(
       bind=True,
       base=YourTaskClass,
       name="app.tasks.module.your_task",
       max_retries=3,
       default_retry_delay=60
   )
   def your_task(self, param1: str, param2: int) -> Dict[str, Any]:
       try:
           # Your task logic here
           result = do_something(param1, param2)
           return {"status": "success", "result": result}
       except Exception as exc:
           logger.error(f"Task failed: {exc}")
           raise self.retry(exc=exc)
   ```

3. **Add routing configuration** in `app/tasks/__init__.py`:
   ```python
   celery_app.conf.task_routes.update({
       "app.tasks.module.your_task": {"queue": "appropriate_queue"},
   })
   ```

4. **Add to periodic schedule** (if needed):
   ```python
   celery_app.conf.beat_schedule.update({
       "your-task-schedule": {
           "task": "app.tasks.module.your_task",
           "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
       },
   })
   ```

### Testing

Run tests for the task system:

```bash
# Run task-specific tests
pytest tests/test_tasks/

# Run with task logging
pytest tests/test_tasks/ -v -s

# Test specific task types
pytest tests/test_tasks/test_identity_tasks.py
pytest tests/test_tasks/test_notification_tasks.py
```

## Configuration

### Worker Configuration

Workers can be configured via environment variables:

```env
# Worker naming
CELERY_WORKER_NAME=worker-1

# Concurrency (number of parallel tasks)
CELERY_WORKER_CONCURRENCY=4

# Log level
CELERY_LOG_LEVEL=INFO
```

### Queue Configuration

Queues are automatically configured with the following properties:

- **High Priority**: Max priority 10, for urgent tasks
- **Medium Priority**: Max priority 5, for normal tasks  
- **Low Priority**: Max priority 1, for background tasks
- **Dead Letter**: TTL 24 hours, max 10,000 messages

### Retry Policies

Default retry configurations:

- **Max Retries**: 3 (configurable per task)
- **Retry Delay**: 60 seconds (with exponential backoff)
- **Rate Limiting**: 100 tasks/minute (configurable per task)

## Troubleshooting

### Common Issues

1. **Workers not starting**
   ```bash
   # Check Docker containers
   docker-compose -f docker-compose.tasks.yml ps
   
   # Check logs
   docker-compose -f docker-compose.tasks.yml logs celery-worker-general
   ```

2. **Tasks stuck in queue**
   ```bash
   # Check worker connectivity
   ./scripts/start_tasks.sh health
   
   # Inspect queues in RabbitMQ management interface
   # http://localhost:15672
   ```

3. **High memory usage**
   - Reduce worker concurrency
   - Check for memory leaks in task code
   - Restart workers periodically

4. **Failed tasks**
   - Check dead letter queue
   - Review task logs
   - Verify external service connectivity

### Debugging

Enable debug logging:

```env
CELERY_LOG_LEVEL=DEBUG
LOG_LEVEL=DEBUG
```

Monitor task execution:

```python
# In your application code
from app.tasks import celery_app

# Get task status
result = celery_app.AsyncResult(task_id)
print(f"Status: {result.status}")
print(f"Result: {result.result}")

# Get worker stats
inspect = celery_app.control.inspect()
stats = inspect.stats()
print(f"Worker stats: {stats}")
```

## Security Considerations

### Message Security

- All task messages are serialized as JSON
- Sensitive data should be encrypted before queuing
- Use task IDs to reference sensitive data stored securely

### Access Control

- Flower monitoring requires authentication
- RabbitMQ management interface is password protected
- API endpoints require appropriate permissions

### Network Security

- Use TLS for production RabbitMQ connections
- Restrict access to monitoring interfaces
- Use VPN or private networks for multi-server deployments

## Performance Optimization

### Scaling

1. **Horizontal Scaling**:
   - Add more worker containers
   - Distribute workers across multiple servers
   - Use load balancing for high availability

2. **Vertical Scaling**:
   - Increase worker concurrency
   - Allocate more memory and CPU
   - Optimize task code for efficiency

### Monitoring Metrics

Key metrics to monitor:

- **Queue Length**: Tasks waiting to be processed
- **Task Rate**: Tasks processed per second
- **Failure Rate**: Percentage of failed tasks
- **Worker Utilization**: CPU and memory usage
- **Response Time**: Task execution duration

### Best Practices

1. **Task Design**:
   - Keep tasks idempotent
   - Use appropriate timeouts
   - Handle failures gracefully
   - Log important events

2. **Resource Management**:
   - Set memory limits for workers
   - Use connection pooling
   - Clean up resources in task cleanup

3. **Error Handling**:
   - Implement proper retry logic
   - Use dead letter queues
   - Monitor failure patterns

## Production Deployment

### High Availability Setup

1. **Multiple RabbitMQ Nodes**:
   ```yaml
   # docker-compose.prod.yml
   rabbitmq-1:
     image: rabbitmq:3.12-management
     environment:
       RABBITMQ_ERLANG_COOKIE: secure_cookie
   
   rabbitmq-2:
     image: rabbitmq:3.12-management
     environment:
       RABBITMQ_ERLANG_COOKIE: secure_cookie
   ```

2. **Redis Clustering**:
   - Use Redis Sentinel for high availability
   - Configure Redis cluster for scalability

3. **Worker Distribution**:
   - Deploy workers across multiple servers
   - Use container orchestration (Kubernetes)

### Monitoring in Production

1. **Prometheus Integration**:
   ```yaml
   # Add to docker-compose
   prometheus:
     image: prom/prometheus
     ports:
       - "9090:9090"
   ```

2. **Grafana Dashboards**:
   - Import Celery monitoring dashboards
   - Set up alerting for critical metrics

3. **Health Checks**:
   - Implement liveness and readiness probes
   - Monitor external service dependencies

## Support

For issues and questions:

1. Check the logs: `./scripts/start_tasks.sh logs`
2. Review the monitoring interfaces
3. Consult the troubleshooting section
4. Check task-specific documentation in the code