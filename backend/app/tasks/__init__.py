"""Celery configuration and initialization."""
from celery import Celery
from kombu import Exchange, Queue

from app.core.config import settings

# Create Celery instance
celery_app = Celery(
    "ezzday",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.identity_tasks",
        "app.tasks.audit_tasks",
        "app.tasks.notification_tasks",
        "app.tasks.integration_tasks",
    ],
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes hard limit
    task_soft_time_limit=25 * 60,  # 25 minutes soft limit
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    result_expires=3600,  # 1 hour
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,  # For testing
)

# Define exchanges
default_exchange = Exchange("default", type="direct")
priority_exchange = Exchange("priority", type="direct")
notifications_exchange = Exchange("notifications", type="topic")
integrations_exchange = Exchange("integrations", type="topic")

# Define queues with routing
celery_app.conf.task_queues = (
    # Default queue
    Queue("celery", default_exchange, routing_key="celery"),
    # Priority queues
    Queue(
        "high_priority",
        priority_exchange,
        routing_key="high",
        queue_arguments={"x-max-priority": 10},
    ),
    Queue(
        "medium_priority",
        priority_exchange,
        routing_key="medium",
        queue_arguments={"x-max-priority": 5},
    ),
    Queue(
        "low_priority",
        priority_exchange,
        routing_key="low",
        queue_arguments={"x-max-priority": 1},
    ),
    # Specialized queues
    Queue("identity", default_exchange, routing_key="identity"),
    Queue("audit", default_exchange, routing_key="audit"),
    Queue("notifications", notifications_exchange, routing_key="notification.*"),
    Queue("integrations", integrations_exchange, routing_key="integration.*"),
    # Dead letter queue
    Queue(
        "dead_letter",
        Exchange("dead_letter", type="direct"),
        routing_key="failed",
        queue_arguments={"x-message-ttl": 86400000, "x-max-length": 10000},  # 24 hours
    ),
)

# Route tasks to specific queues
celery_app.conf.task_routes = {
    # Identity tasks
    "app.tasks.identity_tasks.*": {"queue": "identity"},
    # Audit tasks
    "app.tasks.audit_tasks.*": {"queue": "audit"},
    # Notification tasks
    "app.tasks.notification_tasks.send_email": {"queue": "high_priority"},
    "app.tasks.notification_tasks.send_sms": {"queue": "high_priority"},
    "app.tasks.notification_tasks.*": {"queue": "notifications"},
    # Integration tasks
    "app.tasks.integration_tasks.*": {"queue": "integrations"},
}

# Retry configuration
celery_app.conf.task_annotations = {
    "*": {
        "rate_limit": "100/m",
        "max_retries": 3,
        "default_retry_delay": 60,  # 1 minute
    },
    "app.tasks.notification_tasks.send_email": {
        "rate_limit": "50/m",
        "max_retries": 5,
        "default_retry_delay": 120,  # 2 minutes
    },
    "app.tasks.integration_tasks.webhook_delivery": {
        "rate_limit": "30/s",
        "max_retries": 10,
        "default_retry_delay": 300,  # 5 minutes
    },
}

# Beat schedule for periodic tasks
from celery.schedules import crontab

celery_app.conf.beat_schedule = {
    # Cleanup tasks
    "cleanup-expired-sessions": {
        "task": "app.tasks.identity_tasks.cleanup_expired_sessions",
        "schedule": crontab(minute="*/30"),  # Every 30 minutes
    },
    "cleanup-expired-tokens": {
        "task": "app.tasks.identity_tasks.cleanup_expired_tokens",
        "schedule": crontab(hour="*/6"),  # Every 6 hours
    },
    # Audit tasks
    "generate-daily-audit-report": {
        "task": "app.tasks.audit_tasks.generate_daily_report",
        "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
    },
    "archive-old-audit-logs": {
        "task": "app.tasks.audit_tasks.archive_old_logs",
        "schedule": crontab(day_of_week=0, hour=3, minute=0),  # Weekly on Sunday
    },
    # Notification tasks
    "process-scheduled-notifications": {
        "task": "app.tasks.notification_tasks.process_scheduled",
        "schedule": crontab(minute="*/5"),  # Every 5 minutes
    },
    "cleanup-old-notifications": {
        "task": "app.tasks.notification_tasks.cleanup_old_notifications",
        "schedule": crontab(hour=4, minute=0),  # Daily at 4 AM
    },
    # Health checks
    "worker-health-check": {
        "task": "app.tasks.health_check",
        "schedule": 60.0,  # Every minute
    },
    # Integration sync
    "sync-external-systems": {
        "task": "app.tasks.integration_tasks.sync_all_systems",
        "schedule": crontab(minute="*/15"),  # Every 15 minutes
    },
}


# Health check task
@celery_app.task(name="app.tasks.health_check")
def health_check():
    """Simple health check task."""
    return {"status": "healthy", "timestamp": "utcnow"}


# Task event handlers
@celery_app.task(bind=True, name="app.tasks.error_handler")
def error_handler(self, uuid):
    """Handle failed tasks."""
    result = self.AsyncResult(uuid)
    exc = result.get(propagate=False)
    print(f"Task {uuid} raised exception: {exc}")
    # Log to monitoring system
    return {"task_id": uuid, "status": "error_handled"}


# Configure error handling
celery_app.conf.task_reject_on_worker_lost = True
celery_app.conf.task_ignore_result = False

# Monitoring configuration
celery_app.conf.worker_send_task_events = True
celery_app.conf.task_send_sent_event = True

# Export for use in other modules
__all__ = ["celery_app"]
