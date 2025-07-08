"""Celery configuration settings."""
from typing import Any, ClassVar

from app.core.config import settings


# Celery configuration class
class CeleryConfig:
    """Celery configuration settings."""

    # Broker settings
    broker_url = settings.CELERY_BROKER_URL
    result_backend = settings.CELERY_RESULT_BACKEND

    # Task settings
    task_serializer = "json"
    accept_content = "json"
    result_serializer = "json"
    timezone = "UTC"
    enable_utc = True

    # Task execution settings
    task_track_started = True
    task_time_limit = 30 * 60  # 30 minutes hard limit
    task_soft_time_limit = 25 * 60  # 25 minutes soft limit
    task_acks_late = True
    task_reject_on_worker_lost = True
    task_ignore_result = False

    # Worker settings
    worker_prefetch_multiplier = 1
    worker_max_tasks_per_child = 1000
    worker_disable_rate_limits = False
    worker_send_task_events = True

    # Result settings
    result_expires = 3600  # 1 hour
    result_compression = "gzip"
    result_extended = True

    # Monitoring settings
    task_send_sent_event = True

    # Rate limiting
    task_default_rate_limit = "100/m"

    # Retry settings
    task_default_retry_delay = 60
    task_max_retries = 3

    # Security settings
    task_always_eager = settings.CELERY_TASK_ALWAYS_EAGER
    worker_hijack_root_logger = False
    worker_log_color = False

    # Beat settings (for periodic tasks)
    beat_schedule_filename = "celerybeat-schedule"
    beat_sync_every = 1

    # Error handling
    task_annotations: ClassVar[dict[str, Any]] = {
        "*": {
            "rate_limit": "100/m",
            "time_limit": 1800,  # 30 minutes
            "soft_time_limit": 1500,  # 25 minutes
        },
        # High priority tasks
        "app.tasks.notification_tasks.send_email": {
            "rate_limit": "50/m",
            "priority": 8,
            "time_limit": 300,  # 5 minutes
        },
        "app.tasks.notification_tasks.send_sms": {
            "rate_limit": "30/m",
            "priority": 8,
            "time_limit": 120,  # 2 minutes
        },
        "app.tasks.identity_tasks.send_password_reset_email": {
            "rate_limit": "20/m",
            "priority": 7,
            "time_limit": 300,  # 5 minutes
        },
        # Low priority tasks
        "app.tasks.audit_tasks.archive_old_logs": {
            "rate_limit": "1/h",
            "priority": 2,
            "time_limit": 3600,  # 1 hour
        },
        "app.tasks.audit_tasks.generate_compliance_report": {
            "rate_limit": "5/h",
            "priority": 3,
            "time_limit": 1800,  # 30 minutes
        },
        # Integration tasks
        "app.tasks.integration_tasks.webhook_delivery": {
            "rate_limit": "100/s",
            "priority": 6,
            "max_retries": 10,
            "default_retry_delay": 300,  # 5 minutes
        },
        "app.tasks.integration_tasks.sync_external_system": {
            "rate_limit": "10/m",
            "priority": 4,
            "time_limit": 1800,  # 30 minutes
        },
    }


# Queue configuration
CELERY_QUEUES_CONFIG = {
    # Default queue
    "celery": {
        "exchange": "default",
        "exchange_type": "direct",
        "routing_key": "celery",
    },
    # Priority queues
    "high_priority": {
        "exchange": "priority",
        "exchange_type": "direct",
        "routing_key": "high",
        "queue_arguments": {"x-max-priority": 10},
    },
    "medium_priority": {
        "exchange": "priority",
        "exchange_type": "direct",
        "routing_key": "medium",
        "queue_arguments": {"x-max-priority": 5},
    },
    "low_priority": {
        "exchange": "priority",
        "exchange_type": "direct",
        "routing_key": "low",
        "queue_arguments": {"x-max-priority": 1},
    },
    # Specialized queues
    "identity": {
        "exchange": "default",
        "exchange_type": "direct",
        "routing_key": "identity",
    },
    "audit": {"exchange": "default", "exchange_type": "direct", "routing_key": "audit"},
    "notifications": {
        "exchange": "notifications",
        "exchange_type": "topic",
        "routing_key": "notification.*",
    },
    "integrations": {
        "exchange": "integrations",
        "exchange_type": "topic",
        "routing_key": "integration.*",
    },
    # Dead letter queue
    "dead_letter": {
        "exchange": "dead_letter",
        "exchange_type": "direct",
        "routing_key": "failed",
        "queue_arguments": {
            "x-message-ttl": 86400000,  # 24 hours
            "x-max-length": 10000,
        },
    },
}

# Task routing configuration
CELERY_TASK_ROUTES = {
    # Identity tasks
    "app.tasks.identity_tasks.send_password_reset_email": {"queue": "high_priority"},
    "app.tasks.identity_tasks.send_mfa_code": {"queue": "high_priority"},
    "app.tasks.identity_tasks.send_account_verification_email": {
        "queue": "medium_priority"
    },
    "app.tasks.identity_tasks.send_security_alert": {"queue": "high_priority"},
    "app.tasks.identity_tasks.*": {"queue": "identity"},
    # Audit tasks
    "app.tasks.audit_tasks.detect_anomalies": {"queue": "high_priority"},
    "app.tasks.audit_tasks.send_security_alert_email": {"queue": "high_priority"},
    "app.tasks.audit_tasks.*": {"queue": "audit"},
    # Notification tasks
    "app.tasks.notification_tasks.send_email": {"queue": "high_priority"},
    "app.tasks.notification_tasks.send_sms": {"queue": "high_priority"},
    "app.tasks.notification_tasks.send_push_notification": {"queue": "high_priority"},
    "app.tasks.notification_tasks.send_bulk_notification": {"queue": "medium_priority"},
    "app.tasks.notification_tasks.*": {"queue": "notifications"},
    # Integration tasks
    "app.tasks.integration_tasks.webhook_delivery": {"queue": "medium_priority"},
    "app.tasks.integration_tasks.sync_external_system": {"queue": "low_priority"},
    "app.tasks.integration_tasks.*": {"queue": "integrations"},
}

# Monitoring configuration
CELERY_MONITORING_CONFIG = {
    "worker_send_task_events": True,
    "task_send_sent_event": True,
    "worker_enable_remote_control": True,
    "worker_pool_restarts": True,
    # Event monitoring
    "event_queue_expires": 60,
    "event_queue_ttl": 5,
    # Logging
    "worker_log_format": "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s",
    "worker_task_log_format": "[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s",
    # Health checks
    "worker_enable_heartbeats": True,
    "worker_heartbeat_interval": 30,
}

# Security configuration
CELERY_SECURITY_CONFIG = {
    "task_always_eager": settings.CELERY_TASK_ALWAYS_EAGER,
    "worker_hijack_root_logger": False,
    "worker_log_color": False,
    "worker_disable_rate_limits": False,
    # Message encryption (if needed)
    "task_message_compression": "gzip",
    "result_compression": "gzip",
    # Authentication (if using broker auth)
    "broker_use_ssl": getattr(settings, "CELERY_BROKER_USE_SSL", False),
    "broker_connection_retry": True,
    "broker_connection_retry_on_startup": True,
    "broker_connection_max_retries": 10,
}


def get_celery_config() -> dict[str, Any]:
    """Get complete Celery configuration."""
    config = {}

    # Add base configuration
    for attr in dir(CeleryConfig):
        if not attr.startswith("_"):
            config[attr] = getattr(CeleryConfig, attr)

    # Add queue configuration
    config["task_routes"] = CELERY_TASK_ROUTES

    # Add monitoring configuration
    config.update(CELERY_MONITORING_CONFIG)

    # Add security configuration
    config.update(CELERY_SECURITY_CONFIG)

    return config
