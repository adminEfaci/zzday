"""Channel configuration input types.

This module contains GraphQL input types for managing notification channels.
"""

import strawberry

from ..enums import ChannelStatusEnum, NotificationChannelEnum


@strawberry.input
class ChannelSettingsInput:
    """GraphQL input for channel settings."""

    key: str
    value: str
    description: str | None = None
    is_sensitive: bool = False


@strawberry.input
class ChannelRateLimitInput:
    """GraphQL input for channel rate limiting configuration."""

    enabled: bool = True

    # Rate limits
    requests_per_minute: int | None = None
    requests_per_hour: int | None = None
    requests_per_day: int | None = None

    # Burst configuration
    burst_capacity: int | None = None
    burst_refill_rate: float | None = None

    # Throttling behavior
    throttle_on_limit: bool = True
    queue_on_limit: bool = False
    max_queue_size: int | None = None


@strawberry.input
class ChannelProviderConfigInput:
    """GraphQL input for channel provider configuration."""

    provider_name: str

    # Provider settings
    settings: list[ChannelSettingsInput]

    # Connection settings
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: int = 5

    # Health check configuration
    health_check_enabled: bool = True
    health_check_interval_minutes: int = 5
    health_check_timeout_seconds: int = 10

    # Webhook configuration (if supported)
    webhook_url: str | None = None
    webhook_secret: str | None = None
    webhook_events: list[str] | None = None


@strawberry.input
class ChannelConfigInput:
    """GraphQL input for creating or updating channel configuration."""

    # Basic information
    name: str
    description: str | None = None
    channel: NotificationChannelEnum

    # Provider configuration
    provider_config: ChannelProviderConfigInput

    # Channel settings
    settings: list[ChannelSettingsInput] | None = None

    # Status and features
    is_active: bool = True
    is_default: bool = False

    # Feature flags
    supports_scheduling: bool = True
    supports_batching: bool = False
    supports_personalization: bool = True
    supports_a_b_testing: bool = False
    supports_tracking: bool = True
    supports_attachments: bool = False

    # Rate limiting
    rate_limit: ChannelRateLimitInput | None = None

    # Fallback configuration
    fallback_channel_id: strawberry.ID | None = None
    enable_fallback: bool = False

    # Cost tracking
    cost_per_message: float | None = None
    currency: str | None = None
    billing_provider_id: str | None = None


@strawberry.input
class ChannelUpdateInput:
    """GraphQL input for updating channel configuration."""

    # Basic information
    name: str | None = None
    description: str | None = None

    # Provider configuration updates
    provider_config: ChannelProviderConfigInput | None = None

    # Settings updates
    settings: list[ChannelSettingsInput] | None = None

    # Status updates
    status: ChannelStatusEnum | None = None
    is_active: bool | None = None
    is_default: bool | None = None

    # Feature updates
    supports_scheduling: bool | None = None
    supports_batching: bool | None = None
    supports_personalization: bool | None = None
    supports_a_b_testing: bool | None = None
    supports_tracking: bool | None = None
    supports_attachments: bool | None = None

    # Rate limiting updates
    rate_limit: ChannelRateLimitInput | None = None

    # Fallback updates
    fallback_channel_id: strawberry.ID | None = None
    enable_fallback: bool | None = None

    # Cost updates
    cost_per_message: float | None = None
    currency: str | None = None


@strawberry.input
class ChannelTestInput:
    """GraphQL input for testing channel configuration."""

    channel_id: strawberry.ID

    # Test configuration
    test_type: str = "connectivity"  # "connectivity", "send", "webhook"

    # Test message (for send tests)
    test_recipient: str | None = None
    test_subject: str | None = None
    test_body: str | None = None

    # Test options
    timeout_seconds: int = 30
    include_delivery_tracking: bool = True

    # Advanced testing
    test_error_handling: bool = False
    test_rate_limiting: bool = False
    simulate_failure: bool = False


@strawberry.input
class ChannelHealthCheckInput:
    """GraphQL input for channel health check configuration."""

    enabled: bool = True

    # Check frequency
    interval_minutes: int = 5
    timeout_seconds: int = 10

    # Health criteria
    max_response_time_ms: int = 5000
    min_success_rate: float = 95.0

    # Alert configuration
    alert_on_failure: bool = True
    alert_threshold: int = 3  # Number of consecutive failures
    recovery_threshold: int = 2  # Number of consecutive successes

    # Notification settings for alerts
    alert_email: str | None = None
    alert_webhook: str | None = None


@strawberry.input
class ChannelMonitoringInput:
    """GraphQL input for channel monitoring configuration."""

    # Metrics collection
    collect_performance_metrics: bool = True
    collect_cost_metrics: bool = True
    collect_error_metrics: bool = True

    # Retention settings
    metrics_retention_days: int = 90
    detailed_logs_retention_days: int = 30

    # Alerting thresholds
    error_rate_threshold: float = 5.0  # Percentage
    response_time_threshold_ms: int = 10000
    success_rate_threshold: float = 95.0

    # Alert destinations
    alert_channels: list[str] | None = None
    alert_webhooks: list[str] | None = None

    # Reporting
    daily_report_enabled: bool = False
    weekly_report_enabled: bool = True
    monthly_report_enabled: bool = True
    report_recipients: list[str] | None = None


@strawberry.input
class ChannelMigrationInput:
    """GraphQL input for migrating between channels."""

    source_channel_id: strawberry.ID
    target_channel_id: strawberry.ID

    # Migration strategy
    migration_type: str = "gradual"  # "immediate", "gradual", "test_first"

    # Gradual migration settings
    percentage_to_migrate: int = 10  # Start with 10%
    increase_percentage_every_hours: int = 24
    max_percentage: int = 100

    # Test settings
    test_notification_count: int = 100
    test_success_threshold: float = 95.0

    # Rollback settings
    auto_rollback_on_failure: bool = True
    failure_threshold: float = 90.0  # Rollback if success rate drops below this

    # Notification settings
    notify_on_milestone: bool = True
    notify_on_completion: bool = True
    notify_on_failure: bool = True


@strawberry.input
class ChannelBulkActionInput:
    """GraphQL input for bulk channel actions."""

    channel_ids: list[strawberry.ID]
    action: str  # "activate", "deactivate", "test", "reset_stats", "update_settings"

    # Action-specific parameters
    settings_updates: list[ChannelSettingsInput] | None = None
    new_status: ChannelStatusEnum | None = None

    # Test parameters
    test_config: ChannelTestInput | None = None

    # Confirmation for destructive actions
    confirm_action: bool = False

    # Execution options
    continue_on_error: bool = True
    execute_in_parallel: bool = False

    # Reason for bulk action
    reason: str | None = None


@strawberry.input
class ChannelBackupInput:
    """GraphQL input for backing up channel configurations."""

    # Channels to backup
    channel_ids: list[strawberry.ID] | None = None  # If None, backup all

    # Backup options
    include_settings: bool = True
    include_provider_config: bool = True
    include_rate_limits: bool = True
    include_monitoring_config: bool = True
    include_statistics: bool = False

    # Backup format
    format: str = "json"  # "json", "yaml"
    compress: bool = True

    # Encryption
    encrypt_sensitive_data: bool = True
    encryption_key: str | None = None


@strawberry.input
class ChannelRestoreInput:
    """GraphQL input for restoring channel configurations."""

    # Backup data
    backup_data: str  # JSON/YAML string
    backup_format: str = "json"

    # Restore options
    restore_settings: bool = True
    restore_provider_config: bool = True
    restore_rate_limits: bool = True
    restore_monitoring_config: bool = True

    # Conflict resolution
    overwrite_existing: bool = False
    merge_with_existing: bool = True
    create_new_on_conflict: bool = False

    # Validation
    validate_before_restore: bool = True
    test_connections_after_restore: bool = True

    # Decryption
    decryption_key: str | None = None
