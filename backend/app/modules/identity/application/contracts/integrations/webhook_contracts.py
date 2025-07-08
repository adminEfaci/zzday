"""
Webhook Integration Contracts.

Defines comprehensive contracts for webhook delivery including user events,
security events, audit events, and compliance notifications with enterprise
reliability features like retries, dead letter queues, and signature verification.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class WebhookEventType(Enum):
    """Webhook event types."""
    # User Events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ENABLED = "user.enabled"
    USER_DISABLED = "user.disabled"
    USER_LOCKED = "user.locked"
    USER_UNLOCKED = "user.unlocked"
    USER_PASSWORD_CHANGED = "user.password_changed"
    USER_EMAIL_VERIFIED = "user.email_verified"
    USER_PROFILE_UPDATED = "user.profile_updated"

    # Security Events
    LOGIN_SUCCESS = "auth.login_success"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"
    PASSWORD_RESET_COMPLETED = "auth.password_reset_completed"
    MFA_ENABLED = "security.mfa_enabled"
    MFA_DISABLED = "security.mfa_disabled"
    MFA_FAILED = "security.mfa_failed"
    SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    ACCOUNT_LOCKED = "security.account_locked"
    BREACH_DETECTED = "security.breach_detected"

    # Authorization Events
    ROLE_ASSIGNED = "authz.role_assigned"
    ROLE_REVOKED = "authz.role_revoked"
    PERMISSION_GRANTED = "authz.permission_granted"
    PERMISSION_REVOKED = "authz.permission_revoked"
    ACCESS_DENIED = "authz.access_denied"
    PRIVILEGE_ESCALATION = "authz.privilege_escalation"

    # Audit Events
    AUDIT_LOG_CREATED = "audit.log_created"
    COMPLIANCE_VIOLATION = "audit.compliance_violation"
    DATA_ACCESS = "audit.data_access"
    DATA_EXPORT = "audit.data_export"
    ADMIN_ACTION = "audit.admin_action"

    # System Events
    SESSION_CREATED = "system.session_created"
    SESSION_EXPIRED = "system.session_expired"
    API_KEY_CREATED = "system.api_key_created"
    API_KEY_REVOKED = "system.api_key_revoked"
    BACKUP_COMPLETED = "system.backup_completed"
    MAINTENANCE_MODE = "system.maintenance_mode"


class WebhookStatus(Enum):
    """Webhook delivery status."""
    PENDING = "pending"
    SENDING = "sending"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"
    DISABLED = "disabled"


class WebhookSignatureMethod(Enum):
    """Webhook signature methods."""
    HMAC_SHA1 = "hmac-sha1"
    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA512 = "hmac-sha512"
    JWT = "jwt"


class RetryStrategy(Enum):
    """Retry strategies for failed webhooks."""
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"
    FIXED_INTERVAL = "fixed_interval"
    IMMEDIATE = "immediate"


@dataclass
class WebhookConfiguration:
    """Webhook configuration."""
    # Required fields (no defaults)
    webhook_id: UUID
    name: str
    description: str
    url: str
    secret: str
    created_at: datetime
    updated_at: datetime
    created_by: UUID
    tags: list[str]
    event_types: list[WebhookEventType]
    event_filters: dict[str, Any]  # Additional filtering criteria
    retry_intervals: list[int]  # Seconds between retries

    # Optional fields (with defaults)
    backoff_multiplier: float = 2.0
    enabled: bool = True
    max_requests_per_minute: int = 60
    burst_limit: int = 10
    dead_letter_enabled: bool = True
    dead_letter_threshold: int = 10
    signature_method: WebhookSignatureMethod = WebhookSignatureMethod.HMAC_SHA256
    signature_header: str = "X-Signature-256"
    http_method: str = "POST"
    timeout_seconds: int = 30
    verify_ssl: bool = True
    retry_strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    max_retries: int = 5


@dataclass
class WebhookEvent:
    """Webhook event data structure."""
    # Required fields (no defaults)
    event_id: UUID
    event_type: WebhookEventType
    timestamp: datetime
    occurred_at: datetime
    source: str  # Service/component that generated the event
    source_version: str
    environment: str  # prod, staging, dev
    data: dict[str, Any]
    metadata: dict[str, Any]

    # Optional fields (with defaults)
    event_version: str = "1.0"
    previous_data: dict[str, Any] | None = None  # For update events
    user_id: UUID | None = None
    session_id: UUID | None = None
    correlation_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    risk_score: float | None = None


@dataclass
class WebhookDelivery:
    """Webhook delivery record."""
    # Required fields (no defaults)
    delivery_id: UUID
    webhook_id: UUID
    event_id: UUID
    url: str
    http_method: str
    headers: dict[str, str]
    payload: str
    signature: str
    status: WebhookStatus
    created_at: datetime
    max_attempts: int
    processed_by: str  # Worker/process that handled delivery

    # Optional fields (with defaults)
    http_status_code: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    sent_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int | None = None
    attempt_number: int = 1
    next_retry_at: datetime | None = None
    error_message: str | None = None
    error_code: str | None = None


@dataclass
class WebhookFilter:
    """Webhook event filtering configuration."""
    # Required fields (no defaults)
    custom_filters: dict[str, Any]

    # Optional fields (with defaults)
    user_ids: list[UUID] | None = None
    user_roles: list[str] | None = None
    user_attributes: dict[str, Any] | None = None
    resource_types: list[str] | None = None
    resource_ids: list[str] | None = None
    ip_address_ranges: list[str] | None = None
    risk_score_threshold: float | None = None
    time_of_day_start: str | None = None  # HH:MM format
    time_of_day_end: str | None = None
    days_of_week: list[int] | None = None  # 0-6, Monday=0


class UserWebhookContract(ABC):
    """Contract for user-related webhook operations."""

    @abstractmethod
    async def send_user_created(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send user created webhook."""

    @abstractmethod
    async def send_user_updated(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        previous_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send user updated webhook."""

    @abstractmethod
    async def send_user_deleted(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send user deleted webhook."""

    @abstractmethod
    async def send_user_status_changed(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        status_change: str,
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send user status change webhook."""

    @abstractmethod
    async def send_password_changed(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send password changed webhook."""

    @abstractmethod
    async def send_email_verified(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send email verified webhook."""


class SecurityWebhookContract(ABC):
    """Contract for security-related webhook operations."""

    @abstractmethod
    async def send_login_success(
        self,
        webhook_config: WebhookConfiguration,
        login_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send successful login webhook."""

    @abstractmethod
    async def send_login_failed(
        self,
        webhook_config: WebhookConfiguration,
        attempt_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send failed login webhook."""

    @abstractmethod
    async def send_suspicious_activity(
        self,
        webhook_config: WebhookConfiguration,
        activity_data: dict[str, Any],
        risk_assessment: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send suspicious activity webhook."""

    @abstractmethod
    async def send_mfa_event(
        self,
        webhook_config: WebhookConfiguration,
        mfa_event: str,
        user_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send MFA-related webhook."""

    @abstractmethod
    async def send_breach_detected(
        self,
        webhook_config: WebhookConfiguration,
        breach_data: dict[str, Any],
        affected_users: list[dict[str, Any]],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send data breach detected webhook."""

    @abstractmethod
    async def send_account_locked(
        self,
        webhook_config: WebhookConfiguration,
        user_data: dict[str, Any],
        lock_reason: str,
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send account locked webhook."""


class AuditWebhookContract(ABC):
    """Contract for audit-related webhook operations."""

    @abstractmethod
    async def send_audit_log_created(
        self,
        webhook_config: WebhookConfiguration,
        audit_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send audit log created webhook."""

    @abstractmethod
    async def send_compliance_violation(
        self,
        webhook_config: WebhookConfiguration,
        violation_data: dict[str, Any],
        framework: str,
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send compliance violation webhook."""

    @abstractmethod
    async def send_data_access(
        self,
        webhook_config: WebhookConfiguration,
        access_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send data access webhook."""

    @abstractmethod
    async def send_data_export(
        self,
        webhook_config: WebhookConfiguration,
        export_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send data export webhook."""

    @abstractmethod
    async def send_admin_action(
        self,
        webhook_config: WebhookConfiguration,
        action_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send admin action webhook."""


class ComplianceWebhookContract(ABC):
    """Contract for compliance-related webhook operations."""

    @abstractmethod
    async def send_gdpr_request(
        self,
        webhook_config: WebhookConfiguration,
        request_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send GDPR request webhook."""

    @abstractmethod
    async def send_right_to_be_forgotten(
        self,
        webhook_config: WebhookConfiguration,
        deletion_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send right to be forgotten webhook."""

    @abstractmethod
    async def send_data_portability(
        self,
        webhook_config: WebhookConfiguration,
        export_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send data portability webhook."""

    @abstractmethod
    async def send_consent_changed(
        self,
        webhook_config: WebhookConfiguration,
        consent_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send consent changed webhook."""

    @abstractmethod
    async def send_retention_policy_applied(
        self,
        webhook_config: WebhookConfiguration,
        retention_data: dict[str, Any],
        context: dict[str, Any]
    ) -> WebhookDelivery:
        """Send retention policy applied webhook."""


class WebhookDeliveryContract(ABC):
    """Contract for webhook delivery operations."""

    @abstractmethod
    async def deliver_webhook(
        self,
        webhook_config: WebhookConfiguration,
        event: WebhookEvent
    ) -> WebhookDelivery:
        """Deliver webhook to configured endpoint."""

    @abstractmethod
    async def retry_failed_webhook(
        self,
        delivery: WebhookDelivery
    ) -> WebhookDelivery:
        """Retry failed webhook delivery."""

    @abstractmethod
    async def generate_signature(
        self,
        payload: str,
        secret: str,
        method: WebhookSignatureMethod
    ) -> str:
        """Generate webhook signature."""

    @abstractmethod
    async def verify_signature(
        self,
        payload: str,
        signature: str,
        secret: str,
        method: WebhookSignatureMethod
    ) -> bool:
        """Verify webhook signature."""

    @abstractmethod
    async def validate_webhook_url(
        self,
        url: str
    ) -> bool:
        """Validate webhook URL."""

    @abstractmethod
    async def test_webhook_endpoint(
        self,
        webhook_config: WebhookConfiguration
    ) -> dict[str, Any]:
        """Test webhook endpoint connectivity."""

    @abstractmethod
    async def get_delivery_status(
        self,
        delivery_id: UUID
    ) -> WebhookDelivery | None:
        """Get webhook delivery status."""

    @abstractmethod
    async def get_delivery_history(
        self,
        webhook_id: UUID,
        limit: int = 100,
        offset: int = 0
    ) -> list[WebhookDelivery]:
        """Get webhook delivery history."""

    @abstractmethod
    async def get_failed_deliveries(
        self,
        webhook_id: UUID | None = None,
        limit: int = 100
    ) -> list[WebhookDelivery]:
        """Get failed webhook deliveries."""

    @abstractmethod
    async def requeue_failed_deliveries(
        self,
        webhook_id: UUID,
        max_age_hours: int = 24
    ) -> int:
        """Requeue failed deliveries for retry."""

    @abstractmethod
    async def move_to_dead_letter_queue(
        self,
        delivery: WebhookDelivery,
        reason: str
    ) -> None:
        """Move delivery to dead letter queue."""


class WebhookManagementContract(ABC):
    """Contract for webhook management operations."""

    @abstractmethod
    async def create_webhook(
        self,
        config: WebhookConfiguration
    ) -> UUID:
        """Create new webhook configuration."""

    @abstractmethod
    async def update_webhook(
        self,
        webhook_id: UUID,
        updates: dict[str, Any]
    ) -> bool:
        """Update webhook configuration."""

    @abstractmethod
    async def delete_webhook(
        self,
        webhook_id: UUID
    ) -> bool:
        """Delete webhook configuration."""

    @abstractmethod
    async def enable_webhook(
        self,
        webhook_id: UUID
    ) -> bool:
        """Enable webhook."""

    @abstractmethod
    async def disable_webhook(
        self,
        webhook_id: UUID
    ) -> bool:
        """Disable webhook."""

    @abstractmethod
    async def list_webhooks(
        self,
        filters: dict[str, Any] | None = None
    ) -> list[WebhookConfiguration]:
        """List webhook configurations."""

    @abstractmethod
    async def get_webhook(
        self,
        webhook_id: UUID
    ) -> WebhookConfiguration | None:
        """Get webhook configuration."""

    @abstractmethod
    async def test_webhook(
        self,
        webhook_id: UUID,
        test_event: WebhookEvent | None = None
    ) -> WebhookDelivery:
        """Test webhook with sample event."""

    @abstractmethod
    async def get_webhook_statistics(
        self,
        webhook_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get webhook delivery statistics."""

    @abstractmethod
    async def get_webhook_metrics(
        self,
        webhook_id: UUID,
        granularity: str = "hour"
    ) -> dict[str, Any]:
        """Get webhook performance metrics."""

    @abstractmethod
    async def rotate_webhook_secret(
        self,
        webhook_id: UUID
    ) -> str:
        """Rotate webhook secret."""
