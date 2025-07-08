"""
Data Transfer Objects for administrative operations.

Contains configuration and parameter objects to reduce function argument counts
and improve maintainability of administrative commands.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AnonymizationConfig:
    """Configuration for data anonymization operations."""
    
    data_categories: list[str]
    anonymization_level: str  # AnonymizationLevel enum value
    reason: str
    retain_for_legal: bool = False
    legal_retention_days: int | None = None
    create_backup: bool = True
    notify_user: bool = True
    immediate_deletion: bool = False
    custom_rules: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdminContext:
    """Context information for administrative operations."""
    
    admin_user_id: UUID
    target_user_id: UUID
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BulkOperationConfig:
    """Configuration for bulk operations."""
    
    operation_type: str  # BulkOperationType enum value
    target_user_ids: list[UUID]
    parameters: dict[str, Any]
    reason: str
    dry_run: bool = False
    batch_size: int = 100
    parallel_execution: bool = False
    stop_on_error: bool = True
    rollback_on_failure: bool = True
    notify_affected_users: bool = True
    schedule_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExportConfig:
    """Configuration for data export operations."""
    
    export_format: str
    include_categories: list[str]
    include_audit_logs: bool = True
    include_sessions: bool = True
    include_permissions: bool = True
    include_devices: bool = True
    include_integrations: bool = True
    compress_output: bool = True
    encrypt_output: bool = True
    retention_days: int = 30
    auto_delete: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NotificationConfig:
    """Configuration for administrative notifications."""
    
    notify_user: bool = True
    notify_compliance: bool = True
    notify_admin: bool = True
    email_template: str | None = None
    custom_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ImpersonationConfig:
    """Configuration for user impersonation."""
    
    duration_minutes: int
    allowed_actions: list[str]
    reason: str
    audit_level: str = "detailed"
    require_justification: bool = True
    auto_terminate: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MaintenanceConfig:
    """Configuration for system maintenance operations."""
    
    maintenance_type: str
    affected_components: list[str]
    estimated_duration_minutes: int
    reason: str
    downtime_required: bool = False
    backup_before: bool = True
    notify_users: bool = True
    rollback_plan: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StatusUpdateConfig:
    """Configuration for user status updates."""
    
    new_status: str  # UserStatus enum value
    reason: str
    effective_immediately: bool = True
    send_notification: bool = True
    create_audit_trail: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PurgeConfig:
    """Configuration for user data purging."""
    
    purge_criteria: dict[str, Any]
    include_soft_deleted: bool = True
    include_permanently_deleted: bool = False
    retention_period_days: int = 2555  # 7 years
    create_audit_record: bool = True
    notify_compliance: bool = True
    dry_run: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceDependencies:
    """Common service dependencies for administrative operations."""
    
    user_repository: Any  # IUserRepository
    audit_repository: Any | None = None
    session_repository: Any | None = None
    notification_repository: Any | None = None
    token_repository: Any | None = None
    device_repository: Any | None = None
    profile_repository: Any | None = None
    registration_attempt_repository: Any | None = None
    authorization_service: Any | None = None
    security_service: Any | None = None
    data_privacy_service: Any | None = None
    email_service: Any | None = None
    backup_service: Any | None = None
    cache_service: Any | None = None
    validation_service: Any | None = None
    notification_service: Any | None = None
    storage_service: Any | None = None
    encryption_service: Any | None = None
    queue_service: Any | None = None
    session_service: Any | None = None
    token_service: Any | None = None
    audit_service: Any | None = None
    metrics_service: Any | None = None
    geolocation_service: Any | None = None
    referral_service: Any | None = None
    password_service: Any | None = None
    risk_assessment_service: Any | None = None
    email_verification_service: Any | None = None
    login_attempt_repository: Any | None = None
    mfa_device_repository: Any | None = None
    social_account_repository: Any | None = None
    social_auth_service: Any | None = None


@dataclass(frozen=True)
class InfrastructureDependencies:
    """Common infrastructure dependencies."""
    
    event_bus: Any  # EventBus
    unit_of_work: Any  # UnitOfWork


# Authentication-specific DTOs
@dataclass(frozen=True)
class AuthenticationConfig:
    """Configuration for authentication operations."""
    
    remember_me: bool = False
    trusted_device: bool = False
    require_mfa: bool = False
    session_timeout_minutes: int = 30
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionContext:
    """Session context for authentication operations."""
    
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    geolocation: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RegistrationConfig:
    """Configuration for user registration."""
    
    email: str
    username: str
    password: str
    first_name: str | None = None
    last_name: str | None = None
    phone_number: str | None = None
    auto_verify: bool = False
    send_welcome_email: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SocialAuthConfig:
    """Configuration for social authentication."""
    
    provider: str  # AuthProvider enum value
    access_token: str
    provider_user_id: str
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    profile_picture_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)