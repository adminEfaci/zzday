"""
Internal DTOs for identity domain.

Defines comprehensive data structures for internal application layer communication,
including contexts for authentication, authorization, risk assessment, operations,
compliance, and system state management.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.modules.identity.domain.enums import (
    AuditAction,
    DevicePlatform,
    DeviceType,
    MFAMethod,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    SessionType,
)


@dataclass
class AuthenticationContext:
    """Internal authentication context."""
    user_id: UUID
    session_id: UUID
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    location: dict[str, Any] | None = None
    risk_score: float = 0.0
    mfa_verified: bool = False
    session_type: SessionType = SessionType.WEB
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationResult:
    """Internal authorization check result."""
    allowed: bool
    user_id: UUID
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None
    reason: str | None = None
    denial_code: str | None = None
    checked_at: datetime = field(default_factory=datetime.utcnow)
    cache_key: str | None = None
    cacheable: bool = True
    cache_ttl: int = 300  # 5 minutes


@dataclass
class RiskAssessmentResult:
    """Internal risk assessment result."""
    risk_score: float
    risk_level: RiskLevel
    risk_factors: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    requires_mfa: bool = False
    requires_additional_verification: bool = False
    should_notify_user: bool = False
    should_log_security_event: bool = False
    recommendations: list[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PasswordValidationResult:
    """Internal password validation result."""
    is_valid: bool
    strength_score: float
    entropy: float
    issues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    passed_criteria: set[str] = field(default_factory=set)
    failed_criteria: set[str] = field(default_factory=set)
    estimated_crack_time: str | None = None


@dataclass
class SessionCreationContext:
    """Context for session creation."""
    user_id: UUID
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    session_type: SessionType = SessionType.WEB
    risk_score: float = 0.0
    mfa_verified: bool = False
    remember_me: bool = False
    trusted_device: bool = False
    location: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenGenerationContext:
    """Context for token generation."""
    user_id: UUID
    session_id: UUID
    token_type: str  # 'access' or 'refresh'
    expires_in: timedelta
    scopes: list[str] = field(default_factory=list)
    claims: dict[str, Any] = field(default_factory=dict)
    audience: str | None = None
    issuer: str = "identity-service"


@dataclass
class EmailContext:
    """Context for email operations."""
    recipient: str
    template: str
    subject: str
    variables: dict[str, Any] = field(default_factory=dict)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    priority: str = "normal"  # low, normal, high
    retry_count: int = 3
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SMSContext:
    """Context for SMS operations."""
    recipient: str
    message: str
    message_type: str = "transactional"  # transactional, promotional
    priority: str = "normal"
    retry_count: int = 3
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditContext:
    """Context for audit operations."""
    action: AuditAction
    resource_type: str
    actor_id: UUID | None = None
    resource_id: str | None = None
    changes: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    session_id: UUID | None = None
    correlation_id: UUID | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityIncidentContext:
    """Context for security incidents."""
    incident_type: SecurityEventType
    severity: RiskLevel
    user_id: UUID | None = None
    ip_address: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    affected_resources: list[dict[str, Any]] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    auto_response: bool = True
    notify_user: bool = True
    notify_admins: bool = False


@dataclass
class BulkOperationContext:
    """Context for bulk operations."""
    operation_id: UUID
    operation_type: str
    target_ids: list[UUID]
    parameters: dict[str, Any] = field(default_factory=dict)
    actor_id: UUID | None = None
    reason: str | None = None
    dry_run: bool = False
    batch_size: int = 100
    parallel: bool = False
    stop_on_error: bool = True
    progress_callback: Callable | None = None


@dataclass
class CacheContext:
    """Context for caching operations."""
    key: str
    value: Any
    ttl: int | None = None  # seconds
    tags: list[str] = field(default_factory=list)
    invalidation_rules: list[str] = field(default_factory=list)
    compress: bool = False
    encrypt: bool = False


@dataclass
class EventContext:
    """Context for domain events."""
    event_id: UUID
    event_type: str
    aggregate_id: UUID
    aggregate_type: str
    data: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)
    correlation_id: UUID | None = None
    causation_id: UUID | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    version: int = 1


@dataclass
class PermissionEvaluationContext:
    """Context for permission evaluation."""
    user_id: UUID
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None
    action: str | None = None
    context_data: dict[str, Any] = field(default_factory=dict)
    inherit_from_roles: bool = True
    check_delegations: bool = True
    check_time_based: bool = True
    effective_date: datetime = field(default_factory=datetime.utcnow)


@dataclass
class UserMergeContext:
    """Context for user merge operations."""
    source_user_id: UUID
    target_user_id: UUID
    merge_strategy: str = "keep_target"  # keep_target, keep_source, newest, manual
    data_categories: list[str] = field(default_factory=list)
    conflict_resolution: dict[str, str] = field(default_factory=dict)
    preserve_history: bool = True
    notify_user: bool = True
    actor_id: UUID | None = None
    reason: str | None = None


@dataclass
class DataExportContext:
    """Context for data export operations."""
    user_id: UUID
    data_categories: list[str]
    format: str = "json"
    include_deleted: bool = False
    include_metadata: bool = True
    anonymize_pii: bool = False
    date_range: dict[str, datetime] | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    encryption_key: str | None = None


@dataclass
class ComplianceCheckContext:
    """Context for compliance checks."""
    check_type: str
    user_id: UUID | None = None
    regulations: list[str] = field(default_factory=list)
    data_categories: list[str] = field(default_factory=list)
    time_period: dict[str, datetime] | None = None
    include_recommendations: bool = True
    generate_report: bool = False


@dataclass
class DeviceRegistrationContext:
    """Context for device registration."""
    user_id: UUID
    device_fingerprint: str
    device_name: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    platform: DevicePlatform = DevicePlatform.UNKNOWN
    user_agent: str | None = None
    ip_address: str | None = None
    trust_immediately: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RateLimitContext:
    """Context for rate limiting."""
    key: str
    operation: str
    limit: int
    window_seconds: int
    current_count: int = 0
    first_request_at: datetime | None = None
    last_request_at: datetime | None = None
    blocked_until: datetime | None = None


class OperationStatus(Enum):
    """Status of an operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIALLY_COMPLETED = "partially_completed"


@dataclass
class OperationResult:
    """Result of an operation."""
    status: OperationStatus
    success_count: int = 0
    failure_count: int = 0
    skipped_count: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: Any | None = None
    duration_ms: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Enhanced Authentication & Session Contexts
# ============================================================================

@dataclass
class LoginAttemptContext:
    """Context for login attempt tracking."""
    ip_address: str
    user_agent: str
    user_id: UUID | None = None
    username: str | None = None
    email: str | None = None
    device_fingerprint: str | None = None
    location: dict[str, Any] | None = None
    attempt_time: datetime = field(default_factory=datetime.utcnow)
    success: bool = False
    failure_reason: str | None = None
    risk_indicators: list[str] = field(default_factory=list)
    requires_mfa: bool = False
    session_id: UUID | None = None


@dataclass
class SessionValidationContext:
    """Context for session validation."""
    session_id: UUID
    user_id: UUID
    ip_address: str
    user_agent: str
    validation_time: datetime = field(default_factory=datetime.utcnow)
    is_valid: bool = True
    validation_errors: list[str] = field(default_factory=list)
    remaining_lifetime: timedelta | None = None
    requires_refresh: bool = False
    requires_reauth: bool = False


@dataclass
class DeviceContext:
    """Enhanced device context for authentication."""
    device_fingerprint: str
    device_type: DeviceType
    platform: DevicePlatform
    browser: str | None = None
    browser_version: str | None = None
    os_version: str | None = None
    is_mobile: bool = False
    is_tablet: bool = False
    is_desktop: bool = True
    screen_resolution: str | None = None
    timezone: str | None = None
    language: str | None = None
    capabilities: list[str] = field(default_factory=list)


@dataclass
class LocationContext:
    """Location context for authentication."""
    ip_address: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    isp: str | None = None
    organization: str | None = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    threat_level: RiskLevel | None = None


# ============================================================================
# Enhanced Security & Risk Contexts
# ============================================================================

@dataclass
class ThreatIndicator:
    """Individual threat indicator."""
    indicator_type: str
    indicator_value: str
    severity: RiskLevel
    source: str
    confidence: float = 0.0
    detected_at: datetime = field(default_factory=datetime.utcnow)
    description: str | None = None
    recommendations: list[str] = field(default_factory=list)


@dataclass
class SecurityPolicyContext:
    """Security policy evaluation context."""
    policy_name: str
    policy_version: str
    evaluation_time: datetime = field(default_factory=datetime.utcnow)
    rules_evaluated: int = 0
    rules_passed: int = 0
    rules_failed: int = 0
    violations: list[dict[str, Any]] = field(default_factory=list)
    exemptions: list[str] = field(default_factory=list)
    enforcement_mode: str = "enforce"  # enforce, audit, disabled
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IncidentResponseContext:
    """Context for incident response."""
    incident_id: UUID
    incident_type: SecurityEventType
    severity: RiskLevel
    detected_at: datetime
    detection_method: str
    affected_entities: list[dict[str, Any]] = field(default_factory=list)
    containment_actions: list[dict[str, Any]] = field(default_factory=list)
    eradication_actions: list[dict[str, Any]] = field(default_factory=list)
    recovery_actions: list[dict[str, Any]] = field(default_factory=list)
    lessons_learned: list[str] = field(default_factory=list)
    status: str = "new"  # new, investigating, contained, eradicated, recovered, closed
    responder_id: UUID | None = None
    escalated: bool = False
    external_ticket: str | None = None


@dataclass
class AnomalyDetectionContext:
    """Context for anomaly detection."""
    user_id: UUID
    anomaly_type: str
    baseline_value: float
    observed_value: float
    deviation: float
    detection_algorithm: str
    time_window: timedelta
    historical_data_points: int
    z_score: float | None = None
    confidence: float = 0.0
    is_anomaly: bool = False
    severity: RiskLevel | None = None
    recommendations: list[str] = field(default_factory=list)


# ============================================================================
# Enhanced Authorization & Permission Contexts
# ============================================================================

@dataclass
class RoleHierarchyContext:
    """Context for role hierarchy evaluation."""
    role_id: UUID
    role_name: str
    parent_roles: list[UUID] = field(default_factory=list)
    child_roles: list[UUID] = field(default_factory=list)
    inherited_permissions: set[str] = field(default_factory=set)
    direct_permissions: set[str] = field(default_factory=set)
    effective_permissions: set[str] = field(default_factory=set)
    hierarchy_depth: int = 0
    circular_reference_check: bool = True
    max_hierarchy_depth: int = 10


@dataclass
class PermissionCondition:
    """Condition for conditional permissions."""
    condition_type: str  # time_based, location_based, attribute_based, etc.
    condition_expression: str
    parameters: dict[str, Any] = field(default_factory=dict)
    evaluation_result: bool | None = None
    evaluated_at: datetime | None = None
    cache_key: str | None = None
    cacheable: bool = True
    cache_ttl: int = 300


@dataclass
class DelegationContext:
    """Context for permission delegation."""
    delegation_id: UUID
    delegator_id: UUID
    delegate_id: UUID
    permissions: list[str]
    start_date: datetime
    end_date: datetime
    resource_type: str | None = None
    resource_ids: list[str] = field(default_factory=list)
    conditions: list[PermissionCondition] = field(default_factory=list)
    can_sub_delegate: bool = False
    max_delegation_depth: int = 1
    current_depth: int = 0
    usage_count: int = 0
    max_usage: int | None = None
    revoked: bool = False
    revoked_at: datetime | None = None
    revoked_by: UUID | None = None
    revocation_reason: str | None = None


@dataclass
class ResourceAccessContext:
    """Context for resource access control."""
    resource_type: str
    resource_id: str
    access_level: str  # read, write, admin, custom
    sharing_level: str  # private, team, organization, public
    resource_owner: UUID | None = None
    access_control_list: list[dict[str, Any]] = field(default_factory=list)
    inherited_permissions: bool = True
    custom_permissions: list[str] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    audit_access: bool = True
    encrypt_at_rest: bool = True
    classification: str = "internal"  # public, internal, confidential, secret


# ============================================================================
# Enhanced MFA & Authentication Method Contexts
# ============================================================================

@dataclass
class MFAVerificationContext:
    """Context for MFA verification."""
    user_id: UUID
    method: MFAMethod
    challenge_id: UUID
    challenge_issued_at: datetime
    challenge_expires_at: datetime
    device_id: UUID | None = None
    verification_attempts: int = 0
    max_attempts: int = 3
    verified: bool = False
    verified_at: datetime | None = None
    trust_device: bool = False
    trust_duration: timedelta | None = None
    backup_code_used: bool = False
    risk_context: RiskAssessmentResult | None = None


@dataclass
class BiometricContext:
    """Context for biometric authentication."""
    user_id: UUID
    biometric_type: str  # fingerprint, face, iris, voice
    device_id: UUID
    template_id: UUID
    enrolled_at: datetime
    match_score: float = 0.0
    threshold: float = 0.95
    liveness_check: bool = True
    liveness_score: float | None = None
    anti_spoofing_check: bool = True
    quality_score: float | None = None
    last_used: datetime | None = None
    update_required: bool = False


# ============================================================================
# Enhanced Emergency & Recovery Contexts
# ============================================================================

@dataclass
class AccountRecoveryContext:
    """Context for account recovery."""
    user_id: UUID
    recovery_method: str  # email, sms, emergency_contact, security_questions
    recovery_token: str
    token_expires_at: datetime
    recovery_initiated_at: datetime
    ip_address: str
    user_agent: str
    verification_attempts: int = 0
    max_attempts: int = 3
    verified_identity: bool = False
    identity_verification_methods: list[str] = field(default_factory=list)
    recovery_completed_at: datetime | None = None
    risk_assessment: RiskAssessmentResult | None = None
    requires_admin_approval: bool = False
    admin_approved: bool = False
    approved_by: UUID | None = None


@dataclass
class EmergencyAccessContext:
    """Context for emergency access by contacts."""
    emergency_contact_id: UUID
    user_id: UUID
    access_reason: str
    access_type: str  # view_only, takeover, medical_emergency
    verification_method: str
    verified: bool = False
    access_granted_at: datetime | None = None
    access_expires_at: datetime | None = None
    accessed_resources: list[dict[str, Any]] = field(default_factory=list)
    restrictions: list[str] = field(default_factory=list)
    audit_trail: list[dict[str, Any]] = field(default_factory=list)
    notification_sent: bool = False
    user_acknowledged: bool = False


# ============================================================================
# Enhanced Compliance & Privacy Contexts
# ============================================================================

@dataclass
class ConsentContext:
    """Context for consent management."""
    user_id: UUID
    consent_type: str
    purpose: str
    data_categories: list[str]
    processing_activities: list[str]
    lawful_basis: str  # consent, contract, legal_obligation, etc.
    controller: str
    processors: list[str] = field(default_factory=list)
    retention_period: timedelta | None = None
    granted: bool = False
    granted_at: datetime | None = None
    withdrawn: bool = False
    withdrawn_at: datetime | None = None
    version: str = "1.0"
    parent_consent: UUID | None = None  # For minors
    special_categories: list[str] = field(default_factory=list)  # Sensitive data
    third_party_sharing: bool = False
    international_transfer: bool = False


@dataclass
class DataRetentionContext:
    """Context for data retention policies."""
    data_category: str
    retention_period: timedelta
    retention_basis: str  # legal_requirement, business_need, user_consent
    deletion_method: str  # soft_delete, anonymize, hard_delete
    review_period: timedelta
    last_reviewed: datetime
    next_review: datetime
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    legal_holds: list[dict[str, Any]] = field(default_factory=list)
    automated_deletion: bool = True
    deletion_verification: bool = True
    backup_retention: timedelta | None = None


@dataclass
class PrivacyImpactContext:
    """Context for privacy impact assessments."""
    assessment_id: UUID
    data_processing_activity: str
    data_categories: list[str]
    purposes: list[str]
    necessity_assessment: dict[str, Any]
    proportionality_assessment: dict[str, Any]
    risk_assessment: dict[str, Any]
    mitigation_measures: list[dict[str, Any]]
    residual_risks: list[dict[str, Any]]
    review_date: datetime
    next_review: datetime
    dpo_review: bool = False
    dpo_approved: bool = False
    version: str = "1.0"


# ============================================================================
# Enhanced Integration & Sync Contexts
# ============================================================================

@dataclass
class SystemIntegrationContext:
    """Context for system integration."""
    integration_id: UUID
    system_name: str
    system_type: str  # ldap, saml, oauth, api, webhook
    connection_status: str  # connected, disconnected, error
    data_flow_direction: str  # inbound, outbound, bidirectional
    conflict_resolution: str  # source_wins, target_wins, newest_wins, manual
    last_sync: datetime | None = None
    next_sync: datetime | None = None
    sync_frequency: timedelta | None = None
    field_mappings: dict[str, str] = field(default_factory=dict)
    transformation_rules: list[dict[str, Any]] = field(default_factory=list)
    error_count: int = 0
    success_count: int = 0
    last_error: dict[str, Any] | None = None


@dataclass
class DataSyncContext:
    """Context for data synchronization."""
    sync_id: UUID
    source_system: str
    target_system: str
    entity_type: str
    entity_id: str
    sync_direction: str  # push, pull, bidirectional
    sync_status: str  # pending, in_progress, completed, failed
    resolution_strategy: str
    changes_detected: list[dict[str, Any]] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    dry_run: bool = False
    force_update: bool = False
    create_if_missing: bool = True
    delete_if_removed: bool = False
    sync_metadata: dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Enhanced Monitoring & Analytics Contexts
# ============================================================================

@dataclass
class MetricsContext:
    """Context for metrics collection."""
    metric_name: str
    metric_type: str  # counter, gauge, histogram, summary
    value: float
    unit: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    aggregation_period: timedelta | None = None
    percentiles: list[float] | None = None
    sample_rate: float = 1.0
    namespace: str = "identity"


@dataclass
class AnalyticsContext:
    """Context for analytics tracking."""
    event_name: str
    event_category: str
    user_id: UUID | None = None
    session_id: UUID | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    user_properties: dict[str, Any] = field(default_factory=dict)
    device_properties: dict[str, Any] = field(default_factory=dict)
    location_properties: dict[str, Any] = field(default_factory=dict)
    referrer: str | None = None
    utm_parameters: dict[str, str] = field(default_factory=dict)
    experiment_ids: list[str] = field(default_factory=list)
    revenue: float | None = None
    currency: str | None = None


@dataclass
class PerformanceContext:
    """Context for performance monitoring."""
    operation_name: str
    start_time: datetime
    trace_id: UUID
    span_id: UUID
    end_time: datetime | None = None
    duration_ms: int | None = None
    success: bool = True
    error: str | None = None
    parent_span_id: UUID | None = None
    tags: dict[str, Any] = field(default_factory=dict)
    baggage: dict[str, Any] = field(default_factory=dict)
    critical_path: bool = False
    sla_target_ms: int | None = None
    sla_met: bool | None = None


# ============================================================================
# Notification & Communication Contexts
# ============================================================================

@dataclass
class NotificationContext:
    """Context for notifications."""
    notification_id: UUID
    recipient_id: UUID
    notification_type: NotificationType
    channel: str  # email, sms, push, in_app
    template_id: str
    template_data: dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"  # low, normal, high, urgent
    scheduled_at: datetime | None = None
    sent_at: datetime | None = None
    delivered_at: datetime | None = None
    read_at: datetime | None = None
    retry_count: int = 0
    max_retries: int = 3
    expires_at: datetime | None = None
    deduplication_key: str | None = None
    batch_id: UUID | None = None
    tracking_enabled: bool = True


@dataclass
class CommunicationPreferenceContext:
    """Context for communication preferences."""
    user_id: UUID
    channel_preferences: dict[str, dict[str, bool]] = field(default_factory=dict)
    frequency_limits: dict[str, int] = field(default_factory=dict)
    quiet_hours: dict[str, str] | None = None
    language: str = "en"
    timezone: str = "UTC"
    opt_out_all: bool = False
    opt_out_categories: list[str] = field(default_factory=list)
    double_opt_in_required: bool = False
    verified_channels: dict[str, bool] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# Workflow & Orchestration Contexts
# ============================================================================

@dataclass
class WorkflowContext:
    """Context for workflow execution."""
    workflow_id: UUID
    workflow_name: str
    workflow_version: str
    instance_id: UUID
    current_step: str
    started_at: datetime
    completed_steps: list[str] = field(default_factory=list)
    pending_steps: list[str] = field(default_factory=list)
    step_results: dict[str, Any] = field(default_factory=dict)
    workflow_data: dict[str, Any] = field(default_factory=dict)
    completed_at: datetime | None = None
    status: str = "running"  # running, completed, failed, cancelled
    error: str | None = None
    retry_count: int = 0
    parent_workflow_id: UUID | None = None
    child_workflow_ids: list[UUID] = field(default_factory=list)


@dataclass
class TaskContext:
    """Context for background task execution."""
    task_id: UUID
    task_name: str
    task_type: str  # immediate, scheduled, recurring
    priority: int = 5  # 1-10, higher is more important
    scheduled_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    result: Any | None = None
    error: str | None = None
    status: str = "pending"  # pending, running, completed, failed, cancelled
    idempotency_key: str | None = None
    depends_on: list[UUID] = field(default_factory=list)


# ============================================================================
# Feature Management Contexts
# ============================================================================

@dataclass
class FeatureFlagContext:
    """Context for feature flag evaluation."""
    flag_name: str
    user_id: UUID | None = None
    default_value: bool = False
    evaluation_context: dict[str, Any] = field(default_factory=dict)
    rollout_percentage: float = 0.0
    enabled_for_users: list[UUID] = field(default_factory=list)
    disabled_for_users: list[UUID] = field(default_factory=list)
    conditions: list[dict[str, Any]] = field(default_factory=list)
    variant: str | None = None
    variants: dict[str, float] = field(default_factory=dict)
    stickiness: str | None = None  # user_id, session_id, random
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    evaluation_reason: str | None = None


@dataclass
class ExperimentContext:
    """Context for A/B testing."""
    experiment_id: UUID
    experiment_name: str
    user_id: UUID
    variant_assigned: str
    enrollment_date: datetime
    variant_config: dict[str, Any] = field(default_factory=dict)
    control_group: bool = False
    conversion_events: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    excluded: bool = False
    exclusion_reason: str | None = None
    forced_variant: str | None = None