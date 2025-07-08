"""
Response DTOs for identity domain.

Defines comprehensive data structures for all outgoing responses including user management,
authentication, authorization, MFA, sessions, emergency contacts, administration,
security, devices, integration operations, and system status.
"""

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field, HttpUrl
from pydantic.generics import GenericModel

from app.modules.identity.domain.entities.user.user_enums import Relationship
from app.modules.identity.domain.enums import (
    AuditAction,
    DevicePlatform,
    DeviceType,
    MFAMethod,
    NotificationType,
    PermissionScope,
    RiskLevel,
    SecurityEventType,
    SessionType,
    UserRole,
    UserStatus,
)

T = TypeVar('T')


# Base response DTOs
class BaseResponse(BaseModel):
    """Base response with common fields."""
    success: bool = Field(True, description="Whether the operation succeeded")
    message: str | None = Field(None, description="Human-readable message")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: UUID | None = Field(None, description="Original request ID")
    correlation_id: UUID | None = Field(None, description="Correlation ID for tracing")


class ErrorResponse(BaseResponse):
    """Error response structure."""
    success: bool = Field(False)
    error_code: str = Field(..., description="Machine-readable error code")
    error_details: dict[str, Any] | None = Field(None)
    field_errors: dict[str, list[str]] | None = Field(None)


class PagedResponse(GenericModel, Generic[T]):
    """Paged response for list operations."""
    items: list[T] = Field(..., description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_previous: bool = Field(..., description="Whether there is a previous page")


# User management responses
class UserResponse(BaseModel):
    """User information response."""
    id: UUID
    username: str
    email: str
    email_verified: bool
    status: UserStatus
    first_name: str | None = None
    last_name: str | None = None
    avatar_url: str | None = None
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None


class UserDetailResponse(UserResponse):
    """Detailed user information response."""
    roles: list['RoleResponse'] = Field(default_factory=list)
    permissions: list['PermissionResponse'] = Field(default_factory=list)
    profile_completion: float = Field(0.0, ge=0.0, le=1.0)
    mfa_enabled: bool = False
    active_sessions: int = 0
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] | None = None


class UserProfileResponse(BaseModel):
    """User profile response."""
    id: UUID
    user_id: UUID
    bio: str | None = None
    date_of_birth: datetime | None = None
    gender: str | None = None
    language: str = "en"
    timezone: str = "UTC"
    preferences: dict[str, Any] = Field(default_factory=dict)
    social_links: dict[str, str] = Field(default_factory=dict)
    completion_percentage: float
    updated_at: datetime


class CreateUserResponse(BaseResponse):
    """Response for user creation."""
    user_id: UUID
    username: str
    email: str
    email_verification_required: bool
    email_verification_sent: bool


# Authentication responses
class LoginResponse(BaseResponse):
    """Response for successful login."""
    user_id: UUID
    session_id: UUID
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # Seconds
    expires_at: datetime
    requires_mfa: bool = False
    mfa_methods: list[MFAMethod] | None = None


class MFAChallengeResponse(BaseResponse):
    """Response when MFA is required."""
    session_id: UUID
    challenge_id: UUID
    available_methods: list[MFAMethod]
    preferred_method: MFAMethod | None = None
    expires_at: datetime


class RefreshTokenResponse(BaseResponse):
    """Response for token refresh."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    expires_at: datetime


class PasswordResetResponse(BaseResponse):
    """Response for password reset request."""
    reset_requested: bool
    email_sent: bool
    expires_at: datetime


# MFA responses
class MFASetupResponse(BaseResponse):
    """Response for MFA setup initiation."""
    device_id: UUID
    secret: str | None = None  # For TOTP
    qr_code: str | None = None  # Base64 encoded QR for TOTP
    backup_codes: list[str] | None = None
    verification_required: bool = True


class MFADeviceResponse(BaseModel):
    """MFA device information."""
    id: UUID
    name: str
    method: MFAMethod
    is_primary: bool
    is_verified: bool
    created_at: datetime
    last_used_at: datetime | None = None
    
    
class MFAStatusResponse(BaseResponse):
    """MFA status for user."""
    mfa_enabled: bool
    devices: list[MFADeviceResponse]
    backup_codes_count: int
    last_backup_code_generation: datetime | None = None


# Session responses
class SessionResponse(BaseModel):
    """Session information."""
    id: UUID
    session_type: SessionType
    ip_address: str
    user_agent: str
    location: dict[str, str] | None = None
    device_info: dict[str, Any] | None = None
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime
    is_current: bool = False


class ActiveSessionsResponse(BaseResponse):
    """Active sessions response."""
    sessions: list[SessionResponse]
    total: int
    current_session_id: UUID


# Permission and role responses
class PermissionResponse(BaseModel):
    """Permission information."""
    id: UUID
    name: str
    resource: str
    action: str
    scope: PermissionScope
    description: str | None = None


class RoleResponse(BaseModel):
    """Role information."""
    id: UUID
    name: str
    description: str | None = None
    priority: int
    permissions_count: int
    is_system: bool = False
    created_at: datetime


class RoleDetailResponse(RoleResponse):
    """Detailed role information."""
    permissions: list[PermissionResponse]
    parent_role: Optional['RoleResponse'] = None
    child_roles: list['RoleResponse'] = Field(default_factory=list)


class PermissionCheckResponse(BaseResponse):
    """Permission check result."""
    allowed: bool
    user_id: UUID
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None
    reason: str | None = None
    denial_code: str | None = None


# Audit responses
class AuditLogResponse(BaseModel):
    """Audit log entry."""
    id: UUID
    actor_id: UUID | None = None
    actor_username: str | None = None
    action: AuditAction
    resource_type: str
    resource_id: str | None = None
    changes: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    success: bool
    error_message: str | None = None
    created_at: datetime


class AuditLogDetailResponse(AuditLogResponse):
    """Detailed audit log entry."""
    request_data: dict[str, Any] | None = None
    response_data: dict[str, Any] | None = None
    duration_ms: int | None = None
    metadata: dict[str, Any] | None = None


# Security responses
class SecurityEventResponse(BaseModel):
    """Security event information."""
    id: UUID
    event_type: SecurityEventType
    severity: RiskLevel
    user_id: UUID | None = None
    ip_address: str | None = None
    details: dict[str, Any]
    created_at: datetime
    resolved: bool = False
    resolved_at: datetime | None = None


class RiskAssessmentResponse(BaseResponse):
    """Risk assessment result."""
    user_id: UUID
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: RiskLevel
    risk_factors: list[str]
    recommendations: list[str]
    requires_action: bool
    assessed_at: datetime


class UserSecurityProfileResponse(BaseResponse):
    """User security profile."""
    user_id: UUID
    trust_score: float = Field(..., ge=0.0, le=1.0)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    account_age_days: int
    mfa_enabled: bool
    recent_suspicious_activities: int
    failed_login_attempts: int
    unusual_activity_detected: bool
    last_security_review: datetime | None = None


# Emergency contact responses
class EmergencyContactResponse(BaseModel):
    """Emergency contact information."""
    id: UUID
    name: str
    relationship: Relationship
    phone_number: str
    email: str | None = None
    is_primary: bool
    is_verified: bool
    verified_at: datetime | None = None
    created_at: datetime


# Compliance responses
class DataExportResponse(BaseResponse):
    """Data export response (GDPR)."""
    export_id: UUID
    user_id: UUID
    data_categories: list[str]
    format: str
    file_size_bytes: int
    download_url: str
    expires_at: datetime
    created_at: datetime


class ComplianceReportResponse(BaseResponse):
    """Compliance report response."""
    report_id: UUID
    report_type: str
    period_start: datetime
    period_end: datetime
    regulations: list[str]
    summary: dict[str, Any]
    issues_found: int
    download_url: str | None = None
    generated_at: datetime


# Statistics responses
class UserStatisticsResponse(BaseResponse):
    """User statistics response."""
    total_users: int
    active_users: int
    new_users_today: int
    new_users_this_week: int
    new_users_this_month: int
    users_by_status: dict[str, int]
    users_by_role: dict[str, int]
    mfa_adoption_rate: float
    average_session_duration_minutes: float


class SecurityStatisticsResponse(BaseResponse):
    """Security statistics response."""
    total_login_attempts: int
    successful_logins: int
    failed_logins: int
    login_success_rate: float
    active_sessions: int
    security_events_today: int
    high_risk_users: int
    mfa_challenges_today: int
    account_lockouts: int


# System responses
class HealthCheckResponse(BaseResponse):
    """System health check response."""
    service: str = "identity"
    version: str
    status: str = "healthy"
    uptime_seconds: int
    checks: dict[str, dict[str, Any]]


class FeatureFlagsResponse(BaseResponse):
    """Feature flags response."""
    flags: dict[str, bool]
    user_specific_flags: dict[str, bool] | None = None


# Update model forward references
UserDetailResponse.update_forward_refs()
RoleDetailResponse.update_forward_refs()


# ============================================================================
# Enhanced User Management Response DTOs
# ============================================================================

class UserSummaryResponse(BaseModel):
    """Minimal user information for lists."""
    id: UUID
    username: str
    email: str
    first_name: str | None = None
    last_name: str | None = None
    full_name: str | None = None
    avatar_url: str | None = None
    status: UserStatus
    role: UserRole
    last_login_at: datetime | None = None
    created_at: datetime


class UserActivityResponse(BaseModel):
    """User activity summary."""
    user_id: UUID
    login_count_today: int = 0
    login_count_week: int = 0
    login_count_month: int = 0
    failed_login_attempts: int = 0
    password_changes: int = 0
    profile_updates: int = 0
    security_events: int = 0
    last_activity: datetime | None = None
    most_used_device: str | None = None
    most_common_location: str | None = None
    activity_trend: str = "normal"  # normal, increasing, decreasing
    risk_indicators: list[str] = Field(default_factory=list)


class UserPreferencesResponse(BaseModel):
    """User preferences response."""
    user_id: UUID
    notifications: dict[str, bool] = Field(default_factory=dict)
    ui_theme: str = "light"
    language: str = "en"
    timezone: str = "UTC"
    date_format: str = "YYYY-MM-DD"
    time_format: str = "24h"
    privacy: dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime


class ProfileCompletionResponse(BaseModel):
    """Profile completion status."""
    user_id: UUID
    completion_percentage: float
    completed_fields: list[str] = Field(default_factory=list)
    missing_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)
    recommendations: list[dict[str, str]] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class AvatarResponse(BaseModel):
    """Avatar operation response."""
    avatar_id: UUID
    avatar_url: HttpUrl
    thumbnail_url: HttpUrl
    format: str
    size_bytes: int
    width: int
    height: int
    created_at: datetime


# ============================================================================
# Enhanced Authentication Response DTOs
# ============================================================================

class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int  # seconds
    expires_at: datetime
    scope: str | None = None
    issued_at: datetime = Field(default_factory=datetime.utcnow)


class AuthenticationResponse(BaseResponse):
    """Enhanced authentication response."""
    user: UserDetailResponse
    tokens: TokenResponse
    session: SessionResponse
    requires_mfa: bool = False
    mfa_challenge: MFAChallengeResponse | None = None
    requires_password_change: bool = False
    requires_terms_acceptance: bool = False
    login_url: HttpUrl | None = None


class SocialAuthResponse(BaseResponse):
    """Social authentication response."""
    provider: str
    is_new_user: bool
    user: UserDetailResponse
    tokens: TokenResponse
    linked_accounts: list[str] = Field(default_factory=list)
    profile_imported: bool = False


class EmailVerificationResponse(BaseResponse):
    """Email verification response."""
    email: str
    verified: bool
    verified_at: datetime | None = None
    user_id: UUID | None = None
    next_steps: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced Password Response DTOs
# ============================================================================

class PasswordStrengthResponse(BaseModel):
    """Password strength analysis."""
    score: int = Field(..., ge=0, le=100)
    strength: str  # very_weak, weak, medium, strong, very_strong
    entropy: float
    estimated_crack_time: str
    passed_requirements: list[str] = Field(default_factory=list)
    failed_requirements: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    contains_common_patterns: bool = False
    contains_user_info: bool = False
    previously_used: bool = False
    breached: bool = False


class PasswordPolicyResponse(BaseModel):
    """Password policy configuration."""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    min_unique_chars: int = 4
    password_history_count: int = 5
    expiry_days: int | None = None
    prevent_user_info_in_password: bool = True
    check_pwned_passwords: bool = True
    custom_rules: list[dict[str, Any]] = Field(default_factory=list)


class PasswordBreachCheckResponse(BaseResponse):
    """Password breach check result."""
    breached: bool
    breach_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    severity: str = "none"  # none, low, medium, high, critical
    recommendations: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced MFA Response DTOs
# ============================================================================

class MFAMethodResponse(BaseModel):
    """MFA method details."""
    method: MFAMethod
    enabled: bool
    configured: bool
    is_primary: bool = False
    last_used: datetime | None = None
    device_count: int = 0


class MFABackupCodesResponse(BaseResponse):
    """MFA backup codes response."""
    codes: list[str] = Field(..., min_items=5, max_items=20)
    generated_at: datetime
    expires_at: datetime | None = None
    download_url: HttpUrl | None = None
    print_url: HttpUrl | None = None
    remaining_uses: dict[str, int] = Field(default_factory=dict)


class MFARecoveryResponse(BaseResponse):
    """MFA recovery response."""
    recovery_id: UUID
    recovery_method: str
    status: str  # pending, verified, completed, failed
    expires_at: datetime
    next_steps: list[str] = Field(default_factory=list)
    alternative_methods: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced Session Response DTOs
# ============================================================================

class SessionDetailResponse(SessionResponse):
    """Detailed session information."""
    risk_assessment: RiskAssessmentResponse
    activity_summary: dict[str, Any] = Field(default_factory=dict)
    security_events: list[SecurityEventResponse] = Field(default_factory=list)
    permissions_snapshot: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionTransferResponse(BaseResponse):
    """Session transfer response."""
    old_session_id: UUID
    new_session_id: UUID
    transfer_token: str
    expires_at: datetime
    verification_required: bool = True
    verification_methods: list[str] = Field(default_factory=list)


class ConcurrentSessionsResponse(BaseResponse):
    """Concurrent sessions information."""
    user_id: UUID
    active_sessions: int
    max_allowed: int
    sessions_by_type: dict[str, int] = Field(default_factory=dict)
    sessions_by_location: dict[str, int] = Field(default_factory=dict)
    oldest_session: SessionResponse | None = None
    newest_session: SessionResponse | None = None
    requires_action: bool = False
    recommended_action: str | None = None


# ============================================================================
# Enhanced Emergency Contact Response DTOs
# ============================================================================

class EmergencyContactDetailResponse(EmergencyContactResponse):
    """Detailed emergency contact information."""
    verification_history: list[dict[str, Any]] = Field(default_factory=list)
    notification_preferences: dict[str, bool] = Field(default_factory=dict)
    last_notified: datetime | None = None
    can_access_medical_info: bool = False
    authorized_actions: list[str] = Field(default_factory=list)


class ContactVerificationResponse(BaseResponse):
    """Contact verification response."""
    contact_id: UUID
    verification_method: str
    verified: bool
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    attempts_remaining: int = 3


class BulkContactImportResponse(BaseResponse):
    """Bulk contact import response."""
    total_contacts: int
    imported: int
    failed: int
    duplicates: int
    errors: list[dict[str, Any]] = Field(default_factory=list)
    imported_contact_ids: list[UUID] = Field(default_factory=list)


# ============================================================================
# Enhanced Administrative Response DTOs
# ============================================================================

class UserStatusUpdateResponse(BaseResponse):
    """User status update response."""
    user_id: UUID
    old_status: UserStatus
    new_status: UserStatus
    effective_date: datetime
    reason: str
    affected_sessions: int = 0
    notifications_sent: list[str] = Field(default_factory=list)


class ImpersonationResponse(BaseResponse):
    """Impersonation session response."""
    impersonation_id: UUID
    actor_id: UUID
    target_user_id: UUID
    session_id: UUID
    expires_at: datetime
    allowed_actions: list[str] = Field(default_factory=list)
    restricted_actions: list[str] = Field(default_factory=list)
    audit_trail_id: UUID


class BulkOperationResponse(BaseResponse):
    """Bulk operation response."""
    operation_id: UUID
    operation_type: str
    total_items: int
    successful: int
    failed: int
    skipped: int
    results: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    completed_at: datetime | None = None
    report_url: HttpUrl | None = None


class UserDataExportResponse(BaseResponse):
    """User data export response."""
    export_id: UUID
    user_id: UUID
    format: str
    status: str  # pending, processing, completed, failed
    progress: float = Field(0.0, ge=0.0, le=100.0)
    file_size_bytes: int | None = None
    download_url: HttpUrl | None = None
    expires_at: datetime | None = None
    includes: list[str] = Field(default_factory=list)


class DataAnonymizationResponse(BaseResponse):
    """Data anonymization response."""
    user_id: UUID
    anonymization_id: UUID
    data_categories: list[str]
    status: str
    anonymized_fields: list[str] = Field(default_factory=list)
    retained_fields: list[str] = Field(default_factory=list)
    completion_date: datetime | None = None
    certificate_url: HttpUrl | None = None


class SystemMaintenanceResponse(BaseResponse):
    """System maintenance response."""
    maintenance_id: UUID
    operation: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    affected_records: int = 0
    cleaned_up: int = 0
    errors: list[dict[str, Any]] = Field(default_factory=list)
    next_maintenance: datetime | None = None


# ============================================================================
# Enhanced Authorization Response DTOs
# ============================================================================

class RoleAssignmentResponse(BaseResponse):
    """Role assignment response."""
    user_id: UUID
    role_id: UUID
    role_name: str
    assigned_by: UUID
    assigned_at: datetime
    expires_at: datetime | None = None
    inherited_permissions: list[str] = Field(default_factory=list)
    effective_permissions: list[str] = Field(default_factory=list)


class PermissionGrantResponse(BaseResponse):
    """Permission grant response."""
    user_id: UUID
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None
    granted_by: UUID
    granted_at: datetime
    expires_at: datetime | None = None
    conditions: dict[str, Any] | None = None
    scope: PermissionScope


class PermissionMatrixResponse(BaseResponse):
    """Permission matrix response."""
    roles: list[RoleResponse]
    permissions: list[PermissionResponse]
    matrix: dict[str, dict[str, bool]]  # role_id -> permission -> granted
    effective_permissions_by_user: dict[UUID, list[str]] | None = None


class PermissionDelegationResponse(BaseResponse):
    """Permission delegation response."""
    delegation_id: UUID
    from_user_id: UUID
    to_user_id: UUID
    permission: str
    resource_type: str | None = None
    resource_id: str | None = None
    can_sub_delegate: bool
    delegated_at: datetime
    expires_at: datetime
    conditions: dict[str, Any] | None = None
    usage_count: int = 0


class PermissionAuditResponse(BaseResponse):
    """Permission audit response."""
    audit_id: UUID
    period_start: datetime
    period_end: datetime
    total_changes: int
    grants: int
    revocations: int
    expirations: int
    delegations: int
    changes_by_user: dict[UUID, int] = Field(default_factory=dict)
    changes_by_role: dict[UUID, int] = Field(default_factory=dict)
    high_risk_changes: list[dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# Enhanced Security Response DTOs
# ============================================================================

class SecurityIncidentResponse(BaseResponse):
    """Security incident response."""
    incident_id: UUID
    incident_type: SecurityEventType
    severity: RiskLevel
    status: str  # new, investigating, contained, resolved, closed
    reported_at: datetime
    reported_by: UUID
    description: str
    affected_users: list[UUID] = Field(default_factory=list)
    affected_resources: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class IPBlockResponse(BaseResponse):
    """IP block response."""
    block_id: UUID
    ip_address: str
    ip_range: str | None = None
    block_type: str
    reason: str
    blocked_at: datetime
    expires_at: datetime | None = None
    affected_users: int = 0
    blocked_requests: int = 0


class ThreatIntelligenceResponse(BaseResponse):
    """Threat intelligence response."""
    threat_id: UUID
    threat_type: str
    threat_level: RiskLevel
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    mitigation_status: str
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    external_references: list[HttpUrl] = Field(default_factory=list)


class SecurityScanResponse(BaseResponse):
    """Security scan response."""
    scan_id: UUID
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    findings: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    risk_summary: dict[str, int] = Field(default_factory=dict)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    report_url: HttpUrl | None = None


class LoginAttemptsResponse(BaseResponse):
    """Login attempts analysis."""
    user_id: UUID
    period: str
    successful_attempts: int
    failed_attempts: int
    blocked_attempts: int
    suspicious_attempts: int
    attempts_by_location: dict[str, int] = Field(default_factory=dict)
    attempts_by_device: dict[str, int] = Field(default_factory=dict)
    unusual_patterns: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced Device Response DTOs
# ============================================================================

class DeviceResponse(BaseModel):
    """Device information."""
    id: UUID
    user_id: UUID
    device_name: str
    device_type: DeviceType
    device_fingerprint: str
    platform: DevicePlatform
    os_version: str | None = None
    app_version: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    trusted: bool = False
    trusted_until: datetime | None = None
    last_seen: datetime
    registered_at: datetime
    push_enabled: bool = False
    location_enabled: bool = False
    biometric_enabled: bool = False


class DeviceListResponse(BaseResponse):
    """Device list response."""
    devices: list[DeviceResponse]
    total_devices: int
    trusted_devices: int
    active_devices: int
    inactive_devices: int
    devices_by_type: dict[str, int] = Field(default_factory=dict)
    devices_by_platform: dict[str, int] = Field(default_factory=dict)


class DeviceTrustResponse(BaseResponse):
    """Device trust response."""
    device_id: UUID
    trusted: bool
    trust_level: str  # full, conditional, none
    trusted_at: datetime | None = None
    trusted_until: datetime | None = None
    trust_conditions: list[dict[str, Any]] = Field(default_factory=list)
    verification_required: bool = False
    verification_methods: list[str] = Field(default_factory=list)


# ============================================================================
# Enhanced Integration Response DTOs
# ============================================================================

class ExternalUserSyncResponse(BaseResponse):
    """External user sync response."""
    sync_id: UUID
    external_system: str
    external_user_id: str
    user_id: UUID | None = None
    sync_status: str  # success, partial, failed
    created: bool = False
    updated: bool = False
    fields_synced: list[str] = Field(default_factory=list)
    fields_failed: list[str] = Field(default_factory=list)
    conflicts: list[dict[str, Any]] = Field(default_factory=list)
    sync_date: datetime


class UserImportResponse(BaseResponse):
    """User import response."""
    import_id: UUID
    status: str  # pending, processing, completed, failed
    total_users: int
    imported: int
    updated: int
    failed: int
    skipped: int
    errors: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[dict[str, Any]] = Field(default_factory=list)
    report_url: HttpUrl | None = None
    completed_at: datetime | None = None


class UserExportResponse(BaseResponse):
    """User export response."""
    export_id: UUID
    format: str
    status: str
    total_users: int
    exported_users: int
    file_size_bytes: int | None = None
    download_url: HttpUrl | None = None
    expires_at: datetime | None = None
    password_protected: bool = False


class DataMigrationResponse(BaseResponse):
    """Data migration response."""
    migration_id: UUID
    source_system: str
    target_system: str
    status: str
    total_records: int
    migrated: int
    failed: int
    rollback_available: bool = True
    errors: list[dict[str, Any]] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime | None = None
    report_url: HttpUrl | None = None


class DataReconciliationResponse(BaseResponse):
    """Data reconciliation response."""
    reconciliation_id: UUID
    primary_source: str
    secondary_sources: list[str]
    status: str
    total_records: int
    matched: int
    mismatched: int
    missing_in_primary: int
    missing_in_secondary: int
    discrepancies: list[dict[str, Any]] = Field(default_factory=list)
    auto_fixed: int = 0
    manual_review_required: int = 0
    report_url: HttpUrl | None = None


# ============================================================================
# System & Monitoring Response DTOs
# ============================================================================

class SystemMetricsResponse(BaseResponse):
    """System metrics response."""
    timestamp: datetime
    uptime_seconds: int
    active_users: int
    active_sessions: int
    requests_per_minute: float
    average_response_time_ms: float
    error_rate: float
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    cache_hit_rate: float
    database_connections: int


class FeatureFlagResponse(BaseModel):
    """Feature flag information."""
    name: str
    enabled: bool
    description: str | None = None
    rollout_percentage: float = 100.0
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    enabled_for_users: list[UUID] = Field(default_factory=list)
    disabled_for_users: list[UUID] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConfigurationResponse(BaseResponse):
    """System configuration response."""
    version: str
    environment: str
    features: list[FeatureFlagResponse]
    security_settings: dict[str, Any]
    authentication_settings: dict[str, Any]
    session_settings: dict[str, Any]
    password_policy: PasswordPolicyResponse
    rate_limits: dict[str, dict[str, Any]]
    maintenance_mode: bool = False
    read_only_mode: bool = False


# ============================================================================
# Notification Response DTOs
# ============================================================================

class NotificationResponse(BaseModel):
    """Notification response."""
    id: UUID
    user_id: UUID
    type: NotificationType
    title: str
    message: str
    priority: str = "normal"  # low, normal, high, urgent
    read: bool = False
    read_at: datetime | None = None
    action_url: HttpUrl | None = None
    action_text: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    expires_at: datetime | None = None


class NotificationPreferencesResponse(BaseResponse):
    """Notification preferences response."""
    user_id: UUID
    email_notifications: dict[str, bool] = Field(default_factory=dict)
    sms_notifications: dict[str, bool] = Field(default_factory=dict)
    push_notifications: dict[str, bool] = Field(default_factory=dict)
    in_app_notifications: dict[str, bool] = Field(default_factory=dict)
    quiet_hours: dict[str, str] | None = None
    frequency_limits: dict[str, int] = Field(default_factory=dict)
    updated_at: datetime


# ============================================================================
# Analytics Response DTOs
# ============================================================================

class UserAnalyticsResponse(BaseResponse):
    """User analytics response."""
    user_id: UUID
    period: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    trends: dict[str, str] = Field(default_factory=dict)
    comparisons: dict[str, float] = Field(default_factory=dict)
    insights: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class SecurityAnalyticsResponse(BaseResponse):
    """Security analytics response."""
    period: str
    total_users: int
    active_users: int
    new_users: int
    security_events: int
    failed_logins: int
    password_resets: int
    mfa_adoptions: int
    high_risk_users: int
    blocked_ips: int
    trends: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    predictions: dict[str, Any] = Field(default_factory=dict)