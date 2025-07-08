"""
Request DTOs for identity domain.

Defines comprehensive data structures for all incoming requests including user management,
authentication, authorization, MFA, sessions, emergency contacts, administration,
security, devices, and integration operations.
"""

import re
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, HttpUrl, constr, validator

from app.modules.identity.domain.entities.user.user_enums import Relationship
from app.modules.identity.domain.enums import (
    AuditAction,
    DevicePlatform,
    DeviceType,
    MFAMethod,
    PermissionScope,
    RiskLevel,
    SecurityEventType,
    SessionType,
    UserRole,
    UserStatus,
)


# Base request DTOs
class BaseRequest(BaseModel):
    """Base request with common fields."""
    request_id: UUID | None = Field(None, description="Unique request ID for tracking")
    correlation_id: UUID | None = Field(None, description="Correlation ID for distributed tracing")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Request timestamp")


class AuthenticatedRequest(BaseRequest):
    """Base request for authenticated operations."""
    current_user_id: UUID = Field(..., description="ID of the user making the request")
    session_id: UUID | None = Field(None, description="Current session ID")
    ip_address: str | None = Field(None, description="Client IP address")
    user_agent: str | None = Field(None, description="Client user agent")


# User management DTOs
class CreateUserRequest(BaseRequest):
    """Request to create a new user."""
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr = Field(...)
    password: str = Field(..., min_length=8)
    first_name: str | None = Field(None, max_length=50)
    last_name: str | None = Field(None, max_length=50)
    phone_number: str | None = Field(None)
    roles: list[str] | None = Field(default_factory=list)
    send_welcome_email: bool = Field(True)
    require_email_verification: bool = Field(True)


class UpdateProfileRequest(AuthenticatedRequest):
    """Request to update user profile."""
    target_user_id: UUID = Field(..., description="User ID to update")
    first_name: str | None = Field(None, max_length=50)
    last_name: str | None = Field(None, max_length=50)
    bio: str | None = Field(None, max_length=500)
    date_of_birth: datetime | None = Field(None)
    gender: str | None = Field(None)
    language: str | None = Field(None)
    timezone: str | None = Field(None)
    metadata: dict[str, Any] | None = Field(None)


class UploadAvatarRequest(AuthenticatedRequest):
    """Request to upload avatar."""
    target_user_id: UUID = Field(...)
    file_data: bytes = Field(...)
    content_type: str = Field(...)
    file_size: int = Field(..., gt=0, le=5*1024*1024)  # Max 5MB


# Authentication DTOs
class LoginRequest(BaseRequest):
    """Request to authenticate user."""
    email: EmailStr = Field(...)
    password: str = Field(...)
    ip_address: str = Field(...)
    user_agent: str = Field(...)
    device_fingerprint: str | None = Field(None)
    session_type: SessionType = Field(SessionType.WEB)
    remember_me: bool = Field(False)


class RegisterUserRequest(BaseRequest):
    """Request to register new user."""
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr = Field(...)
    password: str = Field(..., min_length=8)
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    phone_number: str | None = Field(None)
    terms_accepted: bool = Field(...)
    marketing_consent: bool = Field(False)
    ip_address: str = Field(...)
    referral_code: str | None = Field(None)


class RefreshTokenRequest(BaseRequest):
    """Request to refresh authentication token."""
    refresh_token: str = Field(...)
    ip_address: str | None = Field(None)
    user_agent: str | None = Field(None)


class VerifyEmailRequest(BaseRequest):
    """Request to verify email address."""
    token: str = Field(...)
    email: EmailStr | None = Field(None)


class ForgotPasswordRequest(BaseRequest):
    """Request to initiate password reset."""
    email: EmailStr = Field(...)
    ip_address: str = Field(...)


class ResetPasswordRequest(BaseRequest):
    """Request to reset password."""
    token: str = Field(...)
    new_password: str = Field(..., min_length=8)
    ip_address: str = Field(...)


# MFA DTOs
class SetupMFARequest(AuthenticatedRequest):
    """Request to setup MFA."""
    method: MFAMethod = Field(...)
    device_name: str = Field(..., max_length=100)
    phone_number: str | None = Field(None)  # For SMS method


class VerifyMFASetupRequest(AuthenticatedRequest):
    """Request to verify MFA setup."""
    device_id: UUID = Field(...)
    verification_code: str = Field(..., min_length=6, max_length=6)


class VerifyMFAChallengeRequest(BaseRequest):
    """Request to verify MFA during login."""
    session_id: UUID = Field(...)
    device_id: UUID | None = Field(None)
    code: str = Field(...)
    backup_code: bool = Field(False)


# Session management DTOs
class RevokeSessionRequest(AuthenticatedRequest):
    """Request to revoke a session."""
    session_id: UUID = Field(...)


class ExtendSessionRequest(AuthenticatedRequest):
    """Request to extend session expiry."""
    session_id: UUID = Field(...)
    extension_minutes: int = Field(..., ge=1, le=1440)  # Max 24 hours


# Permission management DTOs
class AssignRoleRequest(AuthenticatedRequest):
    """Request to assign role to user."""
    user_id: UUID = Field(...)
    role_id: UUID = Field(...)
    reason: str | None = Field(None, max_length=500)
    expires_at: datetime | None = Field(None)


class GrantPermissionRequest(AuthenticatedRequest):
    """Request to grant permission to user."""
    user_id: UUID = Field(...)
    permission: str = Field(...)
    resource_type: str | None = Field(None)
    resource_id: str | None = Field(None)
    scope: PermissionScope = Field(PermissionScope.USER)
    expires_at: datetime | None = Field(None)
    reason: str | None = Field(None)


class CreateCustomRoleRequest(AuthenticatedRequest):
    """Request to create custom role."""
    name: str = Field(..., min_length=3, max_length=50)
    description: str = Field(..., max_length=500)
    permissions: list[str] = Field(...)
    parent_role_id: UUID | None = Field(None)
    priority: int = Field(50, ge=1, le=100)


# Search and query DTOs
class SearchUsersRequest(AuthenticatedRequest):
    """Request to search users."""
    search_term: str | None = Field(None)
    status: UserStatus | None = Field(None)
    role: str | None = Field(None)
    created_after: datetime | None = Field(None)
    created_before: datetime | None = Field(None)
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)
    sort_by: str = Field("created_at")
    sort_order: str = Field("desc", regex="^(asc|desc)$")


class GetAuditLogsRequest(AuthenticatedRequest):
    """Request to get audit logs."""
    user_id: UUID | None = Field(None)
    actor_id: UUID | None = Field(None)
    action: AuditAction | None = Field(None)
    resource_type: str | None = Field(None)
    resource_id: str | None = Field(None)
    start_date: datetime | None = Field(None)
    end_date: datetime | None = Field(None)
    success_only: bool | None = Field(None)
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=100)


class GetSecurityEventsRequest(AuthenticatedRequest):
    """Request to get security events."""
    user_id: UUID | None = Field(None)
    event_type: SecurityEventType | None = Field(None)
    severity: RiskLevel | None = Field(None)
    ip_address: str | None = Field(None)
    start_date: datetime | None = Field(None)
    end_date: datetime | None = Field(None)
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


# Emergency contact DTOs
class AddEmergencyContactRequest(AuthenticatedRequest):
    """Request to add emergency contact."""
    name: str = Field(..., min_length=2, max_length=100)
    relationship: Relationship = Field(...)
    phone_number: str = Field(...)
    email: EmailStr | None = Field(None)
    is_primary: bool = Field(False)
    notify_on_emergency: bool = Field(True)


class VerifyEmergencyContactRequest(AuthenticatedRequest):
    """Request to verify emergency contact."""
    contact_id: UUID = Field(...)
    verification_code: str = Field(...)
    verification_method: str = Field(..., regex="^(sms|email)$")


# Administrative DTOs
class BulkUserActionRequest(AuthenticatedRequest):
    """Request for bulk user operations."""
    user_ids: list[UUID] = Field(..., min_items=1, max_items=100)
    action: str = Field(...)
    parameters: dict[str, Any] | None = Field(None)
    reason: str = Field(..., max_length=500)


class ExportUserDataRequest(AuthenticatedRequest):
    """Request to export user data (GDPR)."""
    user_id: UUID = Field(...)
    data_categories: list[str] = Field(...)
    format: str = Field("json", regex="^(json|csv|xml)$")
    include_deleted: bool = Field(False)
    lawful_basis: str = Field(...)
    purpose: str = Field(...)


class GenerateComplianceReportRequest(AuthenticatedRequest):
    """Request to generate compliance report."""
    report_type: str = Field(...)
    start_date: datetime = Field(...)
    end_date: datetime = Field(...)
    regulations: list[str] = Field(...)
    include_details: bool = Field(True)
    format: str = Field("pdf", regex="^(pdf|excel|json)$")


# Validators
class PasswordValidator:
    """Password validation mixin."""
    
    @validator('password', 'new_password')
    def validate_password_strength(self, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError('Password must contain special character')
        return v


class UsernameValidator:
    """Username validation mixin."""
    
    @validator('username')
    def validate_username(self, v):
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username can only contain letters, numbers, dots, dashes and underscores')
        if v.lower() in ['admin', 'root', 'system', 'administrator']:
            raise ValueError('Username is reserved')
        return v.lower()


class PhoneNumberValidator:
    """Phone number validation mixin."""
    
    @validator('phone_number')
    def validate_phone_number(self, v):
        if v:
            # Remove all non-digits
            digits = re.sub(r'\D', '', v)
            if len(digits) < 10 or len(digits) > 15:
                raise ValueError('Invalid phone number length')
            # Format as E.164
            if not v.startswith('+'):
                v = f'+{digits}'
        return v


# ============================================================================
# Enhanced User Management Request DTOs
# ============================================================================

class UpdateContactInfoRequest(AuthenticatedRequest):
    """Request to update contact information."""
    phone_number: constr(regex=r"^\+?[1-9]\d{1,14}$") | None = None
    secondary_phone: constr(regex=r"^\+?[1-9]\d{1,14}$") | None = None
    work_extension: constr(max_length=10) | None = None
    home_address: dict[str, Any] | None = None
    mailing_address: dict[str, Any] | None = None
    
    
class UpdatePreferencesRequest(AuthenticatedRequest):
    """Request to update user preferences."""
    notifications: dict[str, bool] | None = None
    ui_theme: str | None = Field(None, regex="^(light|dark|auto)$")
    language: str | None = Field(None, min_length=2, max_length=5)
    timezone: str | None = None
    date_format: str | None = None
    time_format: str | None = Field(None, regex="^(12h|24h)$")
    privacy: dict[str, Any] | None = None
    

class DeactivateUserRequest(AuthenticatedRequest):
    """Request to deactivate user account."""
    user_id: UUID = Field(...)
    reason: str = Field(..., min_length=10, max_length=500)
    notify_user: bool = Field(True)
    preserve_data: bool = Field(True)
    schedule_deletion_days: int | None = Field(None, ge=1, le=365)


class ReactivateUserRequest(AuthenticatedRequest):
    """Request to reactivate user account."""
    user_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    require_password_reset: bool = Field(True)
    require_mfa_reset: bool = Field(False)
    notify_user: bool = Field(True)


class DeleteUserRequest(AuthenticatedRequest):
    """Request to permanently delete user."""
    user_id: UUID = Field(...)
    confirmation_code: str = Field(..., min_length=6, max_length=6)
    anonymize_data: bool = Field(True)
    delete_related_data: bool = Field(True)
    reason: str = Field(..., max_length=500)
    legal_basis: str | None = Field(None)


class MergeUsersRequest(AuthenticatedRequest):
    """Request to merge two user accounts."""
    source_user_id: UUID = Field(...)
    target_user_id: UUID = Field(...)
    merge_strategy: str = Field("keep_target", regex="^(keep_target|keep_source|newest|manual)$")
    data_categories: list[str] = Field(default_factory=list)
    conflict_resolution: dict[str, str] | None = Field(None)
    notify_users: bool = Field(True)
    reason: str = Field(..., max_length=500)


class TransferUserDataRequest(AuthenticatedRequest):
    """Request to transfer user data."""
    source_user_id: UUID = Field(...)
    target_user_id: UUID = Field(...)
    data_types: list[str] = Field(...)
    include_permissions: bool = Field(False)
    include_sessions: bool = Field(False)
    reason: str = Field(..., max_length=500)


class GenerateAvatarRequest(AuthenticatedRequest):
    """Request to generate avatar from initials."""
    style: str = Field("initials", regex="^(initials|pattern|identicon|robot)$")
    background_color: str | None = Field(None, regex="^#[0-9A-Fa-f]{6}$")
    text_color: str | None = Field(None, regex="^#[0-9A-Fa-f]{6}$")
    size: int = Field(256, ge=128, le=512)
    format: str = Field("png", regex="^(png|jpg|svg)$")


class DeleteAvatarRequest(AuthenticatedRequest):
    """Request to delete user avatar."""
    target_user_id: UUID = Field(...)
    use_default: bool = Field(True)


# ============================================================================
# Enhanced Authentication Request DTOs
# ============================================================================

class LogoutRequest(AuthenticatedRequest):
    """Request to logout from current or specific session."""
    session_id: UUID | None = None
    everywhere: bool = Field(False)
    reason: str | None = None
    clear_remember_me: bool = Field(True)


class SocialLoginRequest(BaseRequest):
    """Request for OAuth/Social login."""
    provider: str = Field(..., regex="^(google|facebook|github|linkedin|microsoft|apple)$")
    code: str = Field(...)
    state: str = Field(...)
    redirect_uri: HttpUrl = Field(...)
    ip_address: str = Field(...)
    user_agent: str = Field(...)
    device_fingerprint: str | None = None


class ResendVerificationRequest(BaseRequest):
    """Request to resend verification email."""
    email: EmailStr = Field(...)
    verification_type: str = Field("email", regex="^(email|phone)$")
    
    
class ConfirmEmailChangeRequest(AuthenticatedRequest):
    """Request to confirm email change."""
    token: str = Field(...)
    new_email: EmailStr = Field(...)


class InvalidateAllTokensRequest(AuthenticatedRequest):
    """Request to invalidate all tokens for a user."""
    user_id: UUID | None = None  # None means current user
    include_api_keys: bool = Field(False)
    reason: str = Field(..., max_length=500)


# ============================================================================
# Enhanced Password Management Request DTOs
# ============================================================================

class ChangePasswordRequest(AuthenticatedRequest, PasswordValidator):
    """Request to change password."""
    current_password: str = Field(...)
    new_password: str = Field(..., min_length=8, max_length=128)
    logout_all_sessions: bool = Field(False)
    notify_other_sessions: bool = Field(True)


class ValidatePasswordRequest(BaseRequest):
    """Request to validate password strength."""
    password: str = Field(...)
    user_context: dict[str, Any] | None = None  # Username, email, etc. for context-aware validation


class ForcePasswordResetRequest(AuthenticatedRequest):
    """Request to force password reset (admin)."""
    user_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    require_immediate_action: bool = Field(True)
    temporary_password: str | None = None
    send_notification: bool = Field(True)


class UpdatePasswordPolicyRequest(AuthenticatedRequest):
    """Request to update password policy."""
    min_length: int | None = Field(None, ge=8, le=128)
    require_uppercase: bool | None = None
    require_lowercase: bool | None = None
    require_numbers: bool | None = None
    require_special_chars: bool | None = None
    min_unique_chars: int | None = Field(None, ge=1, le=20)
    password_history_count: int | None = Field(None, ge=0, le=24)
    expiry_days: int | None = Field(None, ge=0, le=365)
    prevent_user_info_in_password: bool | None = None
    check_pwned_passwords: bool | None = None
    apply_to_existing_users: bool = Field(False)


class CheckPasswordBreachRequest(BaseRequest):
    """Request to check if password has been breached."""
    password_hash: str = Field(...)  # SHA-1 hash prefix (5 chars) for k-anonymity
    full_check: bool = Field(False)


# ============================================================================
# Enhanced MFA Request DTOs
# ============================================================================

class DisableMFARequest(AuthenticatedRequest):
    """Request to disable MFA."""
    current_password: str = Field(...)
    reason: str | None = None
    disable_all_devices: bool = Field(True)


class RegenerateBackupCodesRequest(AuthenticatedRequest):
    """Request to regenerate MFA backup codes."""
    current_password: str = Field(...)
    invalidate_old_codes: bool = Field(True)
    code_count: int = Field(10, ge=5, le=20)


class AddMFADeviceRequest(AuthenticatedRequest):
    """Request to add MFA device."""
    method: MFAMethod = Field(...)
    device_name: str = Field(..., min_length=1, max_length=100)
    phone_number: constr(regex=r"^\+?[1-9]\d{1,14}$") | None = None
    is_primary: bool = Field(False)


class RemoveMFADeviceRequest(AuthenticatedRequest):
    """Request to remove MFA device."""
    device_id: UUID = Field(...)
    current_password: str = Field(...)
    reason: str | None = None


class ResetMFARequest(AuthenticatedRequest):
    """Request to reset MFA (admin)."""
    user_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    require_setup: bool = Field(True)
    temporary_bypass_hours: int | None = Field(None, ge=1, le=72)


# ============================================================================
# Enhanced Session Management Request DTOs
# ============================================================================

class RevokeAllSessionsRequest(AuthenticatedRequest):
    """Request to revoke all sessions."""
    user_id: UUID | None = None  # None means current user
    except_current: bool = Field(True)
    reason: str | None = None
    notify_user: bool = Field(True)


class TransferSessionRequest(AuthenticatedRequest):
    """Request to transfer session to new device."""
    session_id: UUID = Field(...)
    new_device_fingerprint: str = Field(...)
    new_device_name: str | None = None
    verification_code: str = Field(..., min_length=6, max_length=6)


class CleanupExpiredSessionsRequest(AuthenticatedRequest):
    """Request to cleanup expired sessions."""
    older_than_days: int = Field(30, ge=1, le=365)
    include_active: bool = Field(False)
    dry_run: bool = Field(True)
    batch_size: int = Field(1000, ge=100, le=10000)


class GetActiveSessionsRequest(AuthenticatedRequest):
    """Request to get active sessions."""
    user_id: UUID | None = None
    include_expired: bool = Field(False)
    group_by_device: bool = Field(True)
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


# ============================================================================
# Emergency Contact Request DTOs
# ============================================================================

class UpdateEmergencyContactRequest(AuthenticatedRequest):
    """Request to update emergency contact."""
    contact_id: UUID = Field(...)
    name: constr(min_length=2, max_length=100) | None = None
    relationship: Relationship | None = None
    phone_number: constr(regex=r"^\+?[1-9]\d{1,14}$") | None = None
    secondary_phone: constr(regex=r"^\+?[1-9]\d{1,14}$") | None = None
    email: EmailStr | None = None
    address: dict[str, Any] | None = None
    is_primary: bool | None = None
    can_make_medical_decisions: bool | None = None
    notes: constr(max_length=500) | None = None


class DeleteEmergencyContactRequest(AuthenticatedRequest):
    """Request to delete emergency contact."""
    contact_id: UUID = Field(...)
    reason: str | None = None


class SendPhoneVerificationRequest(AuthenticatedRequest):
    """Request to send phone verification to emergency contact."""
    contact_id: UUID = Field(...)
    phone_type: str = Field("primary", regex="^(primary|secondary)$")


class VerifyPhoneRequest(AuthenticatedRequest):
    """Request to verify emergency contact phone."""
    contact_id: UUID = Field(...)
    verification_code: str = Field(..., min_length=6, max_length=6)
    phone_type: str = Field("primary", regex="^(primary|secondary)$")


class SetPrimaryContactRequest(AuthenticatedRequest):
    """Request to set primary emergency contact."""
    contact_id: UUID = Field(...)
    notify_previous_primary: bool = Field(True)
    notify_new_primary: bool = Field(True)


class BulkImportContactsRequest(AuthenticatedRequest):
    """Request to bulk import emergency contacts."""
    contacts: list[AddEmergencyContactRequest] = Field(..., max_items=10)
    skip_duplicates: bool = Field(True)
    validate_all_first: bool = Field(True)


# ============================================================================
# Administrative Request DTOs  
# ============================================================================

class UpdateUserStatusRequest(AuthenticatedRequest):
    """Request to update user status (admin)."""
    user_id: UUID = Field(...)
    new_status: UserStatus = Field(...)
    reason: str = Field(..., min_length=10, max_length=500)
    notify_user: bool = Field(True)
    effective_date: datetime | None = None


class ImpersonateUserRequest(AuthenticatedRequest):
    """Request to impersonate user (admin)."""
    target_user_id: UUID = Field(...)
    reason: str = Field(..., min_length=20, max_length=500)
    duration_minutes: int = Field(60, ge=1, le=480)  # Max 8 hours
    allowed_actions: list[str] | None = None
    restricted_actions: list[str] | None = None
    notify_target: bool = Field(True)
    require_approval: bool = Field(True)


class UnlockUserAccountRequest(AuthenticatedRequest):
    """Request to unlock user account (admin)."""
    user_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    reset_failed_attempts: bool = Field(True)
    require_password_reset: bool = Field(False)
    notify_user: bool = Field(True)


class BulkOperationType(str, Enum):
    """Bulk operation types."""
    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"
    SUSPEND = "suspend"
    UNLOCK = "unlock"
    LOCK = "lock"
    DELETE = "delete"
    FORCE_PASSWORD_RESET = "force_password_reset"
    FORCE_MFA_RESET = "force_mfa_reset"
    REVOKE_SESSIONS = "revoke_sessions"
    ASSIGN_ROLE = "assign_role"
    REMOVE_ROLE = "remove_role"
    UPDATE_STATUS = "update_status"
    SEND_NOTIFICATION = "send_notification"


class AnonymizeUserDataRequest(AuthenticatedRequest):
    """Request to anonymize user data (GDPR)."""
    user_id: UUID = Field(...)
    data_categories: list[str] = Field(...)
    preserve_for_legal: bool = Field(True)
    retention_days: int = Field(2555, ge=0, le=3650)  # 7 years default
    reason: str = Field(..., max_length=500)
    legal_basis: str = Field(...)


class SuspendUserRequest(AuthenticatedRequest):
    """Request to suspend user account."""
    user_id: UUID = Field(...)
    reason: str = Field(..., min_length=10, max_length=500)
    duration_days: int | None = Field(None, ge=1, le=365)
    revoke_sessions: bool = Field(True)
    disable_api_access: bool = Field(True)
    notify_user: bool = Field(True)


class TerminateUserRequest(AuthenticatedRequest):
    """Request to terminate user account."""
    user_id: UUID = Field(...)
    reason: str = Field(..., min_length=20, max_length=500)
    immediate: bool = Field(False)
    preserve_audit_logs: bool = Field(True)
    transfer_data_to: UUID | None = None
    notify_emergency_contacts: bool = Field(False)
    legal_hold: bool = Field(False)


class RestoreUserRequest(AuthenticatedRequest):
    """Request to restore terminated user."""
    user_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    restore_permissions: bool = Field(False)
    restore_data: bool = Field(True)
    notify_user: bool = Field(True)


class AuditUserActionsRequest(AuthenticatedRequest):
    """Request to audit user actions."""
    user_id: UUID = Field(...)
    start_date: datetime = Field(...)
    end_date: datetime = Field(...)
    include_system_actions: bool = Field(False)
    include_failed_actions: bool = Field(True)
    group_by: str | None = Field(None, regex="^(action|resource|hour|day)$")


class SystemMaintenanceRequest(AuthenticatedRequest):
    """Request for system maintenance operations."""
    operation: str = Field(..., regex="^(cleanup_sessions|archive_logs|optimize_indexes|purge_deleted|vacuum_database)$")
    target_age_days: int = Field(90, ge=1, le=365)
    dry_run: bool = Field(True)
    force: bool = Field(False)
    notify_users: bool = Field(True)
    schedule_at: datetime | None = None


# ============================================================================
# Authorization Management Request DTOs
# ============================================================================

class UnassignRoleRequest(AuthenticatedRequest):
    """Request to unassign role from user."""
    user_id: UUID = Field(...)
    role_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    effective_immediately: bool = Field(True)


class RevokePermissionRequest(AuthenticatedRequest):
    """Request to revoke permission from user."""
    user_id: UUID = Field(...)
    permission: str = Field(...)
    resource_type: str | None = None
    resource_id: str | None = None
    reason: str = Field(..., max_length=500)


class UpdateRolePermissionsRequest(AuthenticatedRequest):
    """Request to update role permissions."""
    role_id: UUID = Field(...)
    add_permissions: list[str] = Field(default_factory=list)
    remove_permissions: list[str] = Field(default_factory=list)
    reason: str = Field(..., max_length=500)
    notify_affected_users: bool = Field(True)


class DeleteRoleRequest(AuthenticatedRequest):
    """Request to delete a role."""
    role_id: UUID = Field(...)
    reassign_to_role_id: UUID | None = None
    force: bool = Field(False)
    reason: str = Field(..., max_length=500)


class CreatePermissionRequest(AuthenticatedRequest):
    """Request to create new permission."""
    name: str = Field(..., min_length=3, max_length=100)
    resource: str = Field(..., max_length=50)
    action: str = Field(..., max_length=50)
    description: str = Field(..., max_length=500)
    scope: PermissionScope = Field(PermissionScope.RESOURCE)
    conditions: dict[str, Any] | None = None


class UpdatePermissionRequest(AuthenticatedRequest):
    """Request to update permission."""
    permission_id: UUID = Field(...)
    name: str | None = Field(None, min_length=3, max_length=100)
    description: str | None = Field(None, max_length=500)
    conditions: dict[str, Any] | None = None
    deprecated: bool | None = None


class DeletePermissionRequest(AuthenticatedRequest):
    """Request to delete permission."""
    permission_id: UUID = Field(...)
    force: bool = Field(False)
    reassign_to: UUID | None = None
    reason: str = Field(..., max_length=500)


class BulkPermissionAssignmentRequest(AuthenticatedRequest):
    """Request for bulk permission assignment."""
    user_ids: list[UUID] = Field(..., min_items=1, max_items=100)
    permissions: list[str] = Field(..., min_items=1)
    operation: str = Field(..., regex="^(grant|revoke)$")
    resource_type: str | None = None
    resource_ids: list[str] | None = None
    expires_at: datetime | None = None
    reason: str = Field(..., max_length=500)


class CloneRoleRequest(AuthenticatedRequest):
    """Request to clone an existing role."""
    source_role_id: UUID = Field(...)
    new_name: str = Field(..., min_length=3, max_length=50)
    new_description: str = Field(..., max_length=500)
    include_permissions: bool = Field(True)
    include_users: bool = Field(False)


class InheritRoleRequest(AuthenticatedRequest):
    """Request to inherit from parent role."""
    role_id: UUID = Field(...)
    parent_role_id: UUID = Field(...)
    inherit_permissions: bool = Field(True)
    inherit_priority: bool = Field(False)


class SetPermissionExpiryRequest(AuthenticatedRequest):
    """Request to set permission expiry."""
    user_id: UUID = Field(...)
    permission: str = Field(...)
    expires_at: datetime = Field(...)
    resource_type: str | None = None
    resource_id: str | None = None
    notify_before_days: int = Field(7, ge=1, le=30)


class DelegatePermissionRequest(AuthenticatedRequest):
    """Request to delegate permission to another user."""
    to_user_id: UUID = Field(...)
    permission: str = Field(...)
    resource_type: str | None = None
    resource_id: str | None = None
    can_sub_delegate: bool = Field(False)
    expires_at: datetime = Field(...)
    conditions: dict[str, Any] | None = None
    reason: str = Field(..., max_length=500)


class ApprovePermissionRequestRequest(AuthenticatedRequest):
    """Request to approve permission request."""
    request_id: UUID = Field(...)
    approved: bool = Field(...)
    reason: str = Field(..., max_length=500)
    modifications: dict[str, Any] | None = None
    expires_at: datetime | None = None


class AuditPermissionChangesRequest(AuthenticatedRequest):
    """Request to audit permission changes."""
    start_date: datetime = Field(...)
    end_date: datetime = Field(...)
    user_id: UUID | None = None
    role_id: UUID | None = None
    permission: str | None = None
    include_inherited: bool = Field(True)
    include_delegated: bool = Field(True)


class SynchronizePermissionsRequest(AuthenticatedRequest):
    """Request to sync permissions with external system."""
    external_system: str = Field(..., regex="^(ldap|ad|okta|auth0|custom)$")
    sync_mode: str = Field("merge", regex="^(merge|overwrite|additive)$")
    dry_run: bool = Field(True)
    user_mappings: dict[str, str] | None = None
    role_mappings: dict[str, str] | None = None
    permission_mappings: dict[str, str] | None = None


# ============================================================================
# Security Management Request DTOs
# ============================================================================

class ReportSecurityIncidentRequest(AuthenticatedRequest):
    """Request to report security incident."""
    incident_type: SecurityEventType = Field(...)
    severity: RiskLevel = Field(...)
    description: str = Field(..., min_length=20, max_length=1000)
    affected_users: list[UUID] | None = None
    affected_resources: list[dict[str, Any]] | None = None
    evidence: dict[str, Any] | None = None
    immediate_actions_taken: list[str] | None = None
    requires_escalation: bool = Field(False)


class BlockIPAddressRequest(AuthenticatedRequest):
    """Request to block IP address."""
    ip_address: str = Field(...)
    reason: str = Field(..., max_length=500)
    duration_hours: int | None = Field(None, ge=1, le=8760)  # Max 1 year
    block_type: str = Field("full", regex="^(full|read_only|auth_only)$")
    apply_to_subnet: bool = Field(False)
    notify_affected_users: bool = Field(True)


class UnblockIPAddressRequest(AuthenticatedRequest):
    """Request to unblock IP address."""
    ip_address: str = Field(...)
    reason: str = Field(..., max_length=500)
    require_additional_verification: bool = Field(True)


class FlagSuspiciousActivityRequest(AuthenticatedRequest):
    """Request to flag suspicious activity."""
    user_id: UUID | None = None
    session_id: UUID | None = None
    activity_type: str = Field(...)
    description: str = Field(..., max_length=1000)
    risk_indicators: list[str] = Field(...)
    recommended_action: str | None = None
    auto_respond: bool = Field(True)


class SecurityScanRequest(AuthenticatedRequest):
    """Request to run security scan."""
    scan_type: str = Field(..., regex="^(full|quick|targeted|compliance)$")
    target_users: list[UUID] | None = None
    include_inactive_users: bool = Field(False)
    check_weak_passwords: bool = Field(True)
    check_suspicious_sessions: bool = Field(True)
    check_permission_escalation: bool = Field(True)
    check_data_access_patterns: bool = Field(True)


class UpdateSecuritySettingsRequest(AuthenticatedRequest):
    """Request to update security settings."""
    password_policy: dict[str, Any] | None = None
    session_policy: dict[str, Any] | None = None
    mfa_policy: dict[str, Any] | None = None
    ip_restrictions: dict[str, Any] | None = None
    rate_limiting: dict[str, Any] | None = None
    audit_settings: dict[str, Any] | None = None
    apply_immediately: bool = Field(False)
    grandfather_existing: bool = Field(True)


class GenerateSecurityReportRequest(AuthenticatedRequest):
    """Request to generate security report."""
    report_type: str = Field(..., regex="^(executive|detailed|compliance|incident)$")
    start_date: datetime = Field(...)
    end_date: datetime = Field(...)
    include_sections: list[str] = Field(default_factory=lambda: [
        "summary", "incidents", "vulnerabilities", "compliance", "recommendations"
    ])
    format: str = Field("pdf", regex="^(pdf|html|json)$")
    recipient_emails: list[EmailStr] | None = None


class TestSecurityControlsRequest(AuthenticatedRequest):
    """Request to test security controls."""
    control_types: list[str] = Field(...)
    test_mode: str = Field("passive", regex="^(passive|active|aggressive)$")
    target_systems: list[str] | None = None
    notify_on_failure: bool = Field(True)
    auto_remediate: bool = Field(False)


# ============================================================================
# Device Management Request DTOs
# ============================================================================

class RegisterDeviceRequest(AuthenticatedRequest):
    """Request to register a device."""
    device_name: str = Field(..., min_length=1, max_length=100)
    device_type: DeviceType = Field(...)
    device_fingerprint: str = Field(...)
    platform: DevicePlatform = Field(DevicePlatform.UNKNOWN)
    os_version: str | None = None
    app_version: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    push_token: str | None = None
    capabilities: list[str] = Field(default_factory=list)


class UnregisterDeviceRequest(AuthenticatedRequest):
    """Request to unregister device."""
    device_id: UUID = Field(...)
    reason: str | None = None
    wipe_device_data: bool = Field(False)
    revoke_sessions: bool = Field(True)


class UpdateDeviceInfoRequest(AuthenticatedRequest):
    """Request to update device information."""
    device_id: UUID = Field(...)
    device_name: str | None = Field(None, max_length=100)
    os_version: str | None = None
    app_version: str | None = None
    push_token: str | None = None
    location_enabled: bool | None = None
    biometric_enabled: bool | None = None


class TrustDeviceRequest(AuthenticatedRequest):
    """Request to trust a device."""
    device_id: UUID = Field(...)
    trust_duration_days: int = Field(30, ge=1, le=365)
    require_biometric: bool = Field(False)
    location_restricted: bool = Field(False)
    allowed_locations: list[dict[str, Any]] | None = None


class RevokeTrustDeviceRequest(AuthenticatedRequest):
    """Request to revoke device trust."""
    device_id: UUID = Field(...)
    reason: str = Field(..., max_length=500)
    block_device: bool = Field(False)
    notify_user: bool = Field(True)


class CleanupDevicesRequest(AuthenticatedRequest):
    """Request to cleanup old devices."""
    inactive_days: int = Field(90, ge=30, le=365)
    include_trusted: bool = Field(False)
    dry_run: bool = Field(True)
    notify_users: bool = Field(True)


# ============================================================================  
# Integration Management Request DTOs
# ============================================================================

class SyncExternalUserRequest(AuthenticatedRequest):
    """Request to sync user with external system."""
    external_system: str = Field(...)
    external_user_id: str = Field(...)
    sync_mode: str = Field("merge", regex="^(merge|overwrite|create_only)$")
    field_mappings: dict[str, str] | None = None
    conflict_resolution: str = Field("skip", regex="^(skip|overwrite|newest|manual)$")
    create_if_missing: bool = Field(True)
    update_if_exists: bool = Field(True)


class ImportUsersRequest(AuthenticatedRequest):
    """Request to bulk import users."""
    source_type: str = Field(..., regex="^(csv|json|ldap|api)$")
    source_data: str | None = None  # Base64 encoded for file uploads
    source_url: HttpUrl | None = None
    field_mappings: dict[str, str] = Field(...)
    validation_mode: str = Field("strict", regex="^(strict|lenient|skip)$")
    duplicate_handling: str = Field("skip", regex="^(skip|update|error)$")
    default_password: str | None = None
    send_welcome_emails: bool = Field(False)
    default_roles: list[UserRole] = Field(default_factory=list)
    batch_size: int = Field(100, ge=10, le=1000)
    dry_run: bool = Field(True)


class ExportUsersRequest(AuthenticatedRequest):
    """Request to export users."""
    format: str = Field("csv", regex="^(csv|json|xlsx)$")
    user_ids: list[UUID] | None = None
    filters: dict[str, Any] | None = None
    include_fields: list[str] | None = None
    exclude_fields: list[str] | None = None
    include_inactive: bool = Field(False)
    anonymize_pii: bool = Field(False)
    password_protected: bool = Field(True)


class MigrateUserDataRequest(AuthenticatedRequest):
    """Request to migrate user data."""
    source_system: str = Field(...)
    target_system: str = Field(...)
    user_ids: list[UUID] | None = None
    data_types: list[str] = Field(...)
    transformation_rules: dict[str, Any] | None = None
    validate_before_migration: bool = Field(True)
    rollback_on_error: bool = Field(True)
    parallel_processing: bool = Field(False)


class ReconcileUserDataRequest(AuthenticatedRequest):
    """Request to reconcile user data."""
    primary_source: str = Field(...)
    secondary_sources: list[str] = Field(...)
    reconciliation_fields: list[str] = Field(...)
    conflict_resolution: dict[str, str] = Field(...)
    generate_report: bool = Field(True)
    auto_fix_discrepancies: bool = Field(False)