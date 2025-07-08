"""
User Entity Events

Domain events related to user lifecycle, authentication, profile management,
and user-specific security operations.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from ...events import IdentityDomainEvent


# =============================================================================
# User Lifecycle Events
# =============================================================================

class UserCreated(IdentityDomainEvent):
    """Event raised when a new user is created."""
    user_id: UUID
    email: str
    name: str
    role: str
    created_by: UUID | None = None
    registration_method: str = Field(default="email")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserActivated(IdentityDomainEvent):
    """Event raised when a user account is activated."""
    user_id: UUID
    activated_by: UUID | None = None
    activation_method: str = Field(default="email_verification")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserSuspended(IdentityDomainEvent):
    """Event raised when a user account is suspended."""
    user_id: UUID
    reason: str
    suspended_by: UUID
    suspension_expires_at: datetime | None = None
    automatic_suspension: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserDeactivated(IdentityDomainEvent):
    """Event raised when a user account is deactivated."""
    user_id: UUID
    reason: str
    deactivated_by: UUID | None = None
    data_retention_required: bool = Field(default=True)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserDeleted(IdentityDomainEvent):
    """Event raised when a user account is permanently deleted."""
    user_id: UUID
    deleted_by: UUID
    deletion_reason: str
    data_retained: bool
    retained_data_types: list[str]
    gdpr_compliant: bool = Field(default=True)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserReactivated(IdentityDomainEvent):
    """Event raised when a deactivated user is reactivated."""
    user_id: UUID
    reactivated_by: UUID
    reactivation_reason: str
    previous_status: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserRegistered(IdentityDomainEvent):
    """Event raised when a new user registers."""
    user_id: UUID
    email: str
    username: str
    account_type: str
    auto_activated: bool
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserReinstated(IdentityDomainEvent):
    """Event raised when suspended user is reinstated."""
    user_id: UUID
    reinstated_by: UUID
    reinstated_at: datetime = Field(default_factory=datetime.utcnow)
    reinstatement_reason: str | None = None
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Profile Events
# =============================================================================

class ProfileUpdated(IdentityDomainEvent):
    """Event raised when user profile is updated."""
    user_id: UUID
    updated_fields: list[str]
    previous_values: dict[str, Any]
    new_values: dict[str, Any]
    updated_by: UUID | None = None
    validation_passed: bool = Field(default=True)
    completion_change: float = Field(default=0.0)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)
    
    def get_sensitive_fields(self) -> list[str]:
        """Get list of fields that contain sensitive data."""
        sensitive_fields = [
            'phone_number', 'date_of_birth', 'home_address', 
            'work_address', 'supervisor_id'
        ]
        return [field for field in self.updated_fields if field in sensitive_fields]


class ProfileCompleted(IdentityDomainEvent):
    """Event raised when user profile reaches 100% completion."""
    user_id: UUID
    completion_percentage: float
    completed_at: datetime
    missing_fields_filled: list[str]

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserProfileUpdated(IdentityDomainEvent):
    """Event raised when user profile is updated."""
    user_id: UUID
    updated_fields: list[str]
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Avatar Events
# =============================================================================

class AvatarUploaded(IdentityDomainEvent):
    """Event raised when user uploads an avatar."""
    user_id: UUID
    avatar_id: UUID
    file_path: str
    file_size: int
    content_type: str
    uploaded_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class AvatarChanged(IdentityDomainEvent):
    """Event raised when user changes their avatar."""
    user_id: UUID
    old_avatar_id: UUID | None
    new_avatar_id: UUID
    changed_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class AvatarDeleted(IdentityDomainEvent):
    """Event raised when user deletes their avatar."""
    user_id: UUID
    avatar_id: UUID
    deleted_at: datetime
    deleted_by: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Authentication Events
# =============================================================================

class LoginSuccessful(IdentityDomainEvent):
    """Event raised on successful login."""
    user_id: UUID
    session_id: UUID
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    risk_score: float = Field(default=0.0)
    mfa_used: bool = Field(default=False)
    trusted_device: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class LoginFailed(IdentityDomainEvent):
    """Event raised on failed login attempt."""
    email: str
    ip_address: str
    user_agent: str
    failure_reason: str
    risk_score: float = Field(default=0.0)
    device_fingerprint: str | None = None
    user_id: UUID | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.email


class AccountLockedOut(IdentityDomainEvent):
    """Event raised when account is locked due to failed login attempts."""
    user_id: UUID
    locked_at: datetime
    lockout_duration_minutes: int
    failed_attempt_count: int
    last_failed_ip: str
    unlock_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class AccountUnlocked(IdentityDomainEvent):
    """Event raised when a locked account is unlocked."""
    user_id: UUID
    unlocked_at: datetime
    unlocked_by: UUID | None
    unlock_method: str  # automatic, manual, user_request

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserLocked(IdentityDomainEvent):
    """Event raised when user account is locked."""
    user_id: UUID
    locked_until: datetime
    lock_reason: str
    locked_at: datetime = Field(default_factory=datetime.utcnow)
    locked_by: UUID | None = None
    automatic_lock: bool = Field(default=False)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserUnlocked(IdentityDomainEvent):
    """Event raised when user account is unlocked."""
    user_id: UUID
    unlocked_by: UUID
    unlocked_at: datetime = Field(default_factory=datetime.utcnow)
    unlock_reason: str | None = None
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Login Attempt Events (From Admin - for moved entity)
# =============================================================================

class LoginAttemptRecorded(IdentityDomainEvent):
    """Event raised when a login attempt is recorded."""
    attempt_id: UUID
    user_id: UUID | None
    email: str
    success: bool
    failure_reason: str | None
    ip_address: str
    risk_score: float
    timestamp: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id) if self.user_id else self.email


# =============================================================================
# Password Events
# =============================================================================

class PasswordChanged(IdentityDomainEvent):
    """Event raised when password is changed."""
    user_id: UUID
    changed_by: UUID | None = None
    strength_score: float = Field(default=0.0)
    force_password_change: bool = Field(default=False)
    password_age_days: int = Field(default=0)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PasswordExpired(IdentityDomainEvent):
    """Event raised when password expires based on policy."""
    user_id: UUID
    password_age_days: int
    max_age_days: int
    force_change_required: bool

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PasswordResetRequested(IdentityDomainEvent):
    """Event raised when password reset is requested."""
    user_id: UUID
    reset_token: str
    expires_at: datetime
    requested_ip: str
    requested_user_agent: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserPasswordChanged(IdentityDomainEvent):
    """Event raised when user password is changed."""
    user_id: UUID
    changed_by: UUID
    sessions_invalidated: bool
    changed_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Email Events
# =============================================================================

class EmailVerificationRequested(IdentityDomainEvent):
    """Event raised when email verification is requested."""
    user_id: UUID
    email: str
    verification_token: str
    expires_at: datetime
    verification_type: str = Field(default="registration")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class EmailVerified(IdentityDomainEvent):
    """Event raised when email is successfully verified."""
    user_id: UUID
    email: str
    verified_at: datetime
    verification_method: str = Field(default="email_link")
    previous_email: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserEmailChanged(IdentityDomainEvent):
    """Event raised when user email is changed."""
    user_id: UUID
    old_email: str
    new_email: str
    changed_at: datetime = Field(default_factory=datetime.utcnow)
    changed_by: UUID | None = None
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Phone Events
# =============================================================================

class PhoneNumberAdded(IdentityDomainEvent):
    """Event raised when phone number is added to account."""
    user_id: UUID
    phone_number: str
    is_primary: bool = Field(default=False)
    added_at: datetime = Field(default_factory=datetime.utcnow)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PhoneNumberVerified(IdentityDomainEvent):
    """Event raised when phone number is verified."""
    user_id: UUID
    phone_number: str
    verification_method: str = Field(default="sms_code")
    verified_at: datetime = Field(default_factory=datetime.utcnow)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PhoneNumberChanged(IdentityDomainEvent):
    """Event raised when phone number is changed."""
    user_id: UUID
    old_phone_number: str
    new_phone_number: str
    changed_at: datetime = Field(default_factory=datetime.utcnow)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class PhoneNumberRemoved(IdentityDomainEvent):
    """Event raised when phone number is removed."""
    user_id: UUID
    phone_number: str
    removed_by: UUID
    removed_at: datetime = Field(default_factory=datetime.utcnow)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# MFA Events (User-level)
# =============================================================================

class MFAEnabled(IdentityDomainEvent):
    """Event raised when MFA is enabled for a user."""
    user_id: UUID
    device_id: UUID
    device_type: str
    device_name: str
    enabled_at: datetime
    backup_codes_generated: bool = Field(default=True)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class MFADisabled(IdentityDomainEvent):
    """Event raised when MFA is disabled for a user."""
    user_id: UUID
    device_id: UUID
    disabled_by: UUID | None = None
    reason: str = Field(default="user_request")
    emergency_disable: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserMFAEnabled(IdentityDomainEvent):
    """Event raised when MFA is enabled."""
    user_id: UUID
    mfa_method: str
    enabled_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserMFADisabled(IdentityDomainEvent):
    """Event raised when MFA is disabled."""
    user_id: UUID
    disabled_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class BackupCodeGenerated(IdentityDomainEvent):
    """Event raised when backup codes are generated for MFA."""
    user_id: UUID
    code_count: int
    generated_by: UUID | None
    expires_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class BackupCodeUsed(IdentityDomainEvent):
    """Event raised when a backup code is used."""
    user_id: UUID
    code_hash: str
    used_at: datetime
    remaining_codes: int
    ip_address: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Biometric Events
# =============================================================================

class BiometricRegistered(IdentityDomainEvent):
    """Event raised when biometric authentication is registered."""
    user_id: UUID
    biometric_id: UUID
    biometric_type: str  # fingerprint, face, voice
    device_id: UUID
    template_hash: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class BiometricVerified(IdentityDomainEvent):
    """Event raised when biometric verification succeeds."""
    user_id: UUID
    biometric_id: UUID
    biometric_type: str
    confidence_score: float
    device_id: UUID

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Device Events (User-level)
# =============================================================================

class DeviceRegistered(IdentityDomainEvent):
    """Event raised when a device is registered."""
    user_id: UUID
    device_id: UUID
    device_name: str
    device_type: str
    fingerprint: str
    trusted: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class DeviceTrusted(IdentityDomainEvent):
    """Event raised when a device is marked as trusted."""
    user_id: UUID
    device_id: UUID
    trusted_by: UUID | None = None
    trust_method: str = Field(default="user_confirmation")

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# API Key Events
# =============================================================================

class APIKeyCreated(IdentityDomainEvent):
    """Event raised when API key is created."""
    api_key_id: UUID
    user_id: UUID
    key_name: str
    permissions: list[str]
    expires_at: datetime | None
    created_by: UUID

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class APIKeyRevoked(IdentityDomainEvent):
    """Event raised when API key is revoked."""
    api_key_id: UUID
    user_id: UUID
    revoked_by: UUID
    revocation_reason: str

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Emergency Contact Events
# =============================================================================

class EmergencyContactAdded(IdentityDomainEvent):
    """Event raised when an emergency contact is added."""
    user_id: UUID
    contact_id: UUID
    contact_name: str
    relationship: str
    phone: str
    is_primary: bool = Field(default=False)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class EmergencyContactVerified(IdentityDomainEvent):
    """Event raised when an emergency contact is verified."""
    user_id: UUID
    contact_id: UUID
    verification_method: str
    verified_at: datetime

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Risk & Privacy Events
# =============================================================================

class RiskLevelChanged(IdentityDomainEvent):
    """Event raised when user's risk level changes."""
    user_id: UUID
    old_risk_level: str
    new_risk_level: str
    risk_factors: list[str]
    risk_score: float
    assessed_by: str  # system, manual

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserExported(IdentityDomainEvent):
    """Event raised when user data is exported for GDPR compliance."""
    user_id: UUID
    export_id: UUID
    export_format: str
    data_categories: list[str]
    requested_by: UUID
    gdpr_request: bool = Field(default=True)

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class ConsentGranted(IdentityDomainEvent):
    """Event raised when user grants consent."""
    user_id: UUID
    consent_type: str
    consent_version: str
    granted_at: datetime
    ip_address: str
    valid_until: datetime | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class ConsentRevoked(IdentityDomainEvent):
    """Event raised when user revokes consent."""
    user_id: UUID
    consent_type: str
    revoked_at: datetime
    revocation_reason: str | None = None

    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Session Events (User-level)
# =============================================================================

class UserSessionCreated(IdentityDomainEvent):
    """Event raised when a new session is created."""
    user_id: UUID
    session_id: UUID
    ip_address: str
    user_agent: str
    device_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class SessionRevoked(IdentityDomainEvent):
    """Event raised when a session is revoked."""
    session_id: UUID
    user_id: UUID
    reason: str
    revoke_all_sessions: bool = False
    revoked_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# =============================================================================
# Role & Permission Events
# =============================================================================

class UserRoleAssigned(IdentityDomainEvent):
    """Event raised when a role is assigned to user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    assigned_by: UUID
    assigned_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserRoleRevoked(IdentityDomainEvent):
    """Event raised when a role is revoked from user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    revoked_by: UUID
    revoked_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserPermissionGranted(IdentityDomainEvent):
    """Event raised when a permission is granted to user."""
    user_id: UUID
    permission_id: UUID
    permission_name: str
    granted_by: UUID
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


class UserPermissionRevoked(IdentityDomainEvent):
    """Event raised when a permission is revoked from user."""
    user_id: UUID
    permission_id: UUID
    permission_name: str
    revoked_by: UUID
    revoked_at: datetime = Field(default_factory=datetime.utcnow)
    
    def get_aggregate_id(self) -> str:
        return str(self.user_id)


# Export all events (alphabetically sorted)
__all__ = [
    'APIKeyCreated',
    'APIKeyRevoked',
    'AccountLockedOut',
    'AccountUnlocked',
    'AvatarChanged',
    'AvatarDeleted',
    'AvatarUploaded',
    'BackupCodeGenerated',
    'BackupCodeUsed',
    'BiometricRegistered',
    'BiometricVerified',
    'ConsentGranted',
    'ConsentRevoked',
    'DeviceRegistered',
    'DeviceTrusted',
    'EmailVerificationRequested',
    'EmailVerified',
    'EmergencyContactAdded',
    'EmergencyContactVerified',
    'LoginAttemptRecorded',
    'LoginFailed',
    'LoginSuccessful',
    'MFADisabled',
    'MFAEnabled',
    'PasswordChanged',
    'PasswordExpired',
    'PasswordResetRequested',
    'PhoneNumberAdded',
    'PhoneNumberChanged',
    'PhoneNumberRemoved',
    'PhoneNumberVerified',
    'ProfileCompleted',
    'ProfileUpdated',
    'RiskLevelChanged',
    'SessionRevoked',
    'UserActivated',
    'UserCreated',
    'UserDeactivated',
    'UserDeleted',
    'UserEmailChanged',
    'UserExported',
    'UserLocked',
    'UserMFADisabled',
    'UserMFAEnabled',
    'UserPasswordChanged',
    'UserPermissionGranted',
    'UserPermissionRevoked',
    'UserProfileUpdated',
    'UserReactivated',
    'UserRegistered',
    'UserReinstated',
    'UserRoleAssigned',
    'UserRoleRevoked',
    'UserSessionCreated',
    'UserSuspended',
    'UserUnlocked'
]