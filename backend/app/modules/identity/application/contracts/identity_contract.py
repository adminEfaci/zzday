"""
Identity Module Contract

Defines the public API for the Identity module including all
events, commands, and queries that other modules can use.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Type
from uuid import UUID

from app.core.contracts import (
    ModuleContract,
    ContractEvent,
    ContractCommand,
    ContractQuery,
)


# ===== EVENTS =====
# Events that the Identity module publishes

@dataclass(frozen=True)
class UserRegisteredEvent(ContractEvent):
    """A new user has been registered in the system."""
    user_id: UUID
    email: str
    username: str
    registered_at: datetime
    requires_verification: bool = True


@dataclass(frozen=True)
class UserLoggedInEvent(ContractEvent):
    """A user has successfully logged in."""
    user_id: UUID
    session_id: UUID
    ip_address: str
    user_agent: str
    logged_in_at: datetime
    mfa_used: bool = False


@dataclass(frozen=True)
class UserLoggedOutEvent(ContractEvent):
    """A user has logged out."""
    user_id: UUID
    session_id: UUID
    logged_out_at: datetime


@dataclass(frozen=True)
class LoginFailedEvent(ContractEvent):
    """A login attempt has failed."""
    email: str
    ip_address: str
    reason: str
    attempt_number: int
    failed_at: datetime


@dataclass(frozen=True)
class UserLockedOutEvent(ContractEvent):
    """A user account has been locked due to too many failed attempts."""
    user_id: UUID
    locked_until: datetime
    reason: str
    locked_at: datetime


@dataclass(frozen=True)
class UserActivatedEvent(ContractEvent):
    """A user account has been activated."""
    user_id: UUID
    activated_at: datetime


@dataclass(frozen=True)
class UserDeactivatedEvent(ContractEvent):
    """A user account has been deactivated."""
    user_id: UUID
    reason: str
    deactivated_at: datetime
    deactivated_by: Optional[UUID] = None


@dataclass(frozen=True)
class UserDeletedEvent(ContractEvent):
    """A user account has been deleted."""
    user_id: UUID
    deleted_at: datetime
    deletion_type: str  # "soft" or "hard"


@dataclass(frozen=True)
class PasswordChangedEvent(ContractEvent):
    """A user's password has been changed."""
    user_id: UUID
    changed_at: datetime
    change_method: str  # "user", "admin", "reset"


@dataclass(frozen=True)
class PasswordResetRequestedEvent(ContractEvent):
    """A password reset has been requested."""
    user_id: UUID
    email: str
    token_id: UUID
    requested_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class MFAEnabledEvent(ContractEvent):
    """Multi-factor authentication has been enabled."""
    user_id: UUID
    mfa_method: str  # "totp", "sms", "email", "hardware"
    enabled_at: datetime


@dataclass(frozen=True)
class MFADisabledEvent(ContractEvent):
    """Multi-factor authentication has been disabled."""
    user_id: UUID
    mfa_method: str
    disabled_at: datetime
    reason: str


@dataclass(frozen=True)
class RoleAssignedEvent(ContractEvent):
    """A role has been assigned to a user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    assigned_by: UUID
    assigned_at: datetime


@dataclass(frozen=True)
class RoleRevokedEvent(ContractEvent):
    """A role has been revoked from a user."""
    user_id: UUID
    role_id: UUID
    role_name: str
    revoked_by: UUID
    revoked_at: datetime


@dataclass(frozen=True)
class SessionExpiredEvent(ContractEvent):
    """A user session has expired."""
    user_id: UUID
    session_id: UUID
    expired_at: datetime
    reason: str  # "timeout", "manual", "security"


@dataclass(frozen=True)
class SecurityAlertEvent(ContractEvent):
    """A security alert has been triggered."""
    user_id: Optional[UUID]
    alert_type: str  # "suspicious_login", "password_breach", "unusual_activity"
    severity: str  # "low", "medium", "high", "critical"
    details: Dict[str, str]
    triggered_at: datetime


# ===== COMMANDS =====
# Commands that the Identity module accepts

@dataclass
class RegisterUserCommand(ContractCommand):
    """Command to register a new user."""
    email: str
    username: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None


@dataclass
class AuthenticateUserCommand(ContractCommand):
    """Command to authenticate a user."""
    email: str
    password: str
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None


@dataclass
class LogoutUserCommand(ContractCommand):
    """Command to logout a user."""
    user_id: UUID
    session_id: UUID
    logout_all_sessions: bool = False


@dataclass
class ChangePasswordCommand(ContractCommand):
    """Command to change a user's password."""
    user_id: UUID
    current_password: str
    new_password: str


@dataclass
class ResetPasswordCommand(ContractCommand):
    """Command to reset a user's password."""
    token: str
    new_password: str


@dataclass
class EnableMFACommand(ContractCommand):
    """Command to enable MFA for a user."""
    user_id: UUID
    mfa_method: str
    setup_data: Dict[str, str]  # Method-specific setup data


@dataclass
class DisableMFACommand(ContractCommand):
    """Command to disable MFA for a user."""
    user_id: UUID
    mfa_method: str
    verification_code: str
    reason: str


@dataclass
class AssignRoleCommand(ContractCommand):
    """Command to assign a role to a user."""
    user_id: UUID
    role_id: UUID
    assigned_by: UUID


@dataclass
class RevokeRoleCommand(ContractCommand):
    """Command to revoke a role from a user."""
    user_id: UUID
    role_id: UUID
    revoked_by: UUID
    reason: str


@dataclass
class ActivateUserCommand(ContractCommand):
    """Command to activate a user account."""
    user_id: UUID
    activation_token: Optional[str] = None


@dataclass
class DeactivateUserCommand(ContractCommand):
    """Command to deactivate a user account."""
    user_id: UUID
    reason: str
    deactivated_by: UUID


# ===== QUERIES =====
# Queries that the Identity module supports

@dataclass
class GetUserByIdQuery(ContractQuery):
    """Query to get user information by ID."""
    user_id: UUID
    include_roles: bool = False
    include_permissions: bool = False


@dataclass
class GetUserByEmailQuery(ContractQuery):
    """Query to get user information by email."""
    email: str
    include_roles: bool = False
    include_permissions: bool = False


@dataclass
class GetUserSessionsQuery(ContractQuery):
    """Query to get active sessions for a user."""
    user_id: UUID
    include_expired: bool = False
    limit: int = 10


@dataclass
class GetUserRolesQuery(ContractQuery):
    """Query to get roles assigned to a user."""
    user_id: UUID
    include_permissions: bool = False


@dataclass
class GetUserPermissionsQuery(ContractQuery):
    """Query to get effective permissions for a user."""
    user_id: UUID
    resource_type: Optional[str] = None


@dataclass
class CheckPermissionQuery(ContractQuery):
    """Query to check if a user has a specific permission."""
    user_id: UUID
    permission: str
    resource_id: Optional[UUID] = None
    context: Optional[Dict[str, str]] = None


@dataclass
class SearchUsersQuery(ContractQuery):
    """Query to search for users."""
    search_term: Optional[str] = None
    filters: Optional[Dict[str, str]] = None
    page: int = 1
    page_size: int = 20
    sort_by: str = "created_at"
    sort_order: str = "desc"


@dataclass
class GetSecurityEventsQuery(ContractQuery):
    """Query to get security events for a user."""
    user_id: UUID
    event_types: Optional[List[str]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 50


# ===== CONTRACT DEFINITION =====

class IdentityModuleContract(ModuleContract):
    """
    Contract definition for the Identity module.
    
    This contract defines all public events, commands, and queries
    that other modules can use to interact with the Identity module.
    """
    
    @property
    def module_name(self) -> str:
        return "identity"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def get_events(self) -> Dict[str, Type[ContractEvent]]:
        """Get all events exposed by the Identity module."""
        return {
            "UserRegistered": UserRegisteredEvent,
            "UserLoggedIn": UserLoggedInEvent,
            "UserLoggedOut": UserLoggedOutEvent,
            "LoginFailed": LoginFailedEvent,
            "UserLockedOut": UserLockedOutEvent,
            "UserActivated": UserActivatedEvent,
            "UserDeactivated": UserDeactivatedEvent,
            "UserDeleted": UserDeletedEvent,
            "PasswordChanged": PasswordChangedEvent,
            "PasswordResetRequested": PasswordResetRequestedEvent,
            "MFAEnabled": MFAEnabledEvent,
            "MFADisabled": MFADisabledEvent,
            "RoleAssigned": RoleAssignedEvent,
            "RoleRevoked": RoleRevokedEvent,
            "SessionExpired": SessionExpiredEvent,
            "SecurityAlert": SecurityAlertEvent,
        }
    
    def get_commands(self) -> Dict[str, Type[ContractCommand]]:
        """Get all commands accepted by the Identity module."""
        return {
            "RegisterUser": RegisterUserCommand,
            "AuthenticateUser": AuthenticateUserCommand,
            "LogoutUser": LogoutUserCommand,
            "ChangePassword": ChangePasswordCommand,
            "ResetPassword": ResetPasswordCommand,
            "EnableMFA": EnableMFACommand,
            "DisableMFA": DisableMFACommand,
            "AssignRole": AssignRoleCommand,
            "RevokeRole": RevokeRoleCommand,
            "ActivateUser": ActivateUserCommand,
            "DeactivateUser": DeactivateUserCommand,
        }
    
    def get_queries(self) -> Dict[str, Type[ContractQuery]]:
        """Get all queries supported by the Identity module."""
        return {
            "GetUserById": GetUserByIdQuery,
            "GetUserByEmail": GetUserByEmailQuery,
            "GetUserSessions": GetUserSessionsQuery,
            "GetUserRoles": GetUserRolesQuery,
            "GetUserPermissions": GetUserPermissionsQuery,
            "CheckPermission": CheckPermissionQuery,
            "SearchUsers": SearchUsersQuery,
            "GetSecurityEvents": GetSecurityEventsQuery,
        }


# Create and register the contract
identity_contract = IdentityModuleContract()