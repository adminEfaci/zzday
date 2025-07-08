"""
DTOs for command parameters to reduce function arguments.

Groups related parameters into logical units for cleaner interfaces.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    ICacheService,
    IEmailService,
    INotificationService,
    IPermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    ISessionRepository,
    ITokenRepository,
    IUserRepository,
)
from app.modules.identity.domain.enums import (
    PermissionScope,
    PermissionType,
    TokenType,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    EncryptionService,
    MFAService,
    SecurityService,
    TokenService,
    ValidationService,
)


@dataclass
class RepositoryDependencies:
    """Groups all repository dependencies."""
    
    user_repository: IUserRepository | None = None
    role_repository: IRoleRepository | None = None
    permission_repository: IPermissionRepository | None = None
    session_repository: ISessionRepository | None = None
    token_repository: ITokenRepository | None = None
    security_event_repository: ISecurityEventRepository | None = None


@dataclass
class ServiceDependencies:
    """Groups all service dependencies."""
    
    authorization_service: AuthorizationService | None = None
    validation_service: ValidationService | None = None
    security_service: SecurityService | None = None
    mfa_service: MFAService | None = None
    token_service: TokenService | None = None
    encryption_service: EncryptionService | None = None
    notification_service: INotificationService | None = None
    email_service: IEmailService | None = None
    audit_service: IAuditService | None = None
    cache_service: ICacheService | None = None


@dataclass
class InfrastructureDependencies:
    """Groups infrastructure dependencies."""
    
    event_bus: EventBus
    unit_of_work: UnitOfWork


@dataclass
class CommandHandlerDependencies:
    """Consolidated dependencies for command handlers."""
    
    repositories: RepositoryDependencies
    services: ServiceDependencies
    infrastructure: InfrastructureDependencies


@dataclass
class PermissionCreationParams:
    """Parameters for creating a permission."""
    
    # Basic information
    name: str
    display_name: str
    description: str
    created_by: UUID
    
    # Permission details
    resource_type: str
    action: str
    permission_type: PermissionType = PermissionType.ALLOW
    scope: PermissionScope = PermissionScope.GLOBAL
    
    # Flags
    is_system: bool = False
    is_critical: bool = False
    is_sensitive: bool = False
    
    # Categorization
    category: str | None = None
    tags: list[str] | None = None
    
    # Relationships
    prerequisites: dict[str, Any] | None = None
    implies: list[UUID] | None = None
    mutually_exclusive_with: list[UUID] | None = None
    
    # Additional data
    conditions: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class RoleCreationParams:
    """Parameters for creating a role."""
    
    # Basic information
    name: str
    display_name: str
    description: str
    created_by: UUID
    
    # Role details
    parent_role_id: UUID | None = None
    permissions: list[UUID] | None = None
    
    # Flags
    is_system: bool = False
    is_default: bool = False
    is_exclusive: bool = False
    
    # Additional data
    metadata: dict[str, Any] | None = None
    tags: list[str] | None = None


@dataclass
class ExtendedRoleCreationParams(RoleCreationParams):
    """Extended parameters for creating a role with additional options."""
    
    role_type: str | None = None
    hierarchy_level: int = 0
    max_assignments: int | None = None
    prerequisites: dict[str, Any] | None = None
    grantable_roles: list[UUID] | None = None
    grantable_permissions: list[UUID] | None = None


@dataclass
class UserRegistrationParams:
    """Parameters for user registration."""
    
    # Basic information
    email: str
    username: str
    password: str
    
    # Profile information
    first_name: str | None = None
    last_name: str | None = None
    phone_number: str | None = None
    
    # Settings
    timezone: str | None = None
    language: str | None = None
    
    # Additional data
    metadata: dict[str, Any] | None = None
    tags: list[str] | None = None


@dataclass
class SessionCreationParams:
    """Parameters for creating a session."""
    
    user_id: UUID
    device_id: str
    ip_address: str
    user_agent: str
    
    # Optional
    location: str | None = None
    device_name: str | None = None
    session_metadata: dict[str, Any] | None = None


@dataclass
class TokenGenerationParams:
    """Parameters for generating tokens."""
    
    user_id: UUID
    token_type: TokenType
    
    # Optional
    scopes: list[str] | None = None
    expires_in_seconds: int | None = None
    metadata: dict[str, Any] | None = None
    audience: str | None = None
    issuer: str | None = None


@dataclass
class AuthenticationParams:
    """Parameters for authentication."""
    
    email: str
    password: str
    
    # Optional
    device_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    remember_me: bool = False
    mfa_code: str | None = None


@dataclass
class SecurityEventParams:
    """Parameters for security events."""
    
    event_type: str
    user_id: UUID | None
    severity: str
    
    # Event details
    details: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    
    # Additional context
    metadata: dict[str, Any] | None = None
    indicators: list[str] | None = None
    recommended_actions: list[str] | None = None


@dataclass
class PermissionGrantParams:
    """Parameters for granting permissions."""
    
    user_id: UUID
    permission_id: UUID
    granted_by: UUID
    
    # Optional
    expires_at: datetime | None = None
    conditions: dict[str, Any] | None = None
    reason: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class PermissionRevocationParams:
    """Parameters for revoking permissions."""
    
    user_id: UUID
    permission_id: UUID
    revoked_by: UUID
    reason: str
    
    # Options
    resource_type: str | None = None
    resource_id: UUID | None = None
    cascade_dependent: bool = True
    force_revoke: bool = False
    revoke_sessions: bool = False
    notify_user: bool = True
    
    # Additional data
    metadata: dict[str, Any] | None = None


@dataclass
class RoleAssignmentParams:
    """Parameters for role assignment."""
    
    user_id: UUID
    role_id: UUID
    assigned_by: UUID
    
    # Optional
    expires_at: datetime | None = None
    reason: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class AuditParams:
    """Parameters for audit logging."""
    
    action: str
    resource_type: str
    resource_id: UUID | None
    user_id: UUID
    
    # Optional
    details: dict[str, Any] | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class NotificationParams:
    """Parameters for notifications."""
    
    recipient_id: UUID
    notification_type: str
    
    # Content
    title: str
    message: str
    
    # Optional
    channel: str = "in_app"
    priority: str = "normal"
    template_data: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class PasswordResetParams:
    """Parameters for password reset."""
    
    user_id: UUID
    new_password: str
    
    # Verification
    reset_token: str | None = None
    current_password: str | None = None
    
    # Context
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass
class TokenInvalidationParams:
    """Parameters for token invalidation."""
    
    user_id: UUID
    password: str
    reason: str
    
    # Options
    include_api_keys: bool = False
    notify_user: bool = True
    
    # Context
    ip_address: str | None = None
    initiated_by: UUID | None = None


@dataclass
class PermissionUpdateParams:
    """Parameters for updating a permission."""
    
    permission_id: UUID
    updated_by: UUID
    
    # Basic information updates
    display_name: str | None = None
    description: str | None = None
    
    # Flag updates
    is_critical: bool | None = None
    is_sensitive: bool | None = None
    is_active: bool | None = None
    
    # Categorization updates
    category: str | None = None
    tags: list[str] | None = None
    
    # Relationship updates
    prerequisites: dict[str, Any] | None = None
    implies_to_add: list[UUID] | None = None
    implies_to_remove: list[UUID] | None = None
    exclusions_to_add: list[UUID] | None = None
    exclusions_to_remove: list[UUID] | None = None
    
    # Additional updates
    conditions: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    
    # Update options
    force_update: bool = False
    notify_affected: bool = True


@dataclass
class PermissionDeletionParams:
    """Parameters for deleting a permission."""
    
    permission_id: UUID
    deleted_by: UUID
    reason: str
    
    # Deletion options
    force_delete: bool = False
    cascade_grants: bool = True
    remove_from_roles: bool = True
    create_backup: bool = True
    notify_affected: bool = True
    
    # Optional replacement
    replace_with_permission_id: UUID | None = None
    
    # Additional data
    metadata: dict[str, Any] | None = None


@dataclass
class RoleDeletionParams:
    """Parameters for deleting a role."""
    
    role_id: UUID
    deleted_by: UUID
    reason: str
    
    # Deletion options
    force_delete: bool = False
    cascade_assignments: bool = True
    create_backup: bool = True
    notify_affected: bool = True
    
    # Optional replacement
    replace_with_role_id: UUID | None = None
    
    # Additional data
    metadata: dict[str, Any] | None = None


@dataclass
class EmergencyContactParams:
    """Parameters for creating an emergency contact."""
    
    user_id: UUID
    contact_name: str
    relationship: str
    phone: str
    
    # Optional information
    email: str | None = None
    address: dict[str, Any] | None = None
    notes: str | None = None
    is_primary: bool = False


@dataclass
class LoginAttemptParams:
    """Parameters for creating login attempts."""
    
    email: str
    ip_address: str
    user_agent: str
    
    # Success-specific
    user_id: UUID | None = None
    session_id: UUID | None = None
    mfa_used: bool = False
    
    # Failure-specific
    failure_reason: str | None = None
    
    # Common
    risk_score: float = 0.0
    risk_indicators: list[str] | None = None


@dataclass
class DeviceQuarantineParams:
    """Parameters for quarantining a device."""
    
    device_id: UUID
    user_id: UUID
    quarantined_by: UUID
    reason: str
    
    # Quarantine options
    severity: str = "high"
    disable_network_access: bool = True
    revoke_credentials: bool = True
    force_logout: bool = True
    block_data_transfer: bool = True
    restrict_app_access: bool = True
    
    # Advanced options
    duration_hours: int | None = None
    auto_review_enabled: bool = True
    notify_user: bool = True
    notify_security_team: bool = True
    create_forensic_backup: bool = False
    
    # Incident tracking
    security_incident_id: UUID | None = None
    evidence_collection_required: bool = False
    compliance_hold: bool = False
    
    # Contacts and metadata
    escalation_contacts: list[str] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ExtendedRepositoryDependencies(RepositoryDependencies):
    """Extended repository dependencies for complex handlers."""
    
    device_repository: Any | None = None
    quarantine_repository: Any | None = None
    device_policy_repository: Any | None = None
    mfa_device_repository: Any | None = None
    login_attempt_repository: Any | None = None
    backup_repository: Any | None = None


@dataclass
class ExtendedServiceDependencies(ServiceDependencies):
    """Extended service dependencies for complex handlers."""
    
    device_security_service: Any | None = None
    quarantine_service: Any | None = None
    session_service: Any | None = None
    sms_service: Any | None = None
    backup_service: Any | None = None
    device_fingerprint_service: Any | None = None
    geolocation_service: Any | None = None
    password_service: Any | None = None


@dataclass
class ExtendedCommandHandlerDependencies:
    """Extended dependencies for complex command handlers."""
    
    repositories: ExtendedRepositoryDependencies
    services: ExtendedServiceDependencies
    infrastructure: InfrastructureDependencies


@dataclass
class GraphQLResolverDependencies:
    """Dependencies for GraphQL resolvers."""
    
    repositories: RepositoryDependencies
    services: ServiceDependencies
    command_bus: Any | None = None
    query_bus: Any | None = None


@dataclass
class AuditEventParams:
    """Parameters for audit event logging."""
    
    context: Any | None
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, Any] | None = None
    risk_level: str = "low"