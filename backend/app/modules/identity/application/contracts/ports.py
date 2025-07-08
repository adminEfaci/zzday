"""
Identity domain ports (interfaces).

Defines contracts for repositories and external services.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.infrastructure.pagination import PagedResult
from app.modules.identity.application.dtos.query import (
    AccessLogQuery,
    ActivityQuery,
    SessionQuery,
)
from app.modules.identity.domain.aggregates import User
from app.modules.identity.domain.entities.admin.emergency_contact import (
    EmergencyContact,
)
from app.modules.identity.domain.entities.admin.login_attempt import LoginAttempt
from app.modules.identity.domain.entities.admin.mfa_device import MfaDevice
from app.modules.identity.domain.entities.admin.password_history import PasswordHistory
from app.modules.identity.domain.entities.device.device_registration import (
    DeviceRegistration,
)

# Domain Entities
from app.modules.identity.domain.entities.role.permission import Permission
from app.modules.identity.domain.entities.role.role import Role
from app.modules.identity.domain.entities.session.session import Session

# Domain Enums  
from app.modules.identity.domain.enums import *

# Domain Value Objects
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.username import Username

# Infrastructure Models (used as entities in repositories)
from app.modules.identity.infrastructure.persistence.sqlalchemy.models.audit_log import (
    AuditLog,
)


# Repository Interfaces
class IUserRepository(ABC):
    """User repository interface."""
    
    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> User | None:
        """Get user by ID."""
    
    @abstractmethod
    async def get_by_email(self, email: Email) -> User | None:
        """Get user by email."""
    
    @abstractmethod
    async def get_by_username(self, username: Username) -> User | None:
        """Get user by username."""
    
    @abstractmethod
    async def exists_by_email(self, email: Email) -> bool:
        """Check if user exists by email."""
    
    @abstractmethod
    async def exists_by_username(self, username: Username) -> bool:
        """Check if user exists by username."""
    
    @abstractmethod
    async def save(self, user: User) -> None:
        """Save user aggregate."""
    
    @abstractmethod
    async def delete(self, user_id: UUID) -> None:
        """Delete user."""
    
    @abstractmethod
    async def search(
        self,
        criteria: dict[str, Any],
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> PagedResult[User]:
        """Search users with pagination."""
    
    @abstractmethod
    async def search_users(
        self,
        criteria: dict[str, Any],
        sort_by: str = "created_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20
    ) -> list[dict[str, Any]]:
        """Search users returning dict format."""
    
    @abstractmethod
    async def count_users(self, criteria: dict[str, Any]) -> int:
        """Count users matching criteria."""
    
    @abstractmethod
    async def count_active_users(self) -> int:
        """Count active users."""
    
    @abstractmethod
    async def get_role_permissions(self, role: str) -> list[str]:
        """Get permissions for a role."""
    
    @abstractmethod
    async def get_user_effective_permissions(self, user_id: UUID) -> list[str]:
        """Get effective permissions for user."""
    
    @abstractmethod
    async def get_user_role_permissions(self, user_id: UUID) -> dict[str, list[str]]:
        """Get role-based permissions for user."""
    
    @abstractmethod
    async def get_role_hierarchy(self, role_name: str) -> dict[str, Any] | None:
        """Get role hierarchy."""
    
    @abstractmethod
    async def get_user_compliance_status(self, user_id: UUID) -> dict[str, Any]:
        """Get user compliance status."""
    
    @abstractmethod
    async def get_user_engagement_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> dict[str, Any]:
        """Get user engagement trends."""


class ISessionRepository(ABC):
    """Session repository interface."""
    
    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Create new session."""
    
    @abstractmethod
    async def get_by_id(self, session_id: UUID) -> Session | None:
        """Get session by ID."""
    
    @abstractmethod
    async def get_by_token(self, access_token: str) -> Session | None:
        """Get session by access token."""
    
    @abstractmethod
    async def get_by_refresh_token(self, refresh_token: str) -> Session | None:
        """Get session by refresh token."""
    
    @abstractmethod
    async def get_active_sessions(self, user_id: UUID) -> list[Session]:
        """Get all active sessions for user."""
    
    @abstractmethod
    async def update(self, session: Session) -> None:
        """Update session."""
    
    @abstractmethod
    async def revoke(self, session_id: UUID) -> None:
        """Revoke session."""
    
    @abstractmethod
    async def revoke_all_for_user(self, user_id: UUID, except_session_id: UUID | None = None) -> None:
        """Revoke all sessions for user."""
    
    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
    
    @abstractmethod
    async def get_user_sessions(
        self,
        query: SessionQuery
    ) -> list[dict[str, Any]]:
        """Get user sessions with filters."""
    
    @abstractmethod
    async def count_user_sessions(
        self,
        user_id: UUID,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        active_only: bool = False
    ) -> int:
        """Count user sessions."""
    
    @abstractmethod
    async def get_user_session_summary(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user session summary."""
    
    @abstractmethod
    async def get_session_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get session statistics."""


class IRoleRepository(ABC):
    """Role repository interface."""
    
    @abstractmethod
    async def get_by_id(self, role_id: UUID) -> Role | None:
        """Get role by ID."""
    
    @abstractmethod
    async def get_by_name(self, name: str) -> Role | None:
        """Get role by name."""
    
    @abstractmethod
    async def get_user_roles(self, user_id: UUID) -> list[Role]:
        """Get all roles for user."""
    
    @abstractmethod
    async def exists(self, role_id: UUID) -> bool:
        """Check if role exists."""
    
    @abstractmethod
    async def save(self, role: Role) -> None:
        """Save role."""
    
    @abstractmethod
    async def delete(self, role_id: UUID) -> None:
        """Delete role."""
    
    @abstractmethod
    async def get_all(self) -> list[Role]:
        """Get all roles."""


class IPermissionRepository(ABC):
    """Permission repository interface."""
    
    @abstractmethod
    async def get_by_id(self, permission_id: UUID) -> Permission | None:
        """Get permission by ID."""
    
    @abstractmethod
    async def get_by_name(self, name: str) -> Permission | None:
        """Get permission by name."""
    
    @abstractmethod
    async def get_user_permissions(self, user_id: UUID) -> list[Permission]:
        """Get all permissions for user (direct + inherited)."""
    
    @abstractmethod
    async def get_direct_permissions(self, user_id: UUID) -> list[Permission]:
        """Get direct permissions for user."""
    
    @abstractmethod
    async def get_role_permissions(self, role_id: UUID) -> list[Permission]:
        """Get permissions for role."""
    
    @abstractmethod
    async def save(self, permission: Permission) -> None:
        """Save permission."""
    
    @abstractmethod
    async def delete(self, permission_id: UUID) -> None:
        """Delete permission."""


class IAuditRepository(ABC):
    """Audit repository interface."""
    
    @abstractmethod
    async def log(self, audit_log: AuditLog) -> None:
        """Log audit entry."""
    
    @abstractmethod
    async def search_logs(
        self,
        criteria: dict[str, Any],
        page: int = 1,
        page_size: int = 50
    ) -> PagedResult[AuditLog]:
        """Search audit logs."""
    
    @abstractmethod
    async def get_audit_trail(
        self,
        filters: dict[str, Any],
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> list[dict[str, Any]]:
        """Get audit trail with filters."""
    
    @abstractmethod
    async def count_audit_entries(self, filters: dict[str, Any]) -> int:
        """Count audit entries matching filters."""
    
    @abstractmethod
    async def get_audit_statistics(self, filters: dict[str, Any]) -> dict[str, Any]:
        """Get audit statistics."""
    
    @abstractmethod
    async def get_risk_distribution(self, filters: dict[str, Any]) -> dict[str, Any]:
        """Get risk distribution."""
    
    @abstractmethod
    async def get_top_actions(self, filters: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
        """Get top actions."""
    
    @abstractmethod
    async def get_geographic_distribution(self, filters: dict[str, Any]) -> dict[str, Any]:
        """Get geographic distribution."""
    
    @abstractmethod
    async def get_user_activities(
        self,
        query: ActivityQuery
    ) -> list[dict[str, Any]]:
        """Get user activities."""
    
    @abstractmethod
    async def count_user_activities(self, user_id: UUID, filters: dict[str, Any]) -> int:
        """Count user activities."""
    
    @abstractmethod
    async def get_user_activity_summary(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user activity summary."""
    
    @abstractmethod
    async def get_user_login_pattern(
        self,
        user_id: UUID,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user login pattern."""
    
    @abstractmethod
    async def get_user_audit_trail(self, user_id: UUID, limit: int = 50) -> list[dict[str, Any]]:
        """Get user audit trail."""
    
    @abstractmethod
    async def get_user_risk_assessment(self, user_id: UUID) -> dict[str, Any] | None:
        """Get user risk assessment."""
    
    @abstractmethod
    async def count_activities(self, start_date: datetime, end_date: datetime) -> int:
        """Count activities in date range."""
    
    @abstractmethod
    async def get_activity_breakdown_by_type(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, int]:
        """Get activity breakdown by type."""
    
    @abstractmethod
    async def get_user_activity_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user activity statistics."""
    
    @abstractmethod
    async def get_resource_access_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get resource access statistics."""
    
    @abstractmethod
    async def count_failed_authentications(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> int:
        """Count failed authentication attempts."""
    
    @abstractmethod
    async def count_privilege_escalations(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> int:
        """Count privilege escalation events."""
    
    @abstractmethod
    async def get_activity_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> dict[str, Any]:
        """Get activity trends."""
    
    @abstractmethod
    async def get_login_patterns(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get login patterns."""
    
    @abstractmethod
    async def get_user_activity_patterns(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user activity patterns."""
    
    @abstractmethod
    async def get_location_analysis(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get location analysis."""
    
    @abstractmethod
    async def count_events(self, start_date: datetime, end_date: datetime) -> int:
        """Count events in date range."""
    
    @abstractmethod
    async def get_compliance_audit_data(
        self,
        requirement_id: str,
        start_date: datetime,
        end_date: datetime
    ) -> list[dict[str, Any]]:
        """Get compliance audit data for requirement."""
    
    @abstractmethod
    async def get_time_series_data(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> list[dict[str, Any]]:
        """Get time series data."""
    
    @abstractmethod
    async def get_summary_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get summary statistics."""
    
    @abstractmethod
    async def get_system_performance_metrics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get system performance metrics."""
    
    @abstractmethod
    async def get_audit_performance_metrics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get audit performance metrics."""


class IMFARepository(ABC):
    """MFA repository interface."""
    
    @abstractmethod
    async def get_device(self, device_id: UUID) -> MfaDevice | None:
        """Get MFA device by ID."""
    
    @abstractmethod
    async def get_user_devices(self, user_id: UUID) -> list[MfaDevice]:
        """Get all MFA devices for user."""
    
    @abstractmethod
    async def create_device(self, device: MfaDevice) -> MfaDevice:
        """Create MFA device."""
    
    @abstractmethod
    async def update_device(self, device: MfaDevice) -> None:
        """Update MFA device."""
    
    @abstractmethod
    async def delete_device(self, device_id: UUID) -> None:
        """Delete MFA device."""


class IMFADeviceRepository(ABC):
    """MFA device repository interface."""
    
    @abstractmethod
    async def add(self, device: MfaDevice) -> None:
        """Add MFA device."""
    
    @abstractmethod
    async def get_by_id(self, device_id: UUID) -> MfaDevice | None:
        """Get MFA device by ID."""
    
    @abstractmethod
    async def get_by_user_id(self, user_id: UUID) -> list[MfaDevice]:
        """Get all MFA devices for user."""
    
    @abstractmethod
    async def get_verified_devices(self, user_id: UUID) -> list[MfaDevice]:
        """Get verified MFA devices for user."""
    
    @abstractmethod
    async def get_by_user_and_method(
        self,
        user_id: UUID,
        method: MFAMethod
    ) -> list[MfaDevice]:
        """Get MFA devices by user and method."""
    
    @abstractmethod
    async def update(self, device: MfaDevice) -> None:
        """Update MFA device."""
    
    @abstractmethod
    async def delete(self, device_id: UUID) -> None:
        """Delete MFA device."""


class IMFAChallengeRepository(ABC):
    """MFA challenge repository interface."""
    
    @abstractmethod
    async def create_challenge(
        self,
        session_id: UUID,
        device_id: UUID,
        challenge_type: str
    ) -> str:
        """Create MFA challenge."""
    
    @abstractmethod
    async def get_challenge(self, session_id: UUID) -> dict[str, Any] | None:
        """Get active challenge for session."""
    
    @abstractmethod
    async def verify_challenge(
        self,
        session_id: UUID,
        code: str
    ) -> bool:
        """Verify challenge code."""
    
    @abstractmethod
    async def expire_challenge(self, session_id: UUID) -> None:
        """Expire MFA challenge."""


class ISecurityRepository(ABC):
    """Security repository interface."""
    
    @abstractmethod
    async def log_security_event(self, event: dict[str, Any]) -> None:
        """Log security event."""
    
    @abstractmethod
    async def get_recent_login_attempts(
        self,
        email: str | None = None,
        ip_address: str | None = None,
        minutes: int = 15
    ) -> list[LoginAttempt]:
        """Get recent login attempts."""
    
    @abstractmethod
    async def get_user_patterns(self, user_id: UUID) -> dict[str, Any]:
        """Get user behavior patterns."""
    
    @abstractmethod
    async def get_security_events(
        self,
        criteria: dict[str, Any],
        page: int = 1,
        page_size: int = 20
    ) -> PagedResult[dict[str, Any]]:
        """Get security events."""
    
    @abstractmethod
    async def get_security_events_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get security events statistics."""
    
    @abstractmethod
    async def count_suspicious_activities(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> int:
        """Count suspicious activities."""
    
    @abstractmethod
    async def get_risk_distribution(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get risk distribution."""
    
    @abstractmethod
    async def get_detailed_risk_distribution(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get detailed risk distribution."""
    
    @abstractmethod
    async def get_risk_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> dict[str, Any]:
        """Get risk trends."""
    
    @abstractmethod
    async def get_top_risk_factors(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> list[dict[str, Any]]:
        """Get top risk factors."""
    
    @abstractmethod
    async def get_security_trends(
        self,
        start_date: datetime,
        end_date: datetime,
        granularity: str
    ) -> dict[str, Any]:
        """Get security trends."""
    
    @abstractmethod
    async def get_policy_violations(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> list[dict[str, Any]]:
        """Get policy violations."""
    
    @abstractmethod
    async def find_correlated_events(
        self,
        event_id: str,
        criteria: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Find correlated security events."""
    
    @abstractmethod
    async def get_events_by_correlation_id(self, correlation_id: str) -> list[dict[str, Any]]:
        """Get events by correlation ID."""
    
    @abstractmethod
    async def get_events_by_session(self, session_id: UUID) -> list[dict[str, Any]]:
        """Get events by session ID."""
    
    @abstractmethod
    async def get_user_events_in_timeframe(
        self,
        user_id: UUID,
        start_time: datetime,
        end_time: datetime
    ) -> list[dict[str, Any]]:
        """Get user events in timeframe."""
    
    @abstractmethod
    async def count_security_events(self, filters: dict[str, Any]) -> int:
        """Count security events."""


class IDeviceRepository(ABC):
    """Device repository interface."""
    
    @abstractmethod
    async def register(self, device: DeviceRegistration) -> DeviceRegistration:
        """Register device."""
    
    @abstractmethod
    async def get_by_id(self, device_id: UUID) -> DeviceRegistration | None:
        """Get device by ID."""
    
    @abstractmethod
    async def get_by_fingerprint(self, fingerprint: str) -> DeviceRegistration | None:
        """Get device by fingerprint."""
    
    @abstractmethod
    async def get_user_devices(
        self,
        user_id: UUID,
        limit: int | None = None,
        include_inactive: bool = False,
        device_type: str | None = None,
        days_back: int | None = None
    ) -> list[dict[str, Any]]:
        """Get all devices for user with filters."""
    
    @abstractmethod
    async def update(self, device: DeviceRegistration) -> None:
        """Update device."""
    
    @abstractmethod
    async def delete(self, device_id: UUID) -> None:
        """Delete device."""


class IEmergencyContactRepository(ABC):
    """Emergency contact repository interface."""
    
    @abstractmethod
    async def get_by_id(self, contact_id: UUID) -> EmergencyContact | None:
        """Get contact by ID."""
    
    @abstractmethod
    async def get_user_contacts(self, user_id: UUID) -> list[EmergencyContact]:
        """Get all contacts for user."""
    
    @abstractmethod
    async def save(self, contact: EmergencyContact) -> EmergencyContact:
        """Save contact."""
    
    @abstractmethod
    async def delete(self, contact_id: UUID) -> None:
        """Delete contact."""


class IPasswordHistoryRepository(ABC):
    """Password history repository interface."""
    
    @abstractmethod
    async def get_history(self, user_id: UUID, limit: int = 10) -> list[PasswordHistory]:
        """Get password history for user."""
    
    @abstractmethod
    async def add_entry(self, entry: PasswordHistory) -> None:
        """Add password history entry."""
    
    @abstractmethod
    async def cleanup_old_entries(self, user_id: UUID, keep_count: int = 10) -> None:
        """Clean up old password history entries."""


# External Service Interfaces
class IEmailService(ABC):
    """Email service interface."""
    
    @abstractmethod
    async def send_verification_email(self, email: str, token: str) -> None:
        """Send email verification."""
    
    @abstractmethod
    async def send_password_reset_email(self, email: str, token: str) -> None:
        """Send password reset email."""
    
    @abstractmethod
    async def send_welcome_email(self, email: str, username: str) -> None:
        """Send welcome email."""
    
    @abstractmethod
    async def send_security_alert(self, email: str, alert_type: str, details: dict[str, Any]) -> None:
        """Send security alert email."""
    
    @abstractmethod
    async def send_mfa_code(self, email: str, code: str) -> None:
        """Send MFA code via email."""


class ISMSService(ABC):
    """SMS service interface."""
    
    @abstractmethod
    async def send_verification_code(self, phone_number: str, code: str) -> None:
        """Send verification code via SMS."""
    
    @abstractmethod
    async def send_mfa_code(self, phone_number: str, code: str) -> None:
        """Send MFA code via SMS."""
    
    @abstractmethod
    async def send_security_alert(self, phone_number: str, message: str) -> None:
        """Send security alert via SMS."""


class IPasswordBreachService(ABC):
    """Password breach checking service interface."""
    
    @abstractmethod
    async def check_password(self, password: str) -> tuple[bool, int]:
        """Check if password has been breached. Returns (is_breached, breach_count)."""


class IThreatIntelligenceService(ABC):
    """Threat intelligence service interface."""
    
    @abstractmethod
    async def check_ip_reputation(self, ip_address: str) -> dict[str, Any]:
        """Check IP address reputation."""
    
    @abstractmethod
    async def is_tor_exit_node(self, ip_address: str) -> bool:
        """Check if IP is a Tor exit node."""
    
    @abstractmethod
    async def is_vpn(self, ip_address: str) -> bool:
        """Check if IP is from VPN."""
    
    @abstractmethod
    async def get_geolocation(self, ip_address: str) -> dict[str, Any] | None:
        """Get geolocation for IP address."""


class ITokenService(ABC):
    """Token generation and validation service interface."""
    
    @abstractmethod
    def generate_access_token(self, user_id: UUID, session_id: UUID) -> str:
        """Generate access token."""
    
    @abstractmethod
    def generate_refresh_token(self) -> str:
        """Generate refresh token."""
    
    @abstractmethod
    def generate_verification_token(self) -> str:
        """Generate verification token."""
    
    @abstractmethod
    def validate_access_token(self, token: str) -> dict[str, Any] | None:
        """Validate and decode access token."""


class IStorageService(ABC):
    """Storage service interface for avatars and files."""
    
    @abstractmethod
    async def upload_avatar(self, user_id: UUID, file_data: bytes, content_type: str) -> str:
        """Upload avatar image."""
    
    @abstractmethod
    async def delete_avatar(self, avatar_url: str) -> None:
        """Delete avatar image."""
    
    @abstractmethod
    async def generate_avatar_thumbnail(self, avatar_url: str, size: tuple[int, int]) -> str:
        """Generate avatar thumbnail."""


class ICacheService(ABC):
    """Cache service interface."""
    
    @abstractmethod
    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache."""
    
    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete value from cache."""
    
    @abstractmethod
    async def clear_pattern(self, pattern: str) -> None:
        """Clear all keys matching pattern."""


class IEventBus(ABC):
    """Event bus interface."""
    
    @abstractmethod
    async def publish(self, event: Any) -> None:
        """Publish domain event."""
    
    @abstractmethod
    async def publish_batch(self, events: list[Any]) -> None:
        """Publish multiple events."""


class IComplianceRepository(ABC):
    """Compliance repository interface."""
    
    @abstractmethod
    async def get_framework_requirements(self, framework: Any) -> list[dict[str, Any]]:
        """Get compliance framework requirements."""
    
    @abstractmethod
    async def get_violations(self, framework: Any, start_date: datetime, end_date: datetime) -> list[dict[str, Any]]:
        """Get compliance violations."""
    
    @abstractmethod
    async def get_compliance_events(self, framework: Any, start_date: datetime, end_date: datetime) -> list[dict[str, Any]]:
        """Get compliance events."""
    
    @abstractmethod
    async def get_compliance_metrics(self, framework: Any, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get compliance metrics."""
    
    @abstractmethod
    async def count_violations(self, start_date: datetime, end_date: datetime) -> int:
        """Count compliance violations."""
    
    @abstractmethod
    async def count_audits(self, start_date: datetime, end_date: datetime) -> int:
        """Count compliance audits."""


class IPolicyRepository(ABC):
    """Policy repository interface."""
    
    @abstractmethod
    async def get_applicable_policies(
        self,
        user_id: UUID | None = None,
        resource: str | None = None,
        action: str | None = None
    ) -> list[dict[str, Any]]:
        """Get applicable policies."""
    
    @abstractmethod
    async def get_policies(
        self,
        user_id: UUID | None = None,
        resource_type: str | None = None,
        policy_type: str | None = None,
        is_active: bool = True
    ) -> list[dict[str, Any]]:
        """Get policies with filters."""
    
    @abstractmethod
    async def save_policy(self, policy: dict[str, Any]) -> None:
        """Save policy."""
    
    @abstractmethod
    async def delete_policy(self, policy_id: UUID) -> None:
        """Delete policy."""


class IAuthorizationRepository(ABC):
    """Authorization repository interface."""
    
    @abstractmethod
    async def get_user_resource_access(self, user_id: UUID, resource_type: str) -> list[dict[str, Any]]:
        """Get user access to resources."""
    
    @abstractmethod
    async def get_resource_access(
        self,
        resource_id: str,
        resource_type: str,
        user_id: UUID | None = None
    ) -> list[dict[str, Any]]:
        """Get access information for a resource."""
    
    @abstractmethod
    async def check_access(
        self,
        user_id: UUID,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None
    ) -> bool:
        """Check if user has access to perform action on resource."""


class IPreferencesRepository(ABC):
    """User preferences repository interface."""
    
    @abstractmethod
    async def get_user_preferences(self, user_id: UUID, category: str | None = None) -> dict[str, Any]:
        """Get user preferences."""
    
    @abstractmethod
    async def save_user_preferences(self, user_id: UUID, preferences: dict[str, Any]) -> None:
        """Save user preferences."""
    
    @abstractmethod
    async def delete_user_preferences(self, user_id: UUID, category: str | None = None) -> None:
        """Delete user preferences."""


class INotificationService(ABC):
    """Notification service interface."""
    
    @abstractmethod
    async def send_notification(
        self,
        user_id: UUID,
        notification_type: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """Send notification to user."""
    
    @abstractmethod
    async def send_bulk_notification(
        self,
        user_ids: list[UUID],
        notification_type: str,
        title: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> None:
        """Send notification to multiple users."""


class IAccessRepository(ABC):
    """Access logging repository interface."""
    
    @abstractmethod
    async def log_access_attempt(self, access_log: dict[str, Any]) -> None:
        """Log access attempt."""
    
    @abstractmethod
    async def get_access_logs(
        self,
        query: AccessLogQuery
    ) -> PagedResult[dict[str, Any]]:
        """Get access logs."""


class IMonitoringRepository(ABC):
    """Monitoring repository interface."""
    
    @abstractmethod
    async def start_monitoring(self, config: dict[str, Any]) -> str:
        """Start monitoring session."""
    
    @abstractmethod
    async def stop_monitoring(self, session_id: str) -> None:
        """Stop monitoring session."""
    
    @abstractmethod
    async def get_monitoring_data(
        self,
        session_id: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Get monitoring data."""


class IIncidentRepository(ABC):
    """Incident repository interface."""
    
    @abstractmethod
    async def create_incident(self, incident: dict[str, Any]) -> UUID:
        """Create security incident."""
    
    @abstractmethod
    async def get_incident(self, incident_id: UUID) -> dict[str, Any] | None:
        """Get incident by ID."""
    
    @abstractmethod
    async def update_incident(self, incident_id: UUID, updates: dict[str, Any]) -> None:
        """Update incident."""
    
    @abstractmethod
    async def get_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Get incidents with filters."""


class IForensicsRepository(ABC):
    """Forensics repository interface."""
    
    @abstractmethod
    async def collect_evidence(self, incident_id: UUID, evidence: dict[str, Any]) -> UUID:
        """Collect forensic evidence."""
    
    @abstractmethod
    async def get_evidence(self, evidence_id: UUID) -> dict[str, Any] | None:
        """Get evidence by ID."""
    
    @abstractmethod
    async def get_incident_evidence(self, incident_id: UUID) -> list[dict[str, Any]]:
        """Get all evidence for incident."""


class IEvidenceRepository(ABC):
    """Evidence repository interface."""
    
    @abstractmethod
    async def store_evidence(self, evidence: dict[str, Any]) -> UUID:
        """Store evidence."""
    
    @abstractmethod
    async def get_evidence_chain(self, evidence_id: UUID) -> list[dict[str, Any]]:
        """Get evidence chain of custody."""
    
    @abstractmethod
    async def verify_evidence_integrity(self, evidence_id: UUID) -> bool:
        """Verify evidence integrity."""


class IKeyRepository(ABC):
    """Encryption key repository interface."""
    
    @abstractmethod
    async def store_key(self, key_data: dict[str, Any]) -> UUID:
        """Store encryption key."""
    
    @abstractmethod
    async def get_key(self, key_id: UUID) -> dict[str, Any] | None:
        """Get encryption key."""
    
    @abstractmethod
    async def rotate_key(self, key_id: UUID) -> UUID:
        """Rotate encryption key."""
    
    @abstractmethod
    async def revoke_key(self, key_id: UUID) -> None:
        """Revoke encryption key."""


class ICertificateRepository(ABC):
    """Certificate repository interface."""
    
    @abstractmethod
    async def store_certificate(self, cert_data: dict[str, Any]) -> UUID:
        """Store certificate."""
    
    @abstractmethod
    async def get_certificate(self, cert_id: UUID) -> dict[str, Any] | None:
        """Get certificate."""
    
    @abstractmethod
    async def revoke_certificate(self, cert_id: UUID, reason: str) -> None:
        """Revoke certificate."""
    
    @abstractmethod
    async def get_expiring_certificates(self, days: int = 30) -> list[dict[str, Any]]:
        """Get certificates expiring within specified days."""


class IEncryptionRepository(ABC):
    """Encryption operations repository interface."""
    
    @abstractmethod
    async def encrypt_data(self, data: str, key_id: UUID) -> str:
        """Encrypt data with specified key."""
    
    @abstractmethod
    async def decrypt_data(self, encrypted_data: str, key_id: UUID) -> str:
        """Decrypt data with specified key."""
    
    @abstractmethod
    async def get_encryption_audit_log(
        self,
        key_id: UUID | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> list[dict[str, Any]]:
        """Get encryption operation audit log."""


class IRuleRepository(ABC):
    """Rule repository interface."""
    
    @abstractmethod
    async def create_rule(self, rule: dict[str, Any]) -> UUID:
        """Create rule."""
    
    @abstractmethod
    async def get_rule(self, rule_id: UUID) -> dict[str, Any] | None:
        """Get rule by ID."""
    
    @abstractmethod
    async def get_rules_by_type(self, rule_type: str) -> list[dict[str, Any]]:
        """Get rules by type."""
    
    @abstractmethod
    async def update_rule(self, rule_id: UUID, updates: dict[str, Any]) -> None:
        """Update rule."""
    
    @abstractmethod
    async def delete_rule(self, rule_id: UUID) -> None:
        """Delete rule."""
