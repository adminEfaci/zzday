"""Application Layer Service Interfaces.

Defines contracts for external services needed by the application layer.
Repository interfaces should be imported from domain layer to avoid duplication.
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

# Import repository interfaces from domain layer - DO NOT DUPLICATE
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.role_repository import (
    IRoleRepository,
)
from app.modules.identity.domain.interfaces.repositories.permission_repository import (
    IPermissionRepository,
)
from app.modules.identity.domain.interfaces.repositories.mfa_repository import (
    IMFARepository,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRegistrationRepository as IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import (
    IEmergencyContactRepository,
)
from app.modules.identity.domain.interfaces.repositories.password_history_repository import (
    IPasswordHistoryRepository,
)

# Import extended repository interfaces for application-specific queries
from app.modules.identity.application.contracts.extended_repositories import (
    IExtendedUserRepository,
    IExtendedSessionRepository,
)

# Import cache interface from domain
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)


# Application-specific repository interfaces that don't have domain equivalents
class IAuditRepository(ABC):
    """Audit repository interface for application layer."""
    
    @abstractmethod
    async def log_access_attempt(self, access_log: dict[str, Any]) -> None:
        """Log access attempt."""
    
    @abstractmethod
    async def get_access_logs(
        self,
        query: AccessLogQuery
    ) -> PagedResult[dict[str, Any]]:
        """Get access logs."""
    
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
    async def get_audit_trail(
        self,
        filters: dict[str, Any],
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "desc"
    ) -> list[dict[str, Any]]:
        """Get audit trail with filters."""


class ISecurityRepository(ABC):
    """Security repository interface for application layer."""
    
    @abstractmethod
    async def log_security_event(self, event: dict[str, Any]) -> None:
        """Log security event."""
    
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
    async def get_user_patterns(self, user_id: UUID) -> dict[str, Any]:
        """Get user behavior patterns."""


class IComplianceRepository(ABC):
    """Compliance repository interface for application layer."""
    
    @abstractmethod
    async def get_framework_requirements(self, framework: Any) -> list[dict[str, Any]]:
        """Get compliance framework requirements."""
    
    @abstractmethod
    async def get_violations(self, framework: Any, start_date: datetime, end_date: datetime) -> list[dict[str, Any]]:
        """Get compliance violations."""
    
    @abstractmethod
    async def get_compliance_metrics(self, framework: Any, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get compliance metrics."""


class IPolicyRepository(ABC):
    """Policy repository interface for application layer."""
    
    @abstractmethod
    async def get_applicable_policies(
        self,
        user_id: UUID | None = None,
        resource: str | None = None,
        action: str | None = None
    ) -> list[dict[str, Any]]:
        """Get applicable policies."""
    
    @abstractmethod
    async def save_policy(self, policy: dict[str, Any]) -> None:
        """Save policy."""
    
    @abstractmethod
    async def delete_policy(self, policy_id: UUID) -> None:
        """Delete policy."""


class IAuthorizationRepository(ABC):
    """Authorization repository interface for application layer."""
    
    @abstractmethod
    async def check_access(
        self,
        user_id: UUID,
        resource: str,
        action: str,
        context: dict[str, Any] | None = None
    ) -> bool:
        """Check if user has access to perform action on resource."""
    
    @abstractmethod
    async def get_user_resource_access(self, user_id: UUID, resource_type: str) -> list[dict[str, Any]]:
        """Get user access to resources."""


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


class IEventBus(ABC):
    """Event bus interface."""
    
    @abstractmethod
    async def publish(self, event: Any) -> None:
        """Publish domain event."""
    
    @abstractmethod
    async def publish_batch(self, events: list[Any]) -> None:
        """Publish multiple events."""


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