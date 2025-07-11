"""
Audit Contract Interface

Contract for sending audit logs to the audit module.
This defines how the Identity domain communicates with the Audit module.
"""

from typing import Any, Protocol
from uuid import UUID


class IAuditContract(Protocol):
    """Contract for sending audit logs to the audit module."""

    async def log_authentication_event(
        self,
        user_id: UUID,
        event_type: str,
        success: bool,
        ip_address: str,
        user_agent: str,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Log authentication-related events.

        Args:
            user_id: User identifier
            event_type: Type of auth event (login/logout/mfa/password_reset)
            success: Whether the authentication succeeded
            ip_address: Client IP address
            user_agent: Client user agent string
            metadata: Additional event metadata
        """
        ...

    async def log_authorization_event(
        self,
        user_id: UUID,
        resource: str,
        action: str,
        allowed: bool,
        reason: str | None = None
    ) -> None:
        """
        Log authorization decisions.

        Args:
            user_id: User identifier
            resource: Resource being accessed
            action: Action being performed
            allowed: Whether access was allowed
            reason: Reason for denial if applicable
        """
        ...

    async def log_user_modification(
        self,
        user_id: UUID,
        modified_by: UUID,
        changes: dict[str, Any],
        reason: str | None = None
    ) -> None:
        """
        Log user profile/setting modifications.

        Args:
            user_id: User being modified
            modified_by: User making the changes
            changes: Dictionary of changed fields
            reason: Reason for modification
        """
        ...

    async def log_security_event(
        self,
        user_id: UUID | None,
        event_type: str,
        severity: str,
        details: dict[str, Any],
        ip_address: str | None = None
    ) -> None:
        """
        Log security-related events.

        Args:
            user_id: Affected user (if applicable)
            event_type: Type of security event
            severity: Event severity (low/medium/high/critical)
            details: Event details
            ip_address: Source IP address
        """
        ...

    async def log_compliance_event(
        self,
        user_id: UUID,
        event_type: str,
        details: dict[str, Any],
        regulation: str | None = None
    ) -> None:
        """
        Log compliance-related events.

        Args:
            user_id: User identifier
            event_type: Type of compliance event (consent/data_export/deletion)
            details: Event details
            regulation: Applicable regulation (GDPR/CCPA/etc)
        """
        ...

    async def log_administrative_action(
        self,
        admin_id: UUID,
        action: str,
        target_type: str,
        target_id: str,
        details: dict[str, Any]
    ) -> None:
        """
        Log administrative actions.

        Args:
            admin_id: Administrator performing action
            action: Action performed
            target_type: Type of target (user/role/permission)
            target_id: Target identifier
            details: Action details
        """
        ...
