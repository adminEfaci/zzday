# domains/identity/domain/contracts/session_contract.py

from datetime import datetime
from typing import Any, Protocol
from uuid import UUID


class SessionContract(Protocol):
    """
    Contract interface for session operations.

    Lets other domains (e.g. analytics, audit, risk) verify session
    status or info without coupling to internal session models.
    """

    def is_valid(self, session_id: UUID) -> bool:
        """
        Return True if the session is valid (not expired/revoked).

        Args:
            session_id: The unique identifier of the session

        Returns:
            bool: True if session is valid, False if expired/revoked/invalid
        """
        ...

    def get_user_id(self, session_id: UUID) -> UUID | None:
        """
        Get the user ID associated with this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[UUID]: User ID or None if session not found
        """
        ...

    def get_ip_address(self, session_id: UUID) -> str | None:
        """
        Get the IP address associated with this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[str]: IP address or None if session not found
        """
        ...

    def get_user_agent(self, session_id: UUID) -> str | None:
        """
        Get the user agent string associated with this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[str]: User agent string or None if not available
        """
        ...

    def get_created_at(self, session_id: UUID) -> datetime | None:
        """
        Get when the session was created.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[datetime]: Session creation time or None if not found
        """
        ...

    def get_expires_at(self, session_id: UUID) -> datetime | None:
        """
        Get when the session expires.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[datetime]: Session expiration time or None if not found
        """
        ...

    def get_device_info(self, session_id: UUID) -> dict[str, Any] | None:
        """
        Get device information associated with this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[Dict[str, Any]]: Device info dict or None if not available
        """
        ...

    def is_mfa_verified(self, session_id: UUID) -> bool:
        """
        Check if MFA has been verified for this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            bool: True if MFA verified, False otherwise
        """
        ...

    def get_session_risk_score(self, session_id: UUID) -> float | None:
        """
        Get the risk score associated with this session.

        Args:
            session_id: The unique identifier of the session

        Returns:
            Optional[float]: Risk score (0.0-1.0) or None if not calculated
        """
        ...
