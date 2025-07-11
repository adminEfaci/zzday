"""
Session Management Service Interface

Port for session lifecycle management including creation, validation,
refresh, and termination operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.session import Session
    from app.modules.identity.domain.aggregates.user import User


class ISessionManagementService(ABC):
    """Port for session management operations."""
    
    @abstractmethod
    async def create_session(
        self,
        user: "User",
        device_info: dict[str, Any],
        ip_address: str,
        user_agent: str | None = None
    ) -> "Session":
        """
        Create a new session for authenticated user.
        
        Args:
            user: Authenticated user
            device_info: Device information
            ip_address: Client IP address
            user_agent: Optional user agent string
            
        Returns:
            Created Session aggregate
            
        Raises:
            MaxSessionsExceededError: If user has too many active sessions
            UserNotActiveError: If user is not active
        """
        ...
    
    @abstractmethod
    async def validate_session(self, session_id: UUID) -> tuple[bool, str | None]:
        """
        Validate if session is active and valid.
        
        Args:
            session_id: ID of session to validate
            
        Returns:
            Tuple of (is_valid, error_reason)
        """
        ...
    
    @abstractmethod
    async def refresh_session(
        self,
        session_id: UUID,
        refresh_token: str
    ) -> tuple["Session", str]:
        """
        Refresh session with refresh token.
        
        Args:
            session_id: ID of session to refresh
            refresh_token: Refresh token
            
        Returns:
            Tuple of (refreshed_session, new_access_token)
            
        Raises:
            InvalidRefreshTokenError: If refresh token is invalid
            SessionExpiredError: If session has expired
        """
        ...
    
    @abstractmethod
    async def terminate_session(
        self,
        session_id: UUID,
        reason: str | None = None
    ) -> None:
        """
        Terminate an active session.
        
        Args:
            session_id: ID of session to terminate
            reason: Optional termination reason
        """
        ...
    
    @abstractmethod
    async def terminate_all_user_sessions(
        self,
        user_id: UUID,
        except_session_id: UUID | None = None,
        reason: str | None = None
    ) -> int:
        """
        Terminate all sessions for a user.
        
        Args:
            user_id: ID of user whose sessions to terminate
            except_session_id: Optional session ID to keep active
            reason: Optional termination reason
            
        Returns:
            Number of sessions terminated
        """
        ...
    
    @abstractmethod
    async def get_active_sessions_count(self, user_id: UUID) -> int:
        """
        Get count of active sessions for user.
        
        Args:
            user_id: ID of user
            
        Returns:
            Number of active sessions
        """
        ...
    
    @abstractmethod
    async def should_require_reauthentication(
        self,
        session: "Session",
        for_action: str | None = None
    ) -> bool:
        """
        Check if session requires reauthentication.
        
        Args:
            session: Session to check
            for_action: Optional sensitive action being performed
            
        Returns:
            True if reauthentication is required
        """
        ...
    
    @abstractmethod
    async def update_session_activity(
        self,
        session_id: UUID,
        activity_data: dict[str, Any] | None = None
    ) -> None:
        """
        Update session's last activity timestamp and optional data.
        
        Args:
            session_id: ID of session to update
            activity_data: Optional activity metadata
        """
        ...