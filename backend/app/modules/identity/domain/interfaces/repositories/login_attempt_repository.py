"""Login Attempt Repository Interface

Domain contract for login attempt tracking that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.modules.identity.domain.enums import LoginFailureReason


class ILoginAttemptRepository(Protocol):
    """Repository interface for login attempt tracking."""
    
    @abstractmethod
    async def create(
        self, 
        email: str,
        ip_address: str,
        user_agent: str | None = None,
        user_id: UUID | None = None,
        success: bool = False,
        failure_reason: LoginFailureReason | None = None
    ) -> UUID:
        """Record login attempt.
        
        Args:
            email: Email address used for login
            ip_address: Source IP address
            user_agent: User agent string
            user_id: User ID if user was found
            success: Whether login was successful
            failure_reason: Reason for failure if applicable
            
        Returns:
            Created attempt ID
        """
        ...
    
    @abstractmethod
    async def count_failed_attempts(
        self, 
        email: str,
        since: datetime | None = None
    ) -> int:
        """Count failed login attempts for email.
        
        Args:
            email: Email address
            since: Count attempts since this time
            
        Returns:
            Number of failed attempts
        """
        ...
    
    @abstractmethod
    async def count_failed_attempts_by_ip(
        self, 
        ip_address: str,
        since: datetime | None = None
    ) -> int:
        """Count failed login attempts by IP.
        
        Args:
            ip_address: IP address
            since: Count attempts since this time
            
        Returns:
            Number of failed attempts
        """
        ...
    
    @abstractmethod
    async def find_recent_attempts(
        self, 
        email: str,
        limit: int = 10
    ) -> list[dict]:
        """Find recent login attempts for email.
        
        Args:
            email: Email address
            limit: Maximum number of attempts to return
            
        Returns:
            List of recent attempts
        """
        ...
    
    @abstractmethod
    async def find_successful_logins(
        self, 
        user_id: UUID,
        limit: int = 10
    ) -> list[dict]:
        """Find recent successful logins for user.
        
        Args:
            user_id: User identifier
            limit: Maximum number of logins to return
            
        Returns:
            List of successful logins
        """
        ...
    
    @abstractmethod
    async def cleanup_old_attempts(self, older_than: datetime) -> int:
        """Remove old login attempts.
        
        Args:
            older_than: Remove attempts older than this date
            
        Returns:
            Number of attempts removed
        """
        ...