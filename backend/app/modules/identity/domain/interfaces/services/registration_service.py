"""
Registration Service Interface

Port for user registration operations including validation,
verification, and onboarding workflows.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User
    from app.modules.identity.domain.value_objects import Email, Username


class IRegistrationService(ABC):
    """Port for user registration operations."""
    
    @abstractmethod
    async def register_user(
        self,
        email: str,
        username: str,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> "User":
        """
        Register a new user with validation.
        
        Args:
            email: User email address
            username: Unique username
            password: User password (will be hashed)
            first_name: Optional first name
            last_name: Optional last name
            metadata: Optional registration metadata
            
        Returns:
            Created User aggregate
            
        Raises:
            DuplicateEmailError: If email already exists
            DuplicateUsernameError: If username already exists
            InvalidRegistrationDataError: If registration data is invalid
        """
        ...
    
    @abstractmethod
    async def validate_registration_data(
        self,
        email: str,
        username: str,
        password: str
    ) -> list[str]:
        """
        Validate registration data before creating user.
        
        Args:
            email: Email to validate
            username: Username to validate
            password: Password to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        ...
    
    @abstractmethod
    async def check_email_availability(self, email: str) -> bool:
        """
        Check if email is available for registration.
        
        Args:
            email: Email to check
            
        Returns:
            True if available, False otherwise
        """
        ...
    
    @abstractmethod
    async def check_username_availability(self, username: str) -> bool:
        """
        Check if username is available for registration.
        
        Args:
            username: Username to check
            
        Returns:
            True if available, False otherwise
        """
        ...
    
    @abstractmethod
    async def send_verification_email(self, user: "User") -> None:
        """
        Send verification email to newly registered user.
        
        Args:
            user: User to send verification email to
        """
        ...
    
    @abstractmethod
    async def verify_email(self, user_id: UUID, verification_token: str) -> bool:
        """
        Verify user's email with token.
        
        Args:
            user_id: ID of user to verify
            verification_token: Token from verification email
            
        Returns:
            True if verified successfully
        """
        ...
    
    @abstractmethod
    async def resend_verification_email(self, user_id: UUID) -> None:
        """
        Resend verification email to user.
        
        Args:
            user_id: ID of user to resend email to
            
        Raises:
            UserNotFoundError: If user doesn't exist
            EmailAlreadyVerifiedError: If email is already verified
        """
        ...