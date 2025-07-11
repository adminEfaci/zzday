"""
Registration Domain Service

Handles user registration with proper domain logic and validation.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from app.core.security import hash_password

from ...entities.user.user_errors import (
    DuplicateEmailError,
    DuplicateUsernameError,
    InvalidRegistrationDataError,
)
from ...entities.user.user_events import (
    UserRegistered,
    VerificationEmailSent,
)
from ...enums import UserStatus
from ...value_objects import Email, Username


class RegistrationService:
    """Domain service for user registration operations."""
    
    @staticmethod
    def register_user(
        email: str,
        username: str,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> User:
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
            InvalidRegistrationDataError: If registration data is invalid
            DuplicateEmailError: If email already exists
            DuplicateUsernameError: If username already exists
        """
        # Import User here to avoid circular imports
        from ...aggregates.user import User
        
        # Validate email and username value objects
        try:
            email_vo = Email(email)
            username_vo = Username(username)
        except ValueError as e:
            raise InvalidRegistrationDataError(str(e))
        
        # Validate password
        if not password or len(password) < 8:
            raise InvalidRegistrationDataError("Password must be at least 8 characters")
        
        # Create user aggregate
        user = User.create(
            id=uuid4(),
            email=email_vo,
            username=username_vo,
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            status=UserStatus.PENDING,  # Start as pending until email verified
            metadata=metadata or {}
        )
        
        # Generate email verification token
        verification_token = secrets.token_urlsafe(32)
        user.email_verification_token = verification_token
        user.email_verification_sent_at = datetime.now(UTC)
        
        # Add registration event
        user.add_domain_event(UserRegistered(
            user_id=user.id,
            email=email,
            username=username,
            registration_source=metadata.get("source", "web") if metadata else "web",
            ip_address=metadata.get("ip_address", "") if metadata else "",
            user_agent=metadata.get("user_agent", "") if metadata else ""
        ))
        
        # Add verification email event
        user.add_domain_event(VerificationEmailSent(
            user_id=user.id,
            email=email,
            verification_token=verification_token,
            expires_at=datetime.now(UTC) + timedelta(hours=24)
        ))
        
        return user
    
    @staticmethod
    def register_with_social(
        provider: str,
        provider_user_id: str,
        email: str,
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        avatar_url: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> User:
        """
        Register user via social provider.
        
        Args:
            provider: Social provider name (google, facebook, etc.)
            provider_user_id: User ID from provider
            email: User email from provider
            username: Optional username (generated if not provided)
            first_name: Optional first name from provider
            last_name: Optional last name from provider
            avatar_url: Optional avatar URL from provider
            metadata: Optional metadata from provider
            
        Returns:
            Created User aggregate
        """
        # Import User here to avoid circular imports
        from ...aggregates.user import User
        
        # Generate username if not provided
        if not username:
            username = f"{provider}_{provider_user_id}"
        
        # Validate value objects
        try:
            email_vo = Email(email)
            username_vo = Username(username)
        except ValueError as e:
            raise InvalidRegistrationDataError(str(e))
        
        # Create user with random password (won't be used for social login)
        random_password = secrets.token_urlsafe(32)
        
        user = User.create(
            id=uuid4(),
            email=email_vo,
            username=username_vo,
            password_hash=hash_password(random_password),
            first_name=first_name,
            last_name=last_name,
            avatar_url=avatar_url,
            status=UserStatus.ACTIVE,  # Social users are pre-verified
            email_verified=True,  # Email is verified by provider
            metadata=metadata or {}
        )
        
        # Store social provider info
        if not hasattr(user, 'social_accounts'):
            user.social_accounts = []
        
        user.social_accounts.append({
            "provider": provider,
            "provider_user_id": provider_user_id,
            "connected_at": datetime.now(UTC),
            "metadata": metadata or {}
        })
        
        # Add registration event
        user.add_domain_event(UserRegistered(
            user_id=user.id,
            email=email,
            username=username,
            registration_source=f"social_{provider}",
            ip_address=metadata.get("ip_address", "") if metadata else "",
            user_agent=metadata.get("user_agent", "") if metadata else ""
        ))
        
        return user
    
    @staticmethod
    def verify_email(user: User, token: str) -> None:
        """
        Verify user email with token.
        
        Args:
            user: User aggregate
            token: Verification token
            
        Raises:
            InvalidRegistrationDataError: If token is invalid or expired
        """
        if not user.email_verification_token:
            raise InvalidRegistrationDataError("No verification pending")
        
        if user.email_verification_token != token:
            raise InvalidRegistrationDataError("Invalid verification token")
        
        # Check if token expired (24 hours)
        if user.email_verification_sent_at:
            expires_at = user.email_verification_sent_at + timedelta(hours=24)
            if datetime.now(UTC) > expires_at:
                raise InvalidRegistrationDataError("Verification token expired")
        
        # Verify email
        user.email_verified = True
        user.email_verification_token = None
        user.email_verification_sent_at = None
        
        # Activate user if pending
        if user.status == UserStatus.PENDING:
            user.status = UserStatus.ACTIVE
        
        user.updated_at = datetime.now(UTC)
        
        # Add verification event
        from ...entities.user.user_events import EmailVerified
        user.add_domain_event(EmailVerified(
            user_id=user.id,
            email=user.email.value,
            verified_at=datetime.now(UTC)
        ))
    
    @staticmethod
    def resend_verification(user: User) -> str:
        """
        Resend email verification.
        
        Args:
            user: User aggregate
            
        Returns:
            New verification token
            
        Raises:
            InvalidRegistrationDataError: If email already verified
        """
        if user.email_verified:
            raise InvalidRegistrationDataError("Email already verified")
        
        # Check rate limiting (max 1 per hour)
        if user.email_verification_sent_at:
            time_since_last = datetime.now(UTC) - user.email_verification_sent_at
            if time_since_last < timedelta(hours=1):
                minutes_left = 60 - int(time_since_last.total_seconds() / 60)
                raise InvalidRegistrationDataError(
                    f"Please wait {minutes_left} minutes before requesting another verification"
                )
        
        # Generate new token
        verification_token = secrets.token_urlsafe(32)
        user.email_verification_token = verification_token
        user.email_verification_sent_at = datetime.now(UTC)
        user.updated_at = datetime.now(UTC)
        
        # Add event
        user.add_domain_event(VerificationEmailSent(
            user_id=user.id,
            email=user.email.value,
            verification_token=verification_token,
            expires_at=datetime.now(UTC) + timedelta(hours=24)
        ))
        
        return verification_token
    
    @staticmethod
    def complete_profile(
        user: User,
        first_name: str,
        last_name: str,
        phone_number: str | None = None,
        date_of_birth: str | None = None,
        preferences: dict[str, Any] | None = None
    ) -> None:
        """
        Complete user profile after registration.
        
        Args:
            user: User aggregate
            first_name: User's first name
            last_name: User's last name
            phone_number: Optional phone number
            date_of_birth: Optional date of birth
            preferences: Optional initial preferences
        """
        # Update basic info
        user.first_name = first_name
        user.last_name = last_name
        
        # Update phone if provided
        if phone_number:
            from ...value_objects import PhoneNumber
            try:
                user.phone_number = PhoneNumber(phone_number)
            except ValueError:
                pass  # Skip invalid phone
        
        # Update date of birth if provided
        if date_of_birth:
            from ...value_objects import DateOfBirth
            try:
                user.date_of_birth = DateOfBirth(date_of_birth)
            except ValueError:
                pass  # Skip invalid date
        
        # Set initial preferences if provided
        if preferences:
            from .preference_service import PreferenceService
            PreferenceService.update_preferences(user, preferences)
        
        user.updated_at = datetime.now(UTC)
        
        # Add profile completed event
        from ...entities.user.user_events import UserProfileCompleted
        user.add_domain_event(UserProfileCompleted(
            user_id=user.id,
            completed_at=datetime.now(UTC)
        ))