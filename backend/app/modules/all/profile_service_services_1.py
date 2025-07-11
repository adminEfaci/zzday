"""Profile Domain Service

Handles user profile operations with proper domain logic and validation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.aggregates.user import User

from ...entities.user.user_errors import (
    InvalidProfileDataError,
    ProfileUpdateError,
)
from ...entities.user.user_events import (
    UserProfileUpdated,
    UserAvatarChanged,
)
from ...value_objects import (
    PhoneNumber,
    DateOfBirth,
    FullName,
)


class ProfileService:
    """Domain service for user profile operations."""
    
    @staticmethod
    def update_profile(
        user: User,
        profile_data: dict[str, Any],
        updated_by: UUID | None = None
    ) -> None:
        """
        Update user profile with validation.
        
        Args:
            user: User aggregate to update
            profile_data: Dictionary containing profile fields to update
            updated_by: ID of user performing update (None if self-update)
        """
        # Track what fields were updated
        updated_fields = []
        
        # Update first name
        if "first_name" in profile_data:
            old_value = user.first_name
            user.first_name = profile_data["first_name"]
            if old_value != user.first_name:
                updated_fields.append("first_name")
        
        # Update last name
        if "last_name" in profile_data:
            old_value = user.last_name
            user.last_name = profile_data["last_name"]
            if old_value != user.last_name:
                updated_fields.append("last_name")
        
        # Update full name value object if provided
        if "full_name" in profile_data:
            try:
                user.full_name = FullName(
                    first_name=profile_data["full_name"].get("first_name", user.first_name),
                    last_name=profile_data["full_name"].get("last_name", user.last_name)
                )
                updated_fields.append("full_name")
            except ValueError as e:
                raise InvalidProfileDataError(f"Invalid full name: {str(e)}")
        
        # Update phone number
        if "phone_number" in profile_data:
            try:
                if profile_data["phone_number"]:
                    user.phone_number = PhoneNumber(profile_data["phone_number"])
                else:
                    user.phone_number = None
                user.phone_verified = False  # Require re-verification
                updated_fields.append("phone_number")
            except ValueError as e:
                raise InvalidProfileDataError(f"Invalid phone number: {str(e)}")
        
        # Update date of birth
        if "date_of_birth" in profile_data:
            try:
                if profile_data["date_of_birth"]:
                    user.date_of_birth = DateOfBirth(profile_data["date_of_birth"])
                else:
                    user.date_of_birth = None
                updated_fields.append("date_of_birth")
            except ValueError as e:
                raise InvalidProfileDataError(f"Invalid date of birth: {str(e)}")
        
        # Update profile metadata
        if "bio" in profile_data:
            if not hasattr(user, 'profile_metadata'):
                user.profile_metadata = {}
            user.profile_metadata["bio"] = profile_data["bio"]
            updated_fields.append("bio")
        
        if "location" in profile_data:
            if not hasattr(user, 'profile_metadata'):
                user.profile_metadata = {}
            user.profile_metadata["location"] = profile_data["location"]
            updated_fields.append("location")
        
        if "timezone" in profile_data:
            if not hasattr(user, 'profile_metadata'):
                user.profile_metadata = {}
            user.profile_metadata["timezone"] = profile_data["timezone"]
            updated_fields.append("timezone")
        
        # Only proceed if fields were actually updated
        if updated_fields:
            user.updated_at = datetime.now(UTC)
            
            # Add domain event
            user.add_domain_event(UserProfileUpdated(
                user_id=user.id,
                updated_by=updated_by or user.id,
                updated_fields=updated_fields,
                timestamp=user.updated_at
            ))
    
    @staticmethod
    def update_avatar(
        user: User,
        avatar_url: str | None,
        updated_by: UUID | None = None
    ) -> None:
        """
        Update user avatar URL.
        
        Args:
            user: User aggregate to update
            avatar_url: New avatar URL (None to remove)
            updated_by: ID of user performing update
        """
        old_avatar = user.avatar_url
        user.avatar_url = avatar_url
        user.updated_at = datetime.now(UTC)
        
        # Add domain event
        user.add_domain_event(UserAvatarChanged(
            user_id=user.id,
            old_avatar_url=old_avatar,
            new_avatar_url=avatar_url,
            changed_by=updated_by or user.id,
            timestamp=user.updated_at
        ))
    
    @staticmethod
    def validate_profile_completeness(user: User) -> dict[str, bool]:
        """
        Check profile completeness for various sections.
        
        Returns:
            Dictionary with completeness status for each section
        """
        return {
            "basic_info": bool(user.first_name and user.last_name),
            "contact_info": bool(user.email_verified and (
                not user.phone_number or user.phone_verified
            )),
            "security": bool(user.mfa_enabled),
            "profile": bool(
                hasattr(user, 'profile_metadata') and 
                user.profile_metadata.get("bio") and
                user.profile_metadata.get("location")
            ),
            "avatar": bool(user.avatar_url)
        }
    
    @staticmethod
    def calculate_profile_completion_percentage(user: User) -> float:
        """
        Calculate overall profile completion percentage.
        
        Returns:
            Completion percentage (0-100)
        """
        completeness = ProfileService.validate_profile_completeness(user)
        completed = sum(1 for complete in completeness.values() if complete)
        total = len(completeness)
        
        return (completed / total) * 100 if total > 0 else 0.0
    
    @staticmethod
    def get_public_profile(user: User) -> dict[str, Any]:
        """
        Get public-facing profile information.
        
        Returns:
            Dictionary with public profile data
        """
        profile = {
            "id": str(user.id),
            "username": user.username.value,
            "display_name": user.get_display_name(),
            "avatar_url": user.avatar_url,
            "created_at": user.created_at.isoformat(),
        }
        
        # Add optional public fields
        if hasattr(user, 'profile_metadata'):
            metadata = user.profile_metadata or {}
            if metadata.get("bio"):
                profile["bio"] = metadata["bio"]
            if metadata.get("location"):
                profile["location"] = metadata["location"]
        
        return profile
    
    @staticmethod
    def get_private_profile(user: User) -> dict[str, Any]:
        """
        Get full profile information (for user themselves or admins).
        
        Returns:
            Dictionary with complete profile data
        """
        profile = ProfileService.get_public_profile(user)
        
        # Add private fields
        profile.update({
            "email": user.email.value,
            "email_verified": user.email_verified,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone_number": user.phone_number.value if user.phone_number else None,
            "phone_verified": user.phone_verified,
            "date_of_birth": user.date_of_birth.value.isoformat() if user.date_of_birth else None,
            "mfa_enabled": user.mfa_enabled,
            "status": user.status.value,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "profile_completion": ProfileService.calculate_profile_completion_percentage(user),
            "metadata": user.profile_metadata or {},
        })
        
        return profile