"""User Factory Domain Service

Factory for creating user aggregates with various configurations.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from app.modules.identity.domain.entities.role.role import Role

from app.core.security import hash_password

from ...aggregates.user import User
from ...entities.user.preference import Preference
from ...enums import PreferenceCategory, PreferenceType, UserStatus
from ...value_objects import Email, Username


class UserFactory:
    """Factory for creating User aggregates with specific configurations."""
    
    @staticmethod
    def create_basic_user(
        email: str,
        username: str,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None
    ) -> User:
        """Create a basic user with minimal configuration."""
        return User.create(
            id=uuid4(),
            email=Email(email),
            username=Username(username),
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            status=UserStatus.PENDING
        )
    
    @staticmethod
    def create_admin_user(
        email: str,
        username: str,
        password: str,
        first_name: str,
        last_name: str,
        super_admin: bool = False
    ) -> User:
        """Create an admin user with appropriate roles and settings."""
        user = User.create(
            id=uuid4(),
            email=Email(email),
            username=Username(username),
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            status=UserStatus.ACTIVE,
            email_verified=True,  # Admins are pre-verified
            mfa_enabled=True,  # MFA required for admins
            require_password_change=True  # Force password change on first login
        )
        
        # Add admin metadata
        user.metadata = {
            "account_type": "admin",
            "created_by": "system",
            "super_admin": super_admin
        }
        
        # Initialize security settings
        user._regenerate_security_stamp()
        
        return user
    
    @staticmethod
    def create_service_account(
        name: str,
        email: str,
        description: str | None = None,
        permissions: list[str] | None = None
    ) -> User:
        """Create a service account for API access."""
        # Service accounts use email as username
        username = email.split('@')[0] + "_service"
        
        # Generate strong random password
        password = secrets.token_urlsafe(32)
        
        user = User.create(
            id=uuid4(),
            email=Email(email),
            username=Username(username),
            password_hash=hash_password(password),
            first_name="Service",
            last_name=name,
            status=UserStatus.ACTIVE,
            email_verified=True,
            mfa_enabled=False  # Service accounts use API keys instead
        )
        
        # Add service account metadata
        user.metadata = {
            "account_type": "service",
            "service_name": name,
            "description": description or "",
            "api_permissions": permissions or [],
            "created_by": "system"
        }
        
        # Service accounts never expire passwords
        user.password_never_expires = True
        
        return user
    
    @staticmethod
    def create_guest_user(
        session_id: str,
        ip_address: str | None = None
    ) -> User:
        """Create a temporary guest user."""
        # Generate guest identifiers
        guest_id = uuid4()
        email = f"guest_{guest_id}@temp.local"
        username = f"guest_{guest_id.hex[:8]}"
        
        user = User.create(
            id=guest_id,
            email=Email(email),
            username=Username(username),
            password_hash=hash_password(secrets.token_urlsafe(32)),
            first_name="Guest",
            last_name="User",
            status=UserStatus.ACTIVE,
            email_verified=False
        )
        
        # Add guest metadata
        user.metadata = {
            "account_type": "guest",
            "session_id": session_id,
            "ip_address": ip_address or "",
            "expires_at": (datetime.now(UTC) + timedelta(hours=24)).isoformat()
        }
        
        # Guests have limited lifetime
        user.account_expires_at = datetime.now(UTC) + timedelta(hours=24)
        
        return user
    
    @staticmethod
    def create_test_user(
        email: str,
        username: str,
        features: list[str] | None = None
    ) -> User:
        """Create a test user for development/testing."""
        user = User.create(
            id=uuid4(),
            email=Email(email),
            username=Username(username),
            password_hash=hash_password("test123"),  # Standard test password
            first_name="Test",
            last_name="User",
            status=UserStatus.ACTIVE,
            email_verified=True
        )
        
        # Add test metadata
        user.metadata = {
            "account_type": "test",
            "test_features": features or [],
            "created_by": "test_system"
        }
        
        # Add test preferences
        if not hasattr(user, '_preferences'):
            user._preferences = []
        
        # Enable all features for testing
        test_prefs = [
            Preference.create(
                user_id=user.id,
                category=PreferenceCategory.SECURITY,
                key="enable_test_mode",
                value=True,
                preference_type=PreferenceType.BOOLEAN
            ),
            Preference.create(
                user_id=user.id,
                category=PreferenceCategory.DISPLAY,
                key="show_debug_info",
                value=True,
                preference_type=PreferenceType.BOOLEAN
            )
        ]
        
        user._preferences.extend(test_prefs)
        
        return user
    
    @staticmethod
    def create_with_profile(
        email: str,
        username: str,
        password: str,
        profile_data: dict[str, Any]
    ) -> User:
        """Create a user with complete profile information."""
        user = User.create(
            id=uuid4(),
            email=Email(email),
            username=Username(username),
            password_hash=hash_password(password),
            first_name=profile_data.get("first_name"),
            last_name=profile_data.get("last_name"),
            status=UserStatus.PENDING
        )
        
        # Add phone number if provided
        if "phone_number" in profile_data:
            from ...value_objects import PhoneNumber
            try:
                user.phone_number = PhoneNumber(profile_data["phone_number"])
            except ValueError:
                pass
        
        # Add date of birth if provided
        if "date_of_birth" in profile_data:
            from ...value_objects import DateOfBirth
            try:
                user.date_of_birth = DateOfBirth(profile_data["date_of_birth"])
            except ValueError:
                pass
        
        # Add avatar URL if provided
        if "avatar_url" in profile_data:
            user.avatar_url = profile_data["avatar_url"]
        
        # Add profile metadata
        user.profile_metadata = {
            "bio": profile_data.get("bio", ""),
            "location": profile_data.get("location", ""),
            "website": profile_data.get("website", ""),
            "company": profile_data.get("company", ""),
            "job_title": profile_data.get("job_title", "")
        }
        
        return user
    
    @staticmethod
    def create_bulk_users(
        user_data_list: list[dict[str, Any]],
        default_password: str | None = None
    ) -> list[User]:
        """Create multiple users in bulk."""
        users = []
        
        for data in user_data_list:
            try:
                password = data.get("password", default_password or secrets.token_urlsafe(16))
                
                user = UserFactory.create_basic_user(
                    email=data["email"],
                    username=data["username"],
                    password=password,
                    first_name=data.get("first_name"),
                    last_name=data.get("last_name")
                )
                
                # Apply any additional data
                if "metadata" in data:
                    user.metadata.update(data["metadata"])
                
                if "status" in data:
                    user.status = UserStatus(data["status"])
                
                users.append(user)
                
            except (ValueError, KeyError):
                # Skip invalid entries
                continue
        
        return users
    
    @staticmethod
    def clone_user(
        source_user: User,
        new_email: str,
        new_username: str
    ) -> User:
        """Create a new user by cloning an existing user's configuration."""
        # Create new user with same basic attributes
        new_user = User.create(
            id=uuid4(),
            email=Email(new_email),
            username=Username(new_username),
            password_hash=source_user.password_hash,  # Same password
            first_name=source_user.first_name,
            last_name=source_user.last_name,
            status=UserStatus.PENDING  # New users start as pending
        )
        
        # Copy profile data
        new_user.phone_number = source_user.phone_number
        new_user.date_of_birth = source_user.date_of_birth
        new_user.avatar_url = None  # Don't copy avatar
        
        # Copy metadata (with clone marker)
        new_user.metadata = source_user.metadata.copy()
        new_user.metadata["cloned_from"] = str(source_user.id)
        new_user.metadata["cloned_at"] = datetime.now(UTC).isoformat()
        
        # Copy preferences
        if hasattr(source_user, '_preferences'):
            new_user._preferences = []
            for pref in source_user._preferences:
                new_pref = Preference.create(
                    user_id=new_user.id,
                    category=pref.category,
                    key=pref.key,
                    value=pref.value,
                    preference_type=pref.preference_type
                )
                new_user._preferences.append(new_pref)
        
        return new_user