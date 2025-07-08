"""
User Preference Repository Implementation

SQLModel-based implementation of the user preference repository interface.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID, uuid4

from sqlmodel import Session, select, and_, or_, col, func
from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.entities.user.preference import UserPreference
from app.modules.identity.domain.interfaces.repositories.user_preference_repository import IUserPreferenceRepository
from app.modules.identity.infrastructure.models.user_preference_model import UserPreferenceModel


class SQLUserPreferenceRepository(SQLRepository[UserPreference, UserPreferenceModel], IUserPreferenceRepository):
    """SQLModel implementation of user preference repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, UserPreferenceModel)
    
    async def create(
        self, 
        user_id: UUID,
        key: str,
        value: Any,
        category: str | None = None
    ) -> UUID:
        """Create user preference."""
        # Check if user preferences exist
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            # Create new preferences for user
            preference = UserPreference.create(user_id=user_id)
            model = UserPreferenceModel.from_domain(preference)
            self.session.add(model)
        
        # Update specific preference
        if category == "notification":
            model.notification_settings[key] = value
        elif category == "privacy":
            model.privacy_settings[key] = value
        elif category == "accessibility":
            model.accessibility_settings[key] = value
        elif category == "custom":
            model.custom_preferences[key] = value
        else:
            # Store in custom preferences if no category specified
            model.custom_preferences[key] = value
        
        model.updated_at = datetime.now(UTC)
        await self.session.commit()
        
        return model.id
    
    async def find_by_user(self, user_id: UUID) -> dict[str, Any]:
        """Find all preferences for user."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return {}
        
        # Combine all preferences into a single dictionary
        preferences = {
            "language": model.language,
            "timezone": model.timezone,
            "date_format": model.date_format,
            "time_format": model.time_format,
            "theme": model.theme,
            "email_digest_frequency": model.email_digest_frequency,
            "show_profile_publicly": model.show_profile_publicly,
            "allow_messages_from": model.allow_messages_from,
            **model.custom_preferences
        }
        
        # Add categorized preferences
        for key, value in model.notification_settings.items():
            preferences[f"notification.{key}"] = value
        
        for key, value in model.privacy_settings.items():
            preferences[f"privacy.{key}"] = value
        
        for key, value in model.accessibility_settings.items():
            preferences[f"accessibility.{key}"] = value
        
        return preferences
    
    async def find_by_key(self, user_id: UUID, key: str) -> Any | None:
        """Find specific preference for user."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        # Check if key contains category prefix
        if "." in key:
            category, pref_key = key.split(".", 1)
            
            if category == "notification":
                return model.notification_settings.get(pref_key)
            elif category == "privacy":
                return model.privacy_settings.get(pref_key)
            elif category == "accessibility":
                return model.accessibility_settings.get(pref_key)
        
        # Check direct attributes
        if hasattr(model, key):
            return getattr(model, key)
        
        # Check custom preferences
        return model.custom_preferences.get(key)
    
    async def find_by_category(
        self, 
        user_id: UUID, 
        category: str
    ) -> dict[str, Any]:
        """Find preferences by category for user."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return {}
        
        if category == "notification":
            return model.notification_settings.copy()
        elif category == "privacy":
            return model.privacy_settings.copy()
        elif category == "accessibility":
            return model.accessibility_settings.copy()
        elif category == "custom":
            return model.custom_preferences.copy()
        elif category == "basic":
            return {
                "language": model.language,
                "timezone": model.timezone,
                "date_format": model.date_format,
                "time_format": model.time_format,
                "theme": model.theme
            }
        elif category == "communication":
            return {
                "email_digest_frequency": model.email_digest_frequency,
                "show_profile_publicly": model.show_profile_publicly,
                "allow_messages_from": model.allow_messages_from
            }
        
        return {}
    
    async def set_preference(
        self, 
        user_id: UUID,
        key: str,
        value: Any,
        category: str | None = None
    ) -> bool:
        """Set user preference (create or update)."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            # Create new preferences for user
            preference = UserPreference.create(user_id=user_id)
            model = UserPreferenceModel.from_domain(preference)
            self.session.add(model)
        
        # Update preference based on category
        if category == "notification":
            model.notification_settings[key] = value
        elif category == "privacy":
            model.privacy_settings[key] = value
        elif category == "accessibility":
            model.accessibility_settings[key] = value
        elif category == "custom":
            model.custom_preferences[key] = value
        else:
            # Check if it's a direct attribute
            if hasattr(model, key):
                setattr(model, key, value)
            else:
                # Store in custom preferences
                model.custom_preferences[key] = value
        
        model.updated_at = datetime.now(UTC)
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def update_preferences(
        self, 
        user_id: UUID,
        preferences: dict[str, Any]
    ) -> bool:
        """Update multiple preferences at once."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            # Create new preferences for user
            preference = UserPreference.create(user_id=user_id)
            model = UserPreferenceModel.from_domain(preference)
            self.session.add(model)
        
        # Update each preference
        for key, value in preferences.items():
            if "." in key:
                # Handle categorized preferences
                category, pref_key = key.split(".", 1)
                
                if category == "notification":
                    model.notification_settings[pref_key] = value
                elif category == "privacy":
                    model.privacy_settings[pref_key] = value
                elif category == "accessibility":
                    model.accessibility_settings[pref_key] = value
                else:
                    model.custom_preferences[key] = value
            else:
                # Handle direct attributes
                if hasattr(model, key):
                    setattr(model, key, value)
                else:
                    model.custom_preferences[key] = value
        
        model.updated_at = datetime.now(UTC)
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def delete_preference(self, user_id: UUID, key: str) -> bool:
        """Delete specific preference."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return False
        
        deleted = False
        
        # Check if key contains category prefix
        if "." in key:
            category, pref_key = key.split(".", 1)
            
            if category == "notification" and pref_key in model.notification_settings:
                del model.notification_settings[pref_key]
                deleted = True
            elif category == "privacy" and pref_key in model.privacy_settings:
                del model.privacy_settings[pref_key]
                deleted = True
            elif category == "accessibility" and pref_key in model.accessibility_settings:
                del model.accessibility_settings[pref_key]
                deleted = True
        
        # Check custom preferences
        if key in model.custom_preferences:
            del model.custom_preferences[key]
            deleted = True
        
        if deleted:
            model.updated_at = datetime.now(UTC)
            self.session.add(model)
            await self.session.commit()
        
        return deleted
    
    async def delete_all_preferences(self, user_id: UUID) -> int:
        """Delete all preferences for user."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return 0
        
        # Count total preferences before deletion
        count = (
            len(model.notification_settings) +
            len(model.privacy_settings) +
            len(model.accessibility_settings) +
            len(model.custom_preferences) +
            8  # Basic preferences (language, timezone, etc.)
        )
        
        # Delete the entire record
        await self.session.delete(model)
        await self.session.commit()
        
        return count
    
    async def find_domain_by_user(self, user_id: UUID) -> UserPreference | None:
        """Find user preference domain entity."""
        stmt = select(UserPreferenceModel).where(UserPreferenceModel.user_id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        return model.to_domain() if model else None
    
    async def save(self, preference: UserPreference) -> None:
        """Save user preference domain entity."""
        model = UserPreferenceModel.from_domain(preference)
        
        # Check if preferences exist
        existing = await self.session.exec(
            select(UserPreferenceModel).where(UserPreferenceModel.user_id == preference.user_id)
        )
        existing_model = existing.first()
        
        if existing_model:
            # Update existing model
            for key, value in model.dict(exclude={'id', 'user_id'}).items():
                setattr(existing_model, key, value)
            self.session.add(existing_model)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()