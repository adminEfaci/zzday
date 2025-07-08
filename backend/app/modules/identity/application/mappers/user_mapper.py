"""
User mapper for converting between User domain objects and DTOs.

This module provides mapping functionality to convert User aggregate root 
and related entities to/from DTOs for API requests and responses.
"""

from datetime import datetime, timedelta

from app.modules.identity.application.dtos.response import (
    ProfileCompletionResponse,
    UserActivityResponse,
    UserDetailResponse,
    UserPreferencesResponse,
    UserProfileResponse,
    UserResponse,
    UserSecurityProfileResponse,
    UserSummaryResponse,
)
from app.modules.identity.domain.aggregates.user import User


class UserMapper:
    """Mapper for User domain objects to DTOs."""
    
    @staticmethod
    def to_response(user: User, include_sensitive: bool = False) -> UserResponse:
        """Convert User aggregate to UserResponse DTO.
        
        Args:
            user: User aggregate root
            include_sensitive: Whether to include sensitive information
            
        Returns:
            UserResponse DTO
        """
        return UserResponse(
            id=user.id,
            username=user.username.value,
            email=user.email.value,
            email_verified=user.email_verified,
            status=user.status,
            first_name=user._profile.first_name if user._profile else None,
            last_name=user._profile.last_name if user._profile else None,
            avatar_url=user.avatar_url,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login_at=user.last_login
        )
    
    @staticmethod
    def to_detail_response(
        user: User,
        include_permissions: bool = True,
        include_metadata: bool = False
    ) -> UserDetailResponse:
        """Convert User aggregate to detailed UserDetailResponse DTO.
        
        Args:
            user: User aggregate root
            include_permissions: Whether to include permissions
            include_metadata: Whether to include metadata
            
        Returns:
            UserDetailResponse DTO
        """
        from .permission_mapper import PermissionMapper
        from .role_mapper import RoleMapper
        
        # Get roles and permissions if requested
        roles = []
        permissions = []
        
        if include_permissions:
            roles = [RoleMapper.to_response(role) for role in user._roles]
            permissions = [
                PermissionMapper.to_response(perm) 
                for perm in user.get_all_permissions()
            ]
        
        # Calculate profile completion
        profile_completion = UserMapper._calculate_profile_completion(user)
        
        return UserDetailResponse(
            id=user.id,
            username=user.username.value,
            email=user.email.value,
            email_verified=user.email_verified,
            status=user.status,
            first_name=user._profile.first_name if user._profile else None,
            last_name=user._profile.last_name if user._profile else None,
            avatar_url=user.avatar_url,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login_at=user.last_login,
            roles=roles,
            permissions=permissions,
            profile_completion=profile_completion,
            mfa_enabled=user.mfa_enabled,
            active_sessions=len(user.get_active_sessions()),
            risk_score=user.get_risk_score(),
            metadata=user.to_dict() if include_metadata else None
        )
    
    @staticmethod
    def to_summary_response(user: User) -> UserSummaryResponse:
        """Convert User aggregate to UserSummaryResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            UserSummaryResponse DTO
        """
        # Get primary role
        primary_role = user._roles[0] if user._roles else None
        role_enum = primary_role.name if primary_role else "user"
        
        # Convert role name to UserRole enum if available
        from app.modules.identity.domain.entities.user.user_enums import UserRole
        try:
            user_role = UserRole(role_enum)
        except ValueError:
            user_role = UserRole.USER  # Default to USER if conversion fails
        
        # Get full name
        full_name = None
        if user._profile:
            if user._profile.first_name and user._profile.last_name:
                full_name = f"{user._profile.first_name} {user._profile.last_name}"
            elif user._profile.display_name:
                full_name = user._profile.display_name
        
        return UserSummaryResponse(
            id=user.id,
            username=user.username.value,
            email=user.email.value,
            first_name=user._profile.first_name if user._profile else None,
            last_name=user._profile.last_name if user._profile else None,
            full_name=full_name,
            avatar_url=user.avatar_url,
            status=user.status,
            role=user_role,
            last_login_at=user.last_login,
            created_at=user.created_at
        )
    
    @staticmethod
    def to_profile_response(user: User) -> UserProfileResponse:
        """Convert User profile to UserProfileResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            UserProfileResponse DTO
        """
        if not user._profile:
            # Create minimal profile response if no profile exists
            return UserProfileResponse(
                id=user.id,  # Use user ID as profile ID for now
                user_id=user.id,
                bio=None,
                date_of_birth=None,
                gender=None,
                language="en",
                timezone="UTC",
                preferences={},
                social_links={},
                completion_percentage=UserMapper._calculate_profile_completion(user),
                updated_at=user.updated_at
            )
        
        profile = user._profile
        return UserProfileResponse(
            id=profile.id,
            user_id=user.id,
            bio=getattr(profile, 'bio', None),
            date_of_birth=getattr(profile, 'date_of_birth', None),
            gender=getattr(profile, 'gender', None),
            language=getattr(profile, 'language', 'en'),
            timezone=getattr(profile, 'timezone', 'UTC'),
            preferences=getattr(profile, 'preferences', {}),
            social_links=getattr(profile, 'social_links', {}),
            completion_percentage=UserMapper._calculate_profile_completion(user),
            updated_at=profile.updated_at
        )
    
    @staticmethod
    def to_preferences_response(user: User) -> UserPreferencesResponse:
        """Convert User preferences to UserPreferencesResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            UserPreferencesResponse DTO
        """
        if not user._preferences:
            # Return default preferences
            return UserPreferencesResponse(
                user_id=user.id,
                notifications={},
                ui_theme="light",
                language="en",
                timezone="UTC",
                date_format="YYYY-MM-DD",
                time_format="24h",
                privacy={},
                updated_at=user.updated_at
            )
        
        prefs = user._preferences
        return UserPreferencesResponse(
            user_id=user.id,
            notifications=getattr(prefs, 'notifications', {}),
            ui_theme=getattr(prefs, 'ui_theme', 'light'),
            language=getattr(prefs, 'language', 'en'),
            timezone=getattr(prefs, 'timezone', 'UTC'),
            date_format=getattr(prefs, 'date_format', 'YYYY-MM-DD'),
            time_format=getattr(prefs, 'time_format', '24h'),
            privacy=getattr(prefs, 'privacy', {}),
            updated_at=prefs.updated_at
        )
    
    @staticmethod
    def to_activity_response(user: User) -> UserActivityResponse:
        """Convert User to UserActivityResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            UserActivityResponse DTO
        """
        # Calculate activity metrics from login history
        login_history = user.get_login_history(limit=100)
        
        # Count logins by time period
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)
        
        login_count_today = len([
            attempt for attempt in login_history
            if attempt.timestamp >= today_start and attempt.success
        ])
        
        login_count_week = len([
            attempt for attempt in login_history
            if attempt.timestamp >= week_start and attempt.success
        ])
        
        login_count_month = len([
            attempt for attempt in login_history
            if attempt.timestamp >= month_start and attempt.success
        ])
        
        failed_attempts = len([
            attempt for attempt in login_history[:10]  # Recent failures
            if not attempt.success
        ])
        
        # Determine activity trend
        recent_logins = len([
            attempt for attempt in login_history
            if attempt.timestamp >= (now - timedelta(days=3)) and attempt.success
        ])
        older_logins = len([
            attempt for attempt in login_history
            if week_start <= attempt.timestamp < (now - timedelta(days=3)) and attempt.success
        ])
        
        if recent_logins > older_logins:
            trend = "increasing"
        elif recent_logins < older_logins:
            trend = "decreasing"
        else:
            trend = "stable"
        
        # Get risk indicators
        risk_indicators = []
        if failed_attempts > 3:
            risk_indicators.append("multiple_failed_logins")
        if user.get_password_age_days() > 90:
            risk_indicators.append("old_password")
        if not user.mfa_enabled:
            risk_indicators.append("no_mfa")
        if not user.email_verified:
            risk_indicators.append("unverified_email")
        
        return UserActivityResponse(
            user_id=user.id,
            login_count_today=login_count_today,
            login_count_week=login_count_week,
            login_count_month=login_count_month,
            failed_login_attempts=failed_attempts,
            password_changes=0,  # Would need to track this in domain
            profile_updates=0,  # Would need to track this in domain
            security_events=0,  # Would need to track this in domain
            last_activity=user.last_login,
            most_used_device=None,  # Would need device analytics
            most_common_location=None,  # Would need location analytics
            activity_trend=trend,
            risk_indicators=risk_indicators
        )
    
    @staticmethod
    def to_profile_completion_response(user: User) -> ProfileCompletionResponse:
        """Convert User to ProfileCompletionResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            ProfileCompletionResponse DTO
        """
        # Define required and optional fields
        required_fields = ['email', 'username']
        optional_fields = [
            'first_name', 'last_name', 'bio', 'phone_number', 'avatar_url',
            'date_of_birth', 'location', 'website'
        ]
        
        completed_fields = []
        missing_fields = []
        
        # Check core user fields
        if user.email and user.email_verified:
            completed_fields.append('email')
        else:
            missing_fields.append('email')
        
        if user.username:
            completed_fields.append('username')
        else:
            missing_fields.append('username')
        
        # Check profile fields
        if user._profile:
            profile = user._profile
            
            if getattr(profile, 'first_name', None):
                completed_fields.append('first_name')
            else:
                missing_fields.append('first_name')
                
            if getattr(profile, 'last_name', None):
                completed_fields.append('last_name')
            else:
                missing_fields.append('last_name')
                
            if getattr(profile, 'bio', None):
                completed_fields.append('bio')
            else:
                missing_fields.append('bio')
        else:
            missing_fields.extend(['first_name', 'last_name', 'bio'])
        
        # Check other optional fields
        if user.phone_number:
            completed_fields.append('phone_number')
        else:
            missing_fields.append('phone_number')
            
        if user.avatar_url:
            completed_fields.append('avatar_url')
        else:
            missing_fields.append('avatar_url')
        
        # Calculate completion percentage
        total_fields = len(required_fields) + len(optional_fields)
        completion_percentage = len(completed_fields) / total_fields * 100
        
        # Generate recommendations
        recommendations = []
        if 'first_name' in missing_fields:
            recommendations.append({
                'field': 'first_name',
                'message': 'Add your first name to personalize your account'
            })
        if 'avatar_url' in missing_fields:
            recommendations.append({
                'field': 'avatar_url', 
                'message': 'Upload a profile picture to help others recognize you'
            })
        if 'bio' in missing_fields:
            recommendations.append({
                'field': 'bio',
                'message': 'Add a bio to tell others about yourself'
            })
        
        # Generate next steps
        next_steps = []
        if not user.email_verified:
            next_steps.append('Verify your email address')
        if not user.mfa_enabled:
            next_steps.append('Enable two-factor authentication for security')
        if not user.phone_number:
            next_steps.append('Add a phone number for account recovery')
        
        return ProfileCompletionResponse(
            user_id=user.id,
            completion_percentage=completion_percentage,
            completed_fields=completed_fields,
            missing_fields=[f for f in missing_fields if f not in required_fields],
            optional_fields=optional_fields,
            recommendations=recommendations,
            next_steps=next_steps
        )
    
    @staticmethod
    def to_security_profile_response(user: User) -> UserSecurityProfileResponse:
        """Convert User to UserSecurityProfileResponse DTO.
        
        Args:
            user: User aggregate root
            
        Returns:
            UserSecurityProfileResponse DTO
        """
        # Calculate trust score (inverse of risk score)
        risk_score = user.get_risk_score()
        trust_score = max(0.0, 1.0 - risk_score)
        
        # Get security metrics
        login_history = user.get_login_history(limit=50)
        failed_attempts = len([a for a in login_history[:10] if not a.success])
        
        # Check for unusual activity
        unusual_activity = (
            failed_attempts > 5 or
            user.get_password_age_days() > 180 or
            (user.last_login and (datetime.utcnow() - user.last_login).days > 30)
        )
        
        return UserSecurityProfileResponse(
            success=True,
            user_id=user.id,
            trust_score=trust_score,
            risk_score=risk_score,
            account_age_days=user.get_account_age_days(),
            mfa_enabled=user.mfa_enabled,
            recent_suspicious_activities=0,  # Would need security event tracking
            failed_login_attempts=failed_attempts,
            unusual_activity_detected=unusual_activity,
            last_security_review=None  # Would need to track security reviews
        )
    
    @staticmethod
    def _calculate_profile_completion(user: User) -> float:
        """Calculate profile completion percentage.
        
        Args:
            user: User aggregate root
            
        Returns:
            Profile completion percentage (0.0 to 1.0)
        """
        total_fields = 8  # Total trackable fields
        completed_fields = 0
        
        # Core fields (weight: 1 each)
        if user.email and user.email_verified:
            completed_fields += 1
        if user.username:
            completed_fields += 1
        
        # Profile fields (weight: 1 each)
        if user._profile:
            if getattr(user._profile, 'first_name', None):
                completed_fields += 1
            if getattr(user._profile, 'last_name', None):
                completed_fields += 1
            if getattr(user._profile, 'bio', None):
                completed_fields += 1
        
        # Optional fields (weight: 1 each)
        if user.phone_number and user.phone_verified:
            completed_fields += 1
        if user.avatar_url:
            completed_fields += 1
        if user.mfa_enabled:
            completed_fields += 1
        
        return completed_fields / total_fields