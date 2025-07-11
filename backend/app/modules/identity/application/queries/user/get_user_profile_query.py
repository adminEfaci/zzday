"""
Get user profile query implementation.

Handles retrieval of comprehensive user profile information including
personal details, security settings, activity summary, and preferences.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import UserProfileResponse
from app.modules.identity.domain.enums import AccountType
from app.modules.identity.domain.exceptions import (
    UnauthorizedAccessError,
    UserNotFoundError,
    UserProfileQueryError,
)
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
from app.modules.identity.domain.interfaces.services import (
    IPreferencesRepository,
)
    IUserRepository,
)


class ProfileDetailLevel(Enum):
    """Level of detail to include in user profile."""
    BASIC = "basic"
    STANDARD = "standard"
    DETAILED = "detailed"
    COMPREHENSIVE = "comprehensive"


class ProfileInclude(Enum):
    """Additional information to include in profile."""
    ACTIVITY_SUMMARY = "activity_summary"
    SECURITY_SETTINGS = "security_settings"
    PREFERENCES = "preferences"
    DEVICES = "devices"
    SESSIONS = "sessions"
    PERMISSIONS = "permissions"
    AUDIT_TRAIL = "audit_trail"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_STATUS = "compliance_status"


@dataclass
class GetUserProfileQuery(Query[UserProfileResponse]):
    """Query to retrieve user profile information."""
    
    # Target user
    user_id: UUID

    # Access control
    requester_id: UUID
    requester_permissions: list[str] = field(default_factory=list)

    # Detail level
    detail_level: ProfileDetailLevel = ProfileDetailLevel.STANDARD
    
    # Additional information to include
    include: list[ProfileInclude] | None = None
    
    # Time range for activity data
    activity_days: int = 30
    
    # Privacy and security options
    mask_sensitive_data: bool = True
    include_security_details: bool = False
    include_personal_details: bool = True
    
    # Filtering options
    session_limit: int = 10
    device_limit: int = 10
    audit_limit: int = 50
    
    # Output options
    export_format: str | None = None
    include_metadata: bool = False
    


class GetUserProfileQueryHandler(QueryHandler[GetUserProfileQuery, UserProfileResponse]):
    """Handler for user profile queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        audit_repository: IAuditRepository,
        device_repository: IDeviceRepository,
        preferences_repository: IPreferencesRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.audit_repository = audit_repository
        self.device_repository = device_repository
        self.preferences_repository = preferences_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.profile.read")
    @validate_request
    async def handle(self, query: GetUserProfileQuery) -> UserProfileResponse:
        """Handle user profile query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_profile_access(query)
                
                # Get user entity
                user = await self.user_repository.find_by_id(query.user_id)
                if not user:
                    raise UserNotFoundError(f"User {query.user_id} not found")
                
                # Build base profile
                profile = await self._build_base_profile(user, query)
                
                # Add additional information based on includes
                if query.include:
                    if ProfileInclude.ACTIVITY_SUMMARY in query.include:
                        profile["activity_summary"] = await self._get_activity_summary(
                            query.user_id, query.activity_days
                        )
                    
                    if ProfileInclude.SECURITY_SETTINGS in query.include:
                        profile["security_settings"] = await self._get_security_settings(
                            user, query
                        )
                    
                    if ProfileInclude.PREFERENCES in query.include:
                        profile["preferences"] = await self._get_user_preferences(
                            query.user_id
                        )
                    
                    if ProfileInclude.DEVICES in query.include:
                        profile["devices"] = await self._get_user_devices(
                            query.user_id, query.device_limit
                        )
                    
                    if ProfileInclude.SESSIONS in query.include:
                        profile["sessions"] = await self._get_user_sessions(
                            query.user_id, query.session_limit
                        )
                    
                    if ProfileInclude.PERMISSIONS in query.include:
                        profile["permissions"] = await self._get_user_permissions(
                            user, query
                        )
                    
                    if ProfileInclude.AUDIT_TRAIL in query.include:
                        profile["audit_trail"] = await self._get_audit_trail(
                            query.user_id, query.audit_limit
                        )
                    
                    if ProfileInclude.RISK_ASSESSMENT in query.include:
                        profile["risk_assessment"] = await self._get_risk_assessment(
                            query.user_id
                        )
                    
                    if ProfileInclude.COMPLIANCE_STATUS in query.include:
                        profile["compliance_status"] = await self._get_compliance_status(
                            query.user_id
                        )
                
                # Apply data masking if required
                if query.mask_sensitive_data:
                    profile = await self._mask_sensitive_data(profile, query)
                
                # Generate metadata if requested
                metadata = None
                if query.include_metadata:
                    metadata = await self._generate_metadata(user, query)
                
                # Prepare export data if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        profile, query.export_format
                    )
                
                return UserProfileResponse(
                    user_id=query.user_id,
                    profile=profile,
                    detail_level=query.detail_level.value,
                    included_sections=query.include or [],
                    metadata=metadata,
                    export_data=export_data,
                    retrieved_at=datetime.now(UTC)
                )
                
        except Exception as e:
            raise UserProfileQueryError(f"Failed to retrieve user profile: {e!s}") from e
    
    async def _validate_profile_access(self, query: GetUserProfileQuery) -> None:
        """Validate user has appropriate permissions for profile access."""
        
        # Check basic profile read permission
        if "user.profile.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for user profile access")
        
        # Check if accessing own profile vs others'
        if query.user_id != query.requester_id:
            if "user.profile.read.all" not in query.requester_permissions:
                raise UnauthorizedAccessError("Cannot access other users' profiles")
        
        # Check sensitive data access
        if not query.mask_sensitive_data or query.include_security_details:
            if "user.profile.sensitive" not in query.requester_permissions:
                raise UnauthorizedAccessError("No permission for sensitive profile data")
        
        # Check specific include permissions
        if query.include:
            if ProfileInclude.SECURITY_SETTINGS in query.include:
                if "user.security.read" not in query.requester_permissions:
                    raise UnauthorizedAccessError("No permission for security settings")
            
            if ProfileInclude.AUDIT_TRAIL in query.include:
                if "audit.user_activity.read" not in query.requester_permissions:
                    raise UnauthorizedAccessError("No permission for audit trail")
            
            if ProfileInclude.RISK_ASSESSMENT in query.include:
                if "security.risk_assessment.read" not in query.requester_permissions:
                    raise UnauthorizedAccessError("No permission for risk assessment")
            
            if ProfileInclude.COMPLIANCE_STATUS in query.include:
                if "compliance.status.read" not in query.requester_permissions:
                    raise UnauthorizedAccessError("No permission for compliance status")
    
    async def _build_base_profile(self, user, query: GetUserProfileQuery) -> dict[str, Any]:
        """Build base user profile information."""
        
        profile = {
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "status": user.status.value if hasattr(user.status, 'value') else str(user.status),
            "account_type": getattr(user, 'account_type', AccountType.STANDARD).value,
            "created_at": user.created_at,
            "last_login_at": user.last_login_at,
            "is_active": user.is_active,
            "is_verified": user.is_verified
        }
        
        # Add personal details if requested and permitted
        if query.include_personal_details:
            profile.update({
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": f"{user.first_name} {user.last_name}",
                "phone_number": getattr(user, 'phone_number', None),
                "timezone": getattr(user, 'timezone', None),
                "language": getattr(user, 'language', 'en'),
                "department": getattr(user, 'department', None),
                "title": getattr(user, 'title', None),
                "manager_id": getattr(user, 'manager_id', None)
            })
        
        # Add detail level specific information
        if query.detail_level in [ProfileDetailLevel.DETAILED, ProfileDetailLevel.COMPREHENSIVE]:
            profile.update({
                "roles": user.roles,
                "updated_at": user.updated_at,
                "password_changed_at": getattr(user, 'password_changed_at', None),
                "failed_login_attempts": getattr(user, 'failed_login_attempts', 0),
                "account_locked_until": getattr(user, 'account_locked_until', None),
                "must_change_password": getattr(user, 'must_change_password', False)
            })
        
        if query.detail_level == ProfileDetailLevel.COMPREHENSIVE:
            profile.update({
                "login_count": getattr(user, 'login_count', 0),
                "last_password_change": getattr(user, 'last_password_change', None),
                "terms_accepted_at": getattr(user, 'terms_accepted_at', None),
                "privacy_policy_accepted_at": getattr(user, 'privacy_policy_accepted_at', None),
                "marketing_emails_enabled": getattr(user, 'marketing_emails_enabled', False),
                "notification_preferences": getattr(user, 'notification_preferences', {})
            })
        
        return profile
    
    async def _get_activity_summary(self, user_id: UUID, days: int) -> dict[str, Any]:
        """Get user activity summary for the specified number of days."""
        
        end_date = datetime.now(UTC)
        start_date = end_date - timedelta(days=days)
        
        # Get activity statistics
        activity_stats = await self.audit_repository.get_user_activity_summary(
            user_id, start_date, end_date
        )
        
        # Get session statistics
        session_stats = await self.session_repository.get_user_session_summary(
            user_id, start_date, end_date
        )
        
        # Get login pattern
        login_pattern = await self.audit_repository.get_user_login_pattern(
            user_id, start_date, end_date
        )
        
        return {
            "period_days": days,
            "start_date": start_date,
            "end_date": end_date,
            "total_activities": activity_stats.get("total_activities", 0),
            "unique_resources_accessed": activity_stats.get("unique_resources", 0),
            "total_sessions": session_stats.get("total_sessions", 0),
            "total_session_time_minutes": session_stats.get("total_time_minutes", 0),
            "average_session_duration_minutes": session_stats.get("average_duration_minutes", 0),
            "login_frequency": login_pattern.get("frequency", "unknown"),
            "most_active_hours": login_pattern.get("most_active_hours", []),
            "activity_trend": activity_stats.get("trend", "stable"),
            "last_activity_at": activity_stats.get("last_activity_at")
        }
    
    async def _get_security_settings(self, user, query: GetUserProfileQuery) -> dict[str, Any]:
        """Get user security settings."""
        
        # Get MFA status
        mfa_status = getattr(user, 'mfa_enabled', False)
        mfa_methods = getattr(user, 'mfa_methods', [])
        
        # Get password policy compliance
        password_policy = await self._check_password_policy_compliance(user)
        
        # Get session security settings
        session_settings = await self._get_session_security_settings(user.id)
        
        # Get security notifications
        security_notifications = getattr(user, 'security_notifications_enabled', True)
        
        security_settings = {
            "mfa_enabled": mfa_status,
            "mfa_methods": mfa_methods,
            "password_policy_compliance": password_policy,
            "session_settings": session_settings,
            "security_notifications_enabled": security_notifications,
            "account_locked": getattr(user, 'account_locked_until', None) is not None,
            "password_expires_at": getattr(user, 'password_expires_at', None),
            "require_password_change": getattr(user, 'must_change_password', False)
        }
        
        # Add additional security details if permitted
        if query.include_security_details:
            security_settings.update({
                "failed_login_attempts": getattr(user, 'failed_login_attempts', 0),
                "last_failed_login_at": getattr(user, 'last_failed_login_at', None),
                "security_questions_set": getattr(user, 'security_questions_set', False),
                "backup_codes_generated": getattr(user, 'backup_codes_generated', False),
                "trusted_devices_count": await self._count_trusted_devices(user.id),
                "recent_security_events": await self._get_recent_security_events(user.id)
            })
        
        return security_settings
    
    async def _get_user_preferences(self, user_id: UUID) -> dict[str, Any]:
        """Get user preferences."""
        
        preferences = await self.preferences_repository.get_user_preferences(user_id)
        
        if not preferences:
            return {
                "notification_preferences": {},
                "display_preferences": {},
                "privacy_preferences": {},
                "accessibility_preferences": {}
            }
        
        return {
            "notification_preferences": preferences.get("notifications", {}),
            "display_preferences": preferences.get("display", {}),
            "privacy_preferences": preferences.get("privacy", {}),
            "accessibility_preferences": preferences.get("accessibility", {}),
            "integration_preferences": preferences.get("integrations", {}),
            "updated_at": preferences.get("updated_at")
        }
    
    async def _get_user_devices(self, user_id: UUID, limit: int) -> list[dict[str, Any]]:
        """Get user devices."""
        
        devices = await self.device_repository.find_by_user(user_id, limit=limit)
        
        device_list = []
        for device in devices:
            device_info = {
                "device_id": str(device.id),
                "device_name": device.name,
                "device_type": device.device_type,
                "platform": device.platform,
                "is_trusted": device.is_trusted,
                "is_active": device.is_active,
                "first_seen_at": device.first_seen_at,
                "last_seen_at": device.last_seen_at,
                "location": getattr(device, 'last_location', None)
            }
            
            # Add additional device details for comprehensive view
            if hasattr(device, 'user_agent'):
                device_info["user_agent"] = device.user_agent
            
            if hasattr(device, 'fingerprint'):
                device_info["fingerprint"] = device.fingerprint[:10] + "..." if device.fingerprint else None
            
            device_list.append(device_info)
        
        return device_list
    
    async def _get_user_sessions(self, user_id: UUID, limit: int) -> list[dict[str, Any]]:
        """Get user sessions."""
        
        sessions = await self.session_repository.get_user_sessions(user_id, limit=limit)
        
        session_list = []
        for session in sessions:
            session_info = {
                "session_id": str(session.id),
                "created_at": session.created_at,
                "last_activity_at": session.last_activity_at,
                "status": session.status.value if hasattr(session.status, 'value') else str(session.status),
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "device_id": str(session.device_id) if session.device_id else None,
                "location": getattr(session, 'location', None),
                "is_current": getattr(session, 'is_current', False)
            }
            
            # Calculate session duration
            if session.ended_at:
                duration = (session.ended_at - session.created_at).total_seconds()
                session_info["duration_seconds"] = duration
                session_info["ended_at"] = session.ended_at
            elif session.last_activity_at:
                duration = (session.last_activity_at - session.created_at).total_seconds()
                session_info["duration_seconds"] = duration
            
            session_list.append(session_info)
        
        return session_list
    
    async def _get_user_permissions(self, user, query: GetUserProfileQuery) -> dict[str, Any]:
        """Get user permissions and roles."""
        
        # Get explicit permissions
        explicit_permissions = getattr(user, 'permissions', [])
        
        # Get role-based permissions
        role_permissions = []
        for role in user.roles:
            role_perms = await self.user_repository.find_by_role(role)
            role_permissions.extend(role_perms)
        
        # Get effective permissions (combination of explicit and role-based)
        all_permissions = list(set(explicit_permissions + role_permissions))
        
        # Group permissions by category
        permission_groups = await self._group_permissions_by_category(all_permissions)
        
        return {
            "roles": user.roles,
            "explicit_permissions": explicit_permissions,
            "role_based_permissions": role_permissions,
            "effective_permissions": all_permissions,
            "permission_groups": permission_groups,
            "is_admin": "admin" in user.roles or "system_admin" in user.roles,
            "is_super_user": "super_user" in user.roles,
            "permission_count": len(all_permissions)
        }
    
    async def _get_audit_trail(self, user_id: UUID, limit: int) -> list[dict[str, Any]]:
        """Get user audit trail."""
        
        # Get recent audit entries
        audit_entries = await self.audit_repository.get_user_audit_trail(
            user_id, limit=limit
        )
        
        trail = []
        for entry in audit_entries:
            trail_item = {
                "id": str(entry.id),
                "action": entry.action,
                "resource": entry.resource,
                "timestamp": entry.timestamp,
                "ip_address": entry.ip_address,
                "user_agent": entry.user_agent,
                "result": entry.result,
                "risk_level": getattr(entry, 'risk_level', 'low')
            }
            
            # Add additional context if available
            if hasattr(entry, 'context') and entry.context:
                trail_item["context"] = entry.context
            
            trail.append(trail_item)
        
        return trail
    
    async def _get_risk_assessment(self, user_id: UUID) -> dict[str, Any]:
        """Get user risk assessment."""
        
        # Get latest risk assessment
        risk_assessment = await self.audit_repository.get_user_risk_assessment(user_id)
        
        if not risk_assessment:
            return {
                "risk_level": "low",
                "risk_score": 0,
                "last_assessed_at": None,
                "risk_factors": []
            }
        
        return {
            "risk_level": risk_assessment.get("risk_level", "low"),
            "risk_score": risk_assessment.get("risk_score", 0),
            "last_assessed_at": risk_assessment.get("assessed_at"),
            "risk_factors": risk_assessment.get("risk_factors", []),
            "recommendations": risk_assessment.get("recommendations", []),
            "next_assessment_due": risk_assessment.get("next_assessment_due")
        }
    
    async def _get_compliance_status(self, user_id: UUID) -> dict[str, Any]:
        """Get user compliance status."""
        
        compliance_status = await self.user_repository.get_user_compliance_status(user_id)
        
        return {
            "gdpr_compliant": compliance_status.get("gdpr_compliant", True),
            "data_retention_compliant": compliance_status.get("data_retention_compliant", True),
            "access_review_status": compliance_status.get("access_review_status", "current"),
            "training_completion_status": compliance_status.get("training_completion", {}),
            "policy_acknowledgment_status": compliance_status.get("policy_acknowledgment", {}),
            "last_compliance_check": compliance_status.get("last_check_at"),
            "compliance_score": compliance_status.get("compliance_score", 100)
        }
    
    async def _mask_sensitive_data(self, profile: dict[str, Any], query: GetUserProfileQuery) -> dict[str, Any]:
        """Mask sensitive data based on permissions."""
        
        masked_profile = profile.copy()
        
        # Mask email if not permitted
        if "user.email.read" not in query.requester_permissions:
            if "email" in masked_profile:
                email = masked_profile["email"]
                if "@" in email:
                    local, domain = email.split("@", 1)
                    masked_profile["email"] = f"{local[:2]}***@{domain}"
        
        # Mask phone number if not permitted
        if "user.phone.read" not in query.requester_permissions:
            if masked_profile.get("phone_number"):
                phone = masked_profile["phone_number"]
                masked_profile["phone_number"] = f"***-***-{phone[-4:]}" if len(phone) >= 4 else "***"
        
        # Mask IP addresses in sessions and audit trail
        if "user.ip_addresses.read" not in query.requester_permissions:
            if "sessions" in masked_profile:
                for session in masked_profile["sessions"]:
                    if "ip_address" in session:
                        ip_parts = session["ip_address"].split(".")
                        if len(ip_parts) == 4:
                            session["ip_address"] = f"{ip_parts[0]}.{ip_parts[1]}.*.* "
            
            if "audit_trail" in masked_profile:
                for entry in masked_profile["audit_trail"]:
                    if "ip_address" in entry:
                        ip_parts = entry["ip_address"].split(".")
                        if len(ip_parts) == 4:
                            entry["ip_address"] = f"{ip_parts[0]}.{ip_parts[1]}.*.* "
        
        return masked_profile
    
    # Helper methods (placeholder implementations)
    async def _check_password_policy_compliance(self, user) -> dict[str, Any]:
        """Check password policy compliance."""
        return {
            "compliant": True,
            "strength_score": 85,
            "issues": []
        }
    
    async def _get_session_security_settings(self, user_id: UUID) -> dict[str, Any]:
        """Get session security settings."""
        return {
            "concurrent_sessions_allowed": 3,
            "session_timeout_minutes": 120,
            "require_mfa_for_new_devices": True
        }
    
    async def _count_trusted_devices(self, user_id: UUID) -> int:
        """Count trusted devices."""
        return 2
    
    async def _get_recent_security_events(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get recent security events."""
        return [
            {"event": "login_success", "timestamp": datetime.now(UTC) - timedelta(hours=2)}
        ]
    
    async def _group_permissions_by_category(self, permissions: list[str]) -> dict[str, list[str]]:
        """Group permissions by category."""
        groups = {}
        for permission in permissions:
            category = permission.split(".")[0] if "." in permission else "general"
            if category not in groups:
                groups[category] = []
            groups[category].append(permission)
        return groups
    
    async def _generate_metadata(self, user, query: GetUserProfileQuery) -> dict[str, Any]:
        """Generate metadata about the profile query."""
        return {
            "profile_completeness": await self._calculate_profile_completeness(user),
            "last_profile_update": getattr(user, 'updated_at', None),
            "data_sources": ["user_repository", "session_repository", "audit_repository"],
            "generated_at": datetime.now(UTC)
        }
    
    async def _calculate_profile_completeness(self, user) -> float:
        """Calculate profile completeness percentage."""
        total_fields = 10
        completed_fields = 0
        
        if user.first_name:
            completed_fields += 1
        if user.last_name:
            completed_fields += 1
        if user.email:
            completed_fields += 1
        if getattr(user, 'phone_number', None):
            completed_fields += 1
        if getattr(user, 'department', None):
            completed_fields += 1
        if getattr(user, 'title', None):
            completed_fields += 1
        if getattr(user, 'timezone', None):
            completed_fields += 1
        if user.is_verified:
            completed_fields += 1
        if getattr(user, 'mfa_enabled', False):
            completed_fields += 1
        if user.roles:
            completed_fields += 1
        
        return (completed_fields / total_fields) * 100
    
    async def _prepare_export_data(self, profile: dict[str, Any], export_format: str) -> dict[str, Any]:
        """Prepare profile for export."""
        return {
            "format": export_format,
            "content": f"User profile in {export_format} format",
            "filename": f"user_profile_{profile.get('user_id')}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{export_format}"
        }