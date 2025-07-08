"""
Export user data command implementation.

Handles GDPR-compliant user data export with comprehensive data collection.
"""

import asyncio
import json
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    AdminContext,
    ExportConfig,
    InfrastructureDependencies,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import ExportUserDataRequest
from app.modules.identity.application.dtos.response import UserDataExportResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, NotificationType, UserStatus
from app.modules.identity.domain.events import (
    UserDataExportCompleted,
    UserDataExportRequested,
)
from app.modules.identity.domain.exceptions import (
    DataExportError,
    ExportInProgressError,
    UnauthorizedError,
    UserNotFoundError,
)


class ExportFormat(Enum):
    """Data export formats."""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    PDF = "pdf"
    ZIP = "zip"  # Multiple formats


class DataCategory(Enum):
    """Categories of user data."""
    PROFILE = "profile"
    AUTHENTICATION = "authentication"
    SESSIONS = "sessions"
    PERMISSIONS = "permissions"
    AUDIT_LOGS = "audit_logs"
    NOTIFICATIONS = "notifications"
    PREFERENCES = "preferences"
    SECURITY = "security"
    EMERGENCY_CONTACTS = "emergency_contacts"
    DEVICES = "devices"
    INTEGRATIONS = "integrations"
    GDPR = "gdpr"
    ALL = "all"


class ExportUserDataCommand(Command[UserDataExportResponse]):
    """Command to export user data."""
    
    def __init__(
        self,
        admin_context: AdminContext,
        export_config: ExportConfig,
        **additional_options
    ):
        self.admin_context = admin_context
        self.export_config = export_config
        self.additional_options = additional_options
        
        # For backward compatibility, expose common fields
        self.target_user_id = admin_context.target_user_id
        self.requesting_user_id = admin_context.admin_user_id
        self.reason = admin_context.reason
        self.data_categories = [
            DataCategory(cat) for cat in export_config.include_categories
        ]
        self.format = ExportFormat(export_config.export_format)
        self.include_deleted = additional_options.get('include_deleted', False)
        self.include_metadata = additional_options.get('include_metadata', True)
        self.anonymize_pii = additional_options.get('anonymize_pii', False)
        self.date_range_start = additional_options.get('date_range_start')
        self.date_range_end = (
            additional_options.get('date_range_end') or datetime.now(UTC)
        )
        self.password_protect = additional_options.get('password_protect', True)
        self.encryption_key = additional_options.get('encryption_key')
        self.notification_email = additional_options.get('notification_email')
        self.gdpr_request = additional_options.get('gdpr_request', False)
        self.metadata = {**admin_context.metadata, **export_config.metadata}


class ExportUserDataCommandHandler(
    CommandHandler[ExportUserDataCommand, UserDataExportResponse]
):
    """Handler for user data export."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies,
        data_privacy_service: Any  # DataPrivacyService
    ):
        self._user_repository = services.user_repository
        self._session_repository = services.session_repository
        self._audit_repository = services.audit_repository
        self._notification_repository = services.notification_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._email_service = services.email_service
        self._storage_service = services.storage_service
        self._encryption_service = services.encryption_service
        self._queue_service = services.queue_service
        self._data_privacy_service = data_privacy_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.DATA_EXPORT,
        resource_type="user",
        include_request=True,
        include_response=True,
        gdpr_compliant=True
    )
    @validate_request(ExportUserDataRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=86400,  # Daily limit
        strategy='user'
    )
    @require_permission(
        "users.export_data",
        resource_type="user",
        resource_id_param="target_user_id"
    )
    @require_mfa(
        skip_if_self=False  # Always require MFA for exports
    )
    async def handle(self, command: ExportUserDataCommand) -> UserDataExportResponse:
        """
        Export user data with comprehensive collection and security.
        
        Process:
        1. Validate permissions
        2. Check for existing exports
        3. Collect data from all sources
        4. Apply filters and anonymization
        5. Format and compress data
        6. Encrypt if required
        7. Upload to secure storage
        8. Send notification
        
        Returns:
            UserDataExportResponse with download details
            
        Raises:
            UserNotFoundError: If user not found
            UnauthorizedError: If lacks permission
            ExportInProgressError: If export already running
            DataExportError: If export fails
        """
        async with self._unit_of_work:
            # 1. Load users
            requesting_user = await self._user_repository.get_by_id(
                command.requesting_user_id
            )
            if not requesting_user:
                raise UnauthorizedError("Requesting user not found")
            
            target_user = await self._user_repository.get_by_id(command.target_user_id)
            if not target_user:
                raise UserNotFoundError(f"User {command.target_user_id} not found")
            
            # 2. Validate permissions
            is_self_export = command.requesting_user_id == command.target_user_id
            
            if not is_self_export:
                # Admin export - need additional checks
                if not await self._can_export_user_data(requesting_user, target_user):
                    raise UnauthorizedError(
                        "Insufficient privileges to export user data"
                    )
                
                # Log privacy-sensitive operation
                await self._data_privacy_service.log_data_access(
                    accessor_id=command.requesting_user_id,
                    data_subject_id=command.target_user_id,
                    purpose=command.reason,
                    data_categories=[c.value for c in command.data_categories]
                )
            
            # 3. Check for existing exports
            existing_export = await self._check_existing_export(command.target_user_id)
            if existing_export:
                raise ExportInProgressError(
                    f"Export already in progress: {existing_export['export_id']}"
                )
            
            # 4. Create export record
            export_id = UUID()
            export_record = await self._create_export_record(export_id, command)
            
            # 5. For large exports, queue the job
            total_data_size = await self._estimate_data_size(command)
            
            if total_data_size > 100_000_000:  # 100MB
                # Queue for async processing
                await self._queue_export_job(export_id, command)
                
                return UserDataExportResponse(
                    export_id=export_id,
                    user_id=command.target_user_id,
                    format=command.format.value,
                    status="processing",
                    progress=0.0,
                    message=(
                        "Large data export queued for processing. "
                        "You will be notified when complete."
                    ),
                    includes=[c.value for c in command.data_categories]
                )
            
            # 6. Collect data synchronously for smaller exports
            try:
                # Publish start event
                await self._event_bus.publish(
                    UserDataExportRequested(
                        aggregate_id=command.target_user_id,
                        export_id=export_id,
                        requested_by=command.requesting_user_id,
                        data_categories=[c.value for c in command.data_categories],
                        gdpr_request=command.gdpr_request
                    )
                )
                
                # Collect all data
                export_data = await self._collect_all_data(command, target_user)
                
                # Apply anonymization if requested
                if command.anonymize_pii:
                    export_data = await self._anonymize_data(export_data)
                
                # Format data
                formatted_data = await self._format_data(
                    export_data,
                    command.format,
                    command.include_metadata
                )
                
                # Compress if needed
                if command.format == ExportFormat.ZIP or len(formatted_data) > 10_000_000:
                    formatted_data = await self._compress_data(formatted_data, command.format)
                    file_extension = "zip"
                else:
                    file_extension = command.format.value
                
                # Encrypt data
                encrypted_data = formatted_data
                encryption_metadata = {}
                
                if command.password_protect or command.encryption_key:
                    encrypted_data, encryption_metadata = await self._encrypt_data(
                        formatted_data,
                        command.encryption_key or self._generate_export_password()
                    )
                
                # Upload to storage
                file_name = f"user_data_export_{command.target_user_id}_{export_id}.{file_extension}"
                download_url = await self._storage_service.upload(
                    bucket="user-exports",
                    key=file_name,
                    data=encrypted_data,
                    content_type=self._get_content_type(command.format),
                    metadata={
                        "export_id": str(export_id),
                        "user_id": str(command.target_user_id),
                        "requester_id": str(command.requesting_user_id),
                        "created_at": datetime.now(UTC).isoformat(),
                        "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                        **encryption_metadata
                    }
                )
                
                # Generate secure download link
                secure_url = await self._generate_secure_download_link(
                    download_url,
                    export_id,
                    expiry_hours=72
                )
                
                # Update export record
                await self._update_export_record(
                    export_id,
                    status="completed",
                    file_size=len(encrypted_data),
                    download_url=secure_url
                )
                
                # Send notification
                notification_email = command.notification_email or target_user.email
                
                await self._send_export_notification(
                    export_id,
                    notification_email,
                    target_user.username,
                    secure_url,
                    command.password_protect,
                    encryption_metadata.get("password_hint")
                )
                
                # Create in-app notification
                if not is_self_export:
                    await self._notification_service.create_notification(
                        NotificationContext(
                            notification_id=UUID(),
                            recipient_id=command.target_user_id,
                            notification_type=NotificationType.DATA_EXPORT,
                            channel="in_app",
                            template_id="data_export_by_admin",
                            template_data={
                                "admin_name": f"{requesting_user.first_name} {requesting_user.last_name}",
                                "reason": command.reason,
                                "export_id": str(export_id)
                            },
                            priority="high"
                        )
                    )
                
                # Publish completion event
                await self._event_bus.publish(
                    UserDataExportCompleted(
                        aggregate_id=command.target_user_id,
                        export_id=export_id,
                        file_size=len(encrypted_data),
                        duration_seconds=int((datetime.now(UTC) - export_record.created_at).total_seconds())
                    )
                )
                
                # Commit transaction
                await self._unit_of_work.commit()
                
                return UserDataExportResponse(
                    export_id=export_id,
                    user_id=command.target_user_id,
                    format=command.format.value,
                    status="completed",
                    progress=100.0,
                    file_size_bytes=len(encrypted_data),
                    download_url=secure_url,
                    expires_at=datetime.now(UTC) + timedelta(hours=72),
                    password_protected=command.password_protect,
                    includes=[c.value for c in command.data_categories],
                    message="Data export completed successfully"
                )
                
            except Exception as e:
                # Update export record with failure
                await self._update_export_record(
                    export_id,
                    status="failed",
                    error=str(e)
                )
                
                raise DataExportError(f"Export failed: {e!s}") from e
    
    async def _can_export_user_data(self, requesting_user: User, target_user: User) -> bool:
        """Check if requesting user can export target user's data."""
        # Check roles
        requester_roles = await self._authorization_service.get_user_roles(requesting_user.id)
        
        # Check for data protection officer role
        if any(role.name in ["dpo", "data_protection_officer", "super_admin"] for role in requester_roles):
            return True
        
        # Check for customer support with restrictions
        if any(role.name in ["support_admin", "customer_support"] for role in requester_roles):
            # Can only export active users
            return target_user.status == UserStatus.ACTIVE
        
        return False
    
    async def _check_existing_export(self, user_id: UUID) -> dict[str, Any] | None:
        """Check for existing in-progress exports."""
        # Check in cache/database for recent exports
        recent_exports = await self._data_privacy_service.get_recent_exports(
            user_id,
            hours=1
        )
        
        for export in recent_exports:
            if export["status"] in ["pending", "processing"]:
                return export
        
        return None
    
    async def _estimate_data_size(self, command: ExportUserDataCommand) -> int:
        """Estimate total data size for export."""
        size_estimates = {
            DataCategory.PROFILE: 10_000,  # 10KB
            DataCategory.AUTHENTICATION: 50_000,  # 50KB
            DataCategory.SESSIONS: 100_000,  # 100KB per year
            DataCategory.PERMISSIONS: 20_000,  # 20KB
            DataCategory.AUDIT_LOGS: 1_000_000,  # 1MB per year
            DataCategory.NOTIFICATIONS: 500_000,  # 500KB per year
            DataCategory.PREFERENCES: 5_000,  # 5KB
            DataCategory.SECURITY: 100_000,  # 100KB
            DataCategory.EMERGENCY_CONTACTS: 10_000,  # 10KB
            DataCategory.DEVICES: 50_000,  # 50KB
            DataCategory.INTEGRATIONS: 100_000,  # 100KB
            DataCategory.GDPR: 50_000,  # 50KB
        }
        
        total_size = 0
        
        if DataCategory.ALL in command.data_categories:
            # All categories
            for category, size in size_estimates.items():
                if category != DataCategory.ALL:
                    total_size += size
        else:
            # Selected categories
            for category in command.data_categories:
                total_size += size_estimates.get(category, 0)
        
        # Adjust for date range if specified
        if command.date_range_start:
            days_range = (command.date_range_end - command.date_range_start).days
            year_fraction = days_range / 365
            total_size = int(total_size * year_fraction)
        
        return total_size
    
    async def _collect_all_data(
        self,
        command: ExportUserDataCommand,
        user: User
    ) -> dict[str, Any]:
        """Collect all requested data."""
        export_data = self._prepare_export_metadata(command, user)
        
        categories = self._normalize_categories(command.data_categories)
        
        # Create data collectors mapping
        collectors = self._create_data_collectors_map(user, command)
        
        # Collect data for each category
        collection_tasks = [
            collectors[category]
            for category in categories
            if category in collectors
        ]
        
        # Execute collection in parallel
        results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        
        # Merge results
        for i, category in enumerate(categories):
            if category in collectors and not isinstance(results[i], Exception):
                export_data[category.value] = results[i]
            else:
                export_data[category.value] = {
                    "error": f"Failed to collect {category.value} data",
                    "details": str(results[i])
                }
        
        return export_data
    
    def _prepare_export_metadata(
        self,
        command: ExportUserDataCommand,
        user: User
    ) -> dict[str, Any]:
        """Prepare export metadata."""
        return {
            "export_metadata": {
                "export_id": str(UUID()),
                "user_id": str(user.id),
                "export_date": datetime.now(UTC).isoformat(),
                "requested_by": str(command.requesting_user_id),
                "data_categories": [c.value for c in command.data_categories],
                "date_range": {
                    "start": command.date_range_start.isoformat() if command.date_range_start else None,
                    "end": command.date_range_end.isoformat()
                }
            }
        }
    
    def _normalize_categories(
        self,
        categories: list[DataCategory]
    ) -> list[DataCategory]:
        """Normalize data categories, expanding ALL if present."""
        if DataCategory.ALL in categories:
            normalized = list(DataCategory)
            normalized.remove(DataCategory.ALL)
            return normalized
        return categories
    
    def _create_data_collectors_map(
        self,
        user: User,
        command: ExportUserDataCommand
    ) -> dict[DataCategory, Coroutine]:
        """Create mapping of data categories to collector coroutines."""
        return {
            DataCategory.PROFILE: self._collect_profile_data(user),
            DataCategory.AUTHENTICATION: self._collect_authentication_data(user),
            DataCategory.SESSIONS: self._collect_session_data(
                user.id,
                command.date_range_start,
                command.date_range_end
            ),
            DataCategory.PERMISSIONS: self._collect_permissions_data(user.id),
            DataCategory.AUDIT_LOGS: self._collect_audit_data(
                user.id,
                command.date_range_start,
                command.date_range_end,
                command.include_deleted
            ),
            DataCategory.NOTIFICATIONS: self._collect_notification_data(
                user.id,
                command.date_range_start,
                command.date_range_end
            ),
            DataCategory.PREFERENCES: self._collect_preferences_data(user.id),
            DataCategory.SECURITY: self._collect_security_data(user.id),
            DataCategory.EMERGENCY_CONTACTS: self._collect_emergency_contacts_data(user.id),
            DataCategory.DEVICES: self._collect_devices_data(user.id),
            DataCategory.INTEGRATIONS: self._collect_integrations_data(user.id),
            DataCategory.GDPR: self._collect_gdpr_data(user.id)
        }
    
    async def _collect_profile_data(self, user: User) -> dict[str, Any]:
        """Collect user profile data."""
        return {
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "email_verified": user.email_verified,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "full_name": user.full_name,
            "phone_number": user.phone_number,
            "status": user.status.value,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "metadata": user.metadata
        }
    
    async def _collect_authentication_data(self, user: User) -> dict[str, Any]:
        """Collect authentication-related data."""
        # Get MFA devices
        mfa_devices = await self._security_service.get_mfa_devices(user.id)
        
        # Get password history (metadata only, no hashes)
        password_history = await self._security_service.get_password_history(user.id)
        
        return {
            "mfa_enabled": user.mfa_enabled,
            "mfa_devices": [
                {
                    "id": str(device.id),
                    "name": device.name,
                    "type": device.method.value,
                    "created_at": device.created_at.isoformat(),
                    "last_used": device.last_used_at.isoformat() if device.last_used_at else None,
                    "verified": device.is_verified
                }
                for device in mfa_devices
            ],
            "password_changed_count": len(password_history),
            "last_password_change": password_history[0]["changed_at"] if password_history else None,
            "login_methods": await self._security_service.get_login_methods(user.id),
            "failed_login_attempts": await self._security_service.get_failed_login_count(user.id)
        }
    
    async def _collect_session_data(
        self,
        user_id: UUID,
        start_date: datetime | None,
        end_date: datetime
    ) -> dict[str, Any]:
        """Collect session history."""
        sessions = await self._session_repository.get_user_sessions(
            user_id,
            start_date,
            end_date,
            include_expired=True
        )
        
        return {
            "total_sessions": len(sessions),
            "active_sessions": sum(1 for s in sessions if s.is_active),
            "sessions": [
                {
                    "id": str(s.id),
                    "created_at": s.created_at.isoformat(),
                    "last_activity": s.last_activity_at.isoformat(),
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent,
                    "location": s.location,
                    "device_info": s.device_info,
                    "expired": not s.is_active,
                    "revoked": s.revoked,
                    "revoked_at": s.revoked_at.isoformat() if s.revoked_at else None
                }
                for s in sessions
            ]
        }
    
    async def _collect_permissions_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect permissions and roles data."""
        roles = await self._authorization_service.get_user_roles(user_id)
        permissions = await self._authorization_service.get_user_permissions(user_id)
        delegations = await self._authorization_service.get_delegated_permissions(user_id)
        
        return {
            "roles": [
                {
                    "id": str(role.id),
                    "name": role.name,
                    "description": role.description,
                    "assigned_at": role.assigned_at.isoformat(),
                    "assigned_by": str(role.assigned_by) if role.assigned_by else None,
                    "expires_at": role.expires_at.isoformat() if role.expires_at else None
                }
                for role in roles
            ],
            "direct_permissions": [
                {
                    "id": str(perm.id),
                    "name": perm.name,
                    "resource": perm.resource,
                    "action": perm.action,
                    "granted_at": perm.granted_at.isoformat(),
                    "granted_by": str(perm.granted_by) if perm.granted_by else None
                }
                for perm in permissions
            ],
            "delegated_permissions": [
                {
                    "id": str(del_.id),
                    "permission": del_.permission,
                    "delegated_by": str(del_.delegated_by),
                    "delegated_at": del_.delegated_at.isoformat(),
                    "expires_at": del_.expires_at.isoformat() if del_.expires_at else None
                }
                for del_ in delegations
            ]
        }
    
    async def _collect_audit_data(
        self,
        user_id: UUID,
        start_date: datetime | None,
        end_date: datetime,
        include_deleted: bool
    ) -> dict[str, Any]:
        """Collect audit log data."""
        # Get audit logs where user is actor
        actor_logs = await self._audit_repository.get_by_actor(
            user_id,
            start_date,
            end_date
        )
        
        # Get audit logs where user is target
        target_logs = await self._audit_repository.get_by_target(
            user_id,
            start_date,
            end_date
        )
        
        return {
            "actions_performed": len(actor_logs),
            "actions_received": len(target_logs),
            "audit_logs": [
                {
                    "id": str(log.id),
                    "timestamp": log.created_at.isoformat(),
                    "action": log.action.value,
                    "actor_id": str(log.actor_id) if log.actor_id else None,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "success": log.success,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "changes": log.changes if include_deleted else self._sanitize_changes(log.changes)
                }
                for log in actor_logs + target_logs
            ]
        }
    
    async def _collect_notification_data(
        self,
        user_id: UUID,
        start_date: datetime | None,
        end_date: datetime
    ) -> dict[str, Any]:
        """Collect notification data."""
        notifications = await self._notification_repository.get_user_notifications(
            user_id,
            start_date,
            end_date
        )
        
        return {
            "total_notifications": len(notifications),
            "unread_count": sum(1 for n in notifications if not n.read),
            "notifications": [
                {
                    "id": str(n.id),
                    "type": n.type.value,
                    "title": n.title,
                    "message": n.message,
                    "created_at": n.created_at.isoformat(),
                    "read": n.read,
                    "read_at": n.read_at.isoformat() if n.read_at else None,
                    "channel": n.channel,
                    "priority": n.priority
                }
                for n in notifications
            ]
        }
    
    async def _collect_preferences_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect user preferences."""
        preferences = await self._user_repository.get_user_preferences(user_id)
        
        return {
            "notification_preferences": preferences.get("notifications", {}),
            "privacy_settings": preferences.get("privacy", {}),
            "ui_preferences": preferences.get("ui", {}),
            "language": preferences.get("language", "en"),
            "timezone": preferences.get("timezone", "UTC"),
            "marketing_consent": preferences.get("marketing_consent", False),
            "data_sharing_consent": preferences.get("data_sharing_consent", False)
        }
    
    async def _collect_security_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect security-related data."""
        security_events = await self._security_service.get_user_security_events(user_id)
        risk_assessments = await self._security_service.get_risk_assessments(user_id)
        
        return {
            "security_events": [
                {
                    "id": str(event.id),
                    "type": event.event_type.value,
                    "severity": event.severity.value,
                    "timestamp": event.created_at.isoformat(),
                    "resolved": event.resolved,
                    "ip_address": event.ip_address,
                    "details": self._sanitize_security_details(event.details)
                }
                for event in security_events
            ],
            "risk_assessments": [
                {
                    "id": str(assessment.id),
                    "timestamp": assessment.assessed_at.isoformat(),
                    "risk_score": assessment.risk_score,
                    "risk_level": assessment.risk_level.value,
                    "factors": assessment.risk_factors
                }
                for assessment in risk_assessments
            ],
            "account_lockouts": await self._security_service.get_lockout_history(user_id),
            "suspicious_activities": await self._security_service.get_suspicious_activities(user_id)
        }
    
    async def _collect_emergency_contacts_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect emergency contacts data."""
        contacts = await self._user_repository.get_emergency_contacts(user_id)
        
        return {
            "emergency_contacts": [
                {
                    "id": str(contact.id),
                    "name": contact.name,
                    "relationship": contact.relationship.value,
                    "phone": contact.phone_number,
                    "email": contact.email,
                    "is_primary": contact.is_primary,
                    "verified": contact.is_verified,
                    "added_at": contact.created_at.isoformat()
                }
                for contact in contacts
            ]
        }
    
    async def _collect_devices_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect device data."""
        devices = await self._security_service.get_user_devices(user_id)
        
        return {
            "registered_devices": [
                {
                    "id": str(device.id),
                    "name": device.device_name,
                    "type": device.device_type.value,
                    "platform": device.platform.value,
                    "trusted": device.trusted,
                    "last_seen": device.last_seen.isoformat(),
                    "registered_at": device.registered_at.isoformat(),
                    "fingerprint": device.device_fingerprint[:8] + "..."  # Partial for security
                }
                for device in devices
            ]
        }
    
    async def _collect_integrations_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect third-party integration data."""
        integrations = await self._user_repository.get_user_integrations(user_id)
        
        return {
            "connected_services": [
                {
                    "id": str(integration.id),
                    "provider": integration.provider,
                    "connected_at": integration.connected_at.isoformat(),
                    "last_sync": integration.last_sync.isoformat() if integration.last_sync else None,
                    "status": integration.status,
                    "scopes": integration.scopes
                }
                for integration in integrations
            ]
        }
    
    async def _collect_gdpr_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect GDPR-specific data."""
        consents = await self._data_privacy_service.get_user_consents(user_id)
        data_requests = await self._data_privacy_service.get_data_requests(user_id)
        
        return {
            "consents": [
                {
                    "id": str(consent.id),
                    "purpose": consent.purpose,
                    "granted": consent.granted,
                    "granted_at": consent.granted_at.isoformat() if consent.granted_at else None,
                    "withdrawn_at": consent.withdrawn_at.isoformat() if consent.withdrawn_at else None,
                    "version": consent.version
                }
                for consent in consents
            ],
            "data_requests": [
                {
                    "id": str(request.id),
                    "type": request.request_type,
                    "submitted_at": request.submitted_at.isoformat(),
                    "completed_at": request.completed_at.isoformat() if request.completed_at else None,
                    "status": request.status
                }
                for request in data_requests
            ],
            "data_retention": await self._data_privacy_service.get_retention_info(user_id),
            "data_portability": {
                "format_available": ["json", "csv", "xml"],
                "machine_readable": True,
                "commonly_used_format": True
            }
        }
    
    def _sanitize_changes(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Sanitize audit log changes to remove sensitive data."""
        sensitive_fields = ["password", "password_hash", "secret", "token", "key"]
        sanitized = {}
        
        for key, value in changes.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_security_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Sanitize security event details."""
        # Remove any sensitive information from security events
        sanitized = details.copy()
        
        sensitive_keys = ["password", "token", "secret", "key", "hash"]
        for key in list(sanitized.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "[REDACTED]"
        
        return sanitized
    
    async def _anonymize_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Anonymize PII in exported data."""
        anonymized = data.copy()
        
        # Define PII fields to anonymize
        pii_fields = [
            "email", "phone_number", "ip_address", "first_name", "last_name",
            "full_name", "address", "date_of_birth", "social_security_number"
        ]
        
        def anonymize_value(value: Any, field_type: str) -> Any:
            """Anonymize a single value based on type."""
            if field_type == "email":
                parts = value.split("@")
                return f"{parts[0][:2]}****@{parts[1]}" if len(parts) == 2 else "****@****.***"
            if field_type == "phone_number":
                return f"***-***-{value[-4:]}" if len(value) >= 4 else "***-***-****"
            if field_type == "ip_address":
                parts = value.split(".")
                return f"{parts[0]}.***.***.***" if len(parts) == 4 else "***.***.***.***"
            if field_type in ["first_name", "last_name"]:
                return f"{value[0]}***" if value else "****"
            return "****"
        
        def anonymize_dict(d: dict[str, Any]) -> dict[str, Any]:
            """Recursively anonymize dictionary."""
            result = {}
            for key, value in d.items():
                if key in pii_fields:
                    result[key] = anonymize_value(value, key)
                elif isinstance(value, dict):
                    result[key] = anonymize_dict(value)
                elif isinstance(value, list):
                    result[key] = [
                        anonymize_dict(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    result[key] = value
            return result
        
        return anonymize_dict(anonymized)
    
    async def _format_data(
        self,
        data: dict[str, Any],
        export_format: ExportFormat,
        include_metadata: bool
    ) -> bytes:
        """Format data for export."""
        if export_format == ExportFormat.JSON:
            return json.dumps(data, indent=2, default=str).encode()
        
        if export_format == ExportFormat.CSV:
            # Flatten nested data and convert to CSV
            import csv
            import io
            
            output = io.StringIO()
            
            # Create separate CSV for each data category
            for category, category_data in data.items():
                if category == "export_metadata" and not include_metadata:
                    continue
                
                if isinstance(category_data, list) and category_data:
                    # Write category header
                    output.write(f"\n# {category.upper()}\n")
                    
                    # Get headers from first item
                    headers = list(category_data[0].keys())
                    writer = csv.DictWriter(output, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(category_data)
                
                elif isinstance(category_data, dict):
                    # Write as key-value pairs
                    output.write(f"\n# {category.upper()}\n")
                    writer = csv.writer(output)
                    for key, value in category_data.items():
                        writer.writerow([key, str(value)])
            
            return output.getvalue().encode()
        
        if export_format == ExportFormat.XML:
            # Convert to XML
            import xml.etree.ElementTree as ET
            from xml.dom import minidom
            
            root = ET.Element("UserDataExport")
            
            def dict_to_xml(parent, data):
                if isinstance(data, dict):
                    for key, value in data.items():
                        child = ET.SubElement(parent, key)
                        dict_to_xml(child, value)
                elif isinstance(data, list):
                    for item in data:
                        item_elem = ET.SubElement(parent, "item")
                        dict_to_xml(item_elem, item)
                else:
                    parent.text = str(data)
            
            dict_to_xml(root, data)
            
            # Pretty print
            xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")  # noqa: S318
            return xml_str.encode()
        
        if export_format == ExportFormat.PDF:
            # This would use a PDF library like ReportLab
            # For now, returning a simple text representation
            pdf_content = "USER DATA EXPORT\n\n"
            pdf_content += f"Generated: {datetime.now(UTC).isoformat()}\n\n"
            
            for category, category_data in data.items():
                pdf_content += f"\n{category.upper()}\n"
                pdf_content += "=" * 50 + "\n"
                pdf_content += json.dumps(category_data, indent=2, default=str)
                pdf_content += "\n"
            
            return pdf_content.encode()
        
        # Default to JSON
        return json.dumps(data, indent=2, default=str).encode()
    
    async def _compress_data(self, data: bytes, export_format: ExportFormat) -> bytes:
        """Compress data for smaller file size."""
        import io
        import zipfile
        
        buffer = io.BytesIO()
        
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            file_extension = "json" if export_format == ExportFormat.ZIP else export_format.value
            zf.writestr(f"user_data_export.{file_extension}", data)
            
            # Add readme
            readme_content = """
USER DATA EXPORT README

This archive contains your personal data export.

Contents:
- user_data_export.*: Your exported data in the requested format

Security Notes:
- This file may contain sensitive personal information
- Store it securely and do not share with unauthorized parties
- The download link will expire in 72 hours
- Password protection is enabled if requested

For questions, contact: privacy@example.com
            """
            zf.writestr("README.txt", readme_content.encode())
        
        return buffer.getvalue()
    
    async def _encrypt_data(
        self,
        data: bytes,
        password: str | None = None
    ) -> tuple[bytes, dict[str, Any]]:
        """Encrypt data for secure storage."""
        if not password:
            password = self._generate_export_password()
        
        encrypted_data = await self._encryption_service.encrypt(
            data,
            password,
            algorithm="AES-256-GCM"
        )
        
        metadata = {
            "encrypted": True,
            "algorithm": "AES-256-GCM",
            "password_hint": f"First 4 chars: {password[:4]}...",
            "encryption_date": datetime.now(UTC).isoformat()
        }
        
        return encrypted_data, metadata
    
    def _generate_export_password(self) -> str:
        """Generate secure password for export."""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(20))
        
    
    def _get_content_type(self, export_format: ExportFormat) -> str:
        """Get content type for export format."""
        content_types = {
            ExportFormat.JSON: "application/json",
            ExportFormat.CSV: "text/csv",
            ExportFormat.XML: "application/xml",
            ExportFormat.PDF: "application/pdf",
            ExportFormat.ZIP: "application/zip"
        }
        
        return content_types.get(export_format, "application/octet-stream")
    
    async def _create_export_record(
        self,
        export_id: UUID,
        command: ExportUserDataCommand
    ) -> dict[str, Any]:
        """Create export record in database."""
        record = {
            "export_id": export_id,
            "user_id": command.target_user_id,
            "requester_id": command.requesting_user_id,
            "data_categories": [c.value for c in command.data_categories],
            "format": command.format.value,
            "status": "processing",
            "created_at": datetime.now(UTC),
            "gdpr_request": command.gdpr_request,
            "metadata": command.metadata
        }
        
        await self._data_privacy_service.create_export_record(record)
        
        return record
    
    async def _update_export_record(
        self,
        export_id: UUID,
        status: str,
        file_size: int | None = None,
        download_url: str | None = None,
        error: str | None = None
    ) -> None:
        """Update export record status."""
        updates = {
            "status": status,
            "updated_at": datetime.now(UTC)
        }
        
        if file_size is not None:
            updates["file_size"] = file_size
        
        if download_url:
            updates["download_url"] = download_url
        
        if error:
            updates["error"] = error
        
        await self._data_privacy_service.update_export_record(export_id, updates)
    
    async def _generate_secure_download_link(
        self,
        storage_url: str,
        export_id: UUID,
        expiry_hours: int = 72
    ) -> str:
        """Generate time-limited secure download link."""
        # This would typically use signed URLs or tokens
        download_token = await self._token_service.generate_download_token(
            export_id,
            expiry_hours
        )
        
        return f"https://app.example.com/api/v1/exports/download/{export_id}?token={download_token}"
    
    async def _send_export_notification(
        self,
        notification_data: dict[str, Any]
    ) -> None:
        """Send export completion notification."""
        await self._email_service.send_email(
            EmailContext(
                recipient=notification_data.get("email", ""),
                template="data_export_complete",
                subject="Your Data Export is Ready",
                variables={
                    "username": notification_data.get("username", ""),
                    "export_id": notification_data.get("export_id", ""),
                    "download_url": notification_data.get("download_url", ""),
                    "expires_in": "72 hours",
                    "password_protected": notification_data.get("password_protected", False),
                    "password_hint": notification_data.get("password_hint", ""),
                    "support_email": "privacy@example.com"
                },
                priority="high"
            )
        )
    
    async def _queue_export_job(
        self,
        export_id: UUID,
        command: ExportUserDataCommand
    ) -> None:
        """Queue large export for async processing."""
        job_data = {
            "export_id": str(export_id),
            "command": command.dict(),
            "queued_at": datetime.now(UTC).isoformat()
        }
        
        await self._queue_service.enqueue(
            "data_exports",
            job_data,
            priority="normal",
            max_retries=3
        )