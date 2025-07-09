"""
Delete user command implementation.

Handles permanent user deletion with GDPR compliance.
"""

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, DeletionReason, UserStatus
from app.modules.identity.domain.events import UserDeleted
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import (
    IEmergencyContactRepository,
)
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import (
    IMFADeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_profile_repository import (
    IUserProfileRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditLogRepository,
    IBackupService,
    ICachePort,
)
    AuthorizationService,
    DataAnonymizationService,
)


class DeleteUserCommand(Command[BaseResponse]):
    """Command to permanently delete a user account."""
    
    def __init__(
        self,
        user_id: UUID,
        reason: DeletionReason,
        details: str | None = None,
        deleted_by: UUID | None = None,
        ip_address: str | None = None,
        gdpr_request: bool = False,
        backup_data: bool = True,
        notify_user: bool = True,
        immediate: bool = False
    ):
        self.user_id = user_id
        self.reason = reason
        self.details = details
        self.deleted_by = deleted_by
        self.ip_address = ip_address
        self.gdpr_request = gdpr_request
        self.backup_data = backup_data
        self.notify_user = notify_user
        self.immediate = immediate


class DeleteUserCommandHandler(CommandHandler[DeleteUserCommand, BaseResponse]):
    """Handler for permanent user deletion."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        profile_repository: IUserProfileRepository,
        session_repository: ISessionRepository,
        mfa_device_repository: IMFADeviceRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        audit_log_repository: IAuditLogRepository,
        authorization_service: AuthorizationService,
        anonymization_service: DataAnonymizationService,
        email_service: IEmailService,
        backup_service: IBackupService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._profile_repository = profile_repository
        self._session_repository = session_repository
        self._mfa_device_repository = mfa_device_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._audit_log_repository = audit_log_repository
        self._authorization_service = authorization_service
        self._anonymization_service = anonymization_service
        self._email_service = email_service
        self._backup_service = backup_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.USER_DELETED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @rate_limit(
        max_requests=1,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        permission="users.delete",
        resource_type="user"
    )
    async def handle(self, command: DeleteUserCommand) -> BaseResponse:
        """
        Permanently delete user with GDPR compliance.
        
        Process:
        1. Load and validate user
        2. Check deletion eligibility
        3. Backup user data if required
        4. Delete related data
        5. Anonymize audit logs
        6. Delete or anonymize user record
        7. Clear all caches
        8. Send notifications
        9. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidOperationError: If cannot be deleted
            UnauthorizedError: If lacks permission
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Check if already deleted
            if user.status == UserStatus.DELETED:
                raise InvalidOperationError("User is already deleted")
            
            # 3. Check deletion eligibility
            if not await self._can_delete_user(user, command):
                raise InvalidOperationError(
                    "User cannot be deleted due to policy restrictions"
                )
            
            # 4. Prepare deletion data for backup
            deletion_data = None
            if command.backup_data:
                deletion_data = await self._prepare_deletion_data(user)
            
            # 5. Send final notification if email still valid
            if command.notify_user and user.email and "@" in user.email:
                with contextlib.suppress(Exception):
                    # Don't fail deletion if notification fails
                    await self._send_deletion_notification(user, command.gdpr_request)
            
            # 6. Delete sessions
            await self._delete_user_sessions(user.id)
            
            # 7. Delete MFA devices
            await self._delete_mfa_devices(user.id)
            
            # 8. Delete emergency contacts
            await self._delete_emergency_contacts(user.id)
            
            # 9. Delete profile
            profile = await self._profile_repository.get_by_user_id(user.id)
            if profile:
                await self._profile_repository.delete(profile.id)
            
            # 10. Anonymize or delete based on requirements
            if command.gdpr_request:
                # GDPR requires data deletion
                await self._hard_delete_user(user)
            else:
                # Soft delete with anonymization
                await self._anonymize_user(user)
            
            # 11. Anonymize audit logs
            await self._anonymize_audit_logs(user.id)
            
            # 12. Backup deletion data
            if deletion_data:
                await self._backup_service.backup_deletion_data(
                    user_id=user.id,
                    data=deletion_data,
                    retention_days=90  # Legal retention period
                )
            
            # 13. Clear all caches
            await self._clear_all_user_data(user.id)
            
            # 14. Publish domain event
            await self._event_bus.publish(
                UserDeleted(
                    aggregate_id=user.id,
                    reason=command.reason,
                    deleted_by=command.deleted_by,
                    gdpr_request=command.gdpr_request,
                    anonymized=not command.gdpr_request
                )
            )
            
            # 15. Commit transaction
            await self._unit_of_work.commit()
            
            return BaseResponse(
                success=True,
                message=f"User account {'deleted' if command.gdpr_request else 'anonymized'} successfully"
            )
    
    async def _can_delete_user(self, user: User, command: DeleteUserCommand) -> bool:
        """Check if user can be deleted based on policies."""
        # Check for active legal holds
        if user.metadata.get("legal_hold"):
            return False
        
        # Check for recent financial transactions
        if user.metadata.get("has_pending_transactions"):
            return False
        
        # GDPR requests override most restrictions
        if command.gdpr_request:
            # Still check for legal requirements
            return not user.metadata.get("legal_retention_required")
        
        # Check account age for non-GDPR deletions
        account_age = datetime.now(UTC) - user.created_at
        return not (account_age < timedelta(days=30) and not command.immediate)
    
    async def _prepare_deletion_data(self, user: User) -> dict[str, Any]:
        """Prepare user data for backup before deletion."""
        profile = await self._profile_repository.get_by_user_id(user.id)
        sessions = await self._session_repository.get_by_user_id(user.id)
        mfa_devices = await self._mfa_device_repository.get_by_user_id(user.id)
        emergency_contacts = await self._emergency_contact_repository.get_by_user_id(user.id)
        
        return {
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.isoformat(),
                "status": user.status.value
            },
            "profile": profile.to_dict() if profile else None,
            "sessions_count": len(sessions),
            "mfa_devices_count": len(mfa_devices),
            "emergency_contacts_count": len(emergency_contacts),
            "deletion_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _delete_user_sessions(self, user_id: UUID) -> None:
        """Delete all user sessions."""
        sessions = await self._session_repository.find_active_by_user(user_id)
        for session in sessions:
            await self._session_repository.delete(session.id)
    
    async def _delete_mfa_devices(self, user_id: UUID) -> None:
        """Delete all MFA devices."""
        devices = await self._mfa_device_repository.get_by_user_id(user_id)
        for device in devices:
            await self._mfa_device_repository.delete(device.id)
    
    async def _delete_emergency_contacts(self, user_id: UUID) -> None:
        """Delete all emergency contacts."""
        contacts = await self._emergency_contact_repository.get_by_user_id(user_id)
        for contact in contacts:
            await self._emergency_contact_repository.delete(contact.id)
    
    async def _hard_delete_user(self, user: User) -> None:
        """Permanently delete user record."""
        await self._user_repository.delete(user.id)
    
    async def _anonymize_user(self, user: User) -> None:
        """Anonymize user data instead of deletion."""
        # Generate anonymous identifiers
        anon_username = f"deleted_user_{user.id.hex[:8]}"
        anon_email = f"deleted_{user.id.hex[:8]}@anonymized.local"
        
        # Update user with anonymized data
        user.username = anon_username
        user.email = anon_email
        user.password_hash = "DELETED"
        user.first_name = None
        user.last_name = None
        user.phone_number = None
        user.avatar_url = None
        user.metadata = {"anonymized": True, "anonymized_at": datetime.now(UTC).isoformat()}
        user.status = UserStatus.DELETED
        
        await self._user_repository.update(user)
    
    async def _anonymize_audit_logs(self, user_id: UUID) -> None:
        """Anonymize audit logs for the user."""
        # Get all audit logs for the user
        as_actor = await self._audit_log_repository.get_by_actor(user_id)
        as_target = await self._audit_log_repository.get_by_resource(
            resource_type="user",
            resource_id=str(user_id)
        )
        
        # Anonymize logs where user is actor
        for log in as_actor:
            await self._anonymization_service.anonymize_audit_log(log)
        
        # Anonymize logs where user is target
        for log in as_target:
            await self._anonymization_service.anonymize_audit_log(log)
    
    async def _clear_all_user_data(self, user_id: UUID) -> None:
        """Clear all cached data for the user."""
        cache_patterns = [
            f"user:{user_id}*",
            f"profile:{user_id}*",
            f"session:*:{user_id}",
            f"permissions:{user_id}*",
            f"roles:{user_id}*",
            f"mfa:{user_id}*"
        ]
        
        for pattern in cache_patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _send_deletion_notification(self, user: User, gdpr_request: bool) -> None:
        """Send account deletion notification."""
        template = "account_deleted_gdpr" if gdpr_request else "account_deleted"
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template=template,
                subject="Your account has been deleted",
                variables={
                    "username": user.username,
                    "deletion_type": "permanently deleted" if gdpr_request else "anonymized",
                    "support_email": "privacy@example.com"
                },
                priority="high"
            )
        )