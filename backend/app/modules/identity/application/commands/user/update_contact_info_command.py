"""
Update contact info command implementation.

Handles updating user contact information with verification.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    ICacheService,
    IEmailService,
    IPhoneService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    require_self_or_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext
from app.modules.identity.application.dtos.request import UpdateContactInfoRequest
from app.modules.identity.application.dtos.response import ContactInfoResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import UserContactInfoUpdated
from app.modules.identity.domain.exceptions import (
    DuplicateResourceError,
    InvalidOperationError,
    UserNotFoundError,
    ValidationError,
)
from app.modules.identity.domain.services import NotificationService, SecurityService
from app.modules.identity.domain.specifications import UserSpecifications


class UpdateContactInfoCommand(Command[ContactInfoResponse]):
    """Command to update user contact information."""
    
    def __init__(
        self,
        user_id: UUID,
        email: str | None = None,
        phone: str | None = None,
        secondary_email: str | None = None,
        secondary_phone: str | None = None,
        skip_verification: bool = False,
        updated_by: UUID | None = None,
        reason: str | None = None
    ):
        self.user_id = user_id
        self.email = email
        self.phone = phone
        self.secondary_email = secondary_email
        self.secondary_phone = secondary_phone
        self.skip_verification = skip_verification
        self.updated_by = updated_by or user_id
        self.reason = reason


class UpdateContactInfoCommandHandler(CommandHandler[UpdateContactInfoCommand, ContactInfoResponse]):
    """Handler for updating contact information."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        security_service: SecurityService,
        notification_service: NotificationService,
        email_service: IEmailService,
        phone_service: IPhoneService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._security_service = security_service
        self._notification_service = notification_service
        self._email_service = email_service
        self._phone_service = phone_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
        self._specifications = UserSpecifications()
    
    @audit_action(
        action=AuditAction.CONTACT_INFO_UPDATED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @require_auth
    @require_self_or_permission(
        permission="users.update_contact",
        resource_type="user",
        resource_id_attr="user_id"
    )
    @validate_request(UpdateContactInfoRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: UpdateContactInfoCommand) -> ContactInfoResponse:
        """
        Update user contact information.
        
        Process:
        1. Validate user exists
        2. Validate new contact info
        3. Check for duplicates
        4. Store pending changes
        5. Send verification requests
        6. Apply immediate changes if admin
        7. Update user record
        8. Send notifications
        9. Clear caches
        10. Publish event
        
        Returns:
            ContactInfoResponse with updated info
            
        Raises:
            UserNotFoundError: If user not found
            ValidationError: If invalid contact info
            DuplicateResourceError: If email/phone already used
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.get_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Track changes
            changes = {}
            verification_needed = {}
            
            # 3. Process email update
            if command.email and command.email != user.email:
                await self._validate_email_update(command.email, user)
                changes['email'] = command.email
                
                if not command.skip_verification and command.updated_by == user.id:
                    verification_needed['email'] = command.email
                else:
                    user.email = command.email
                    user.email_verified = command.skip_verification
            
            # 4. Process phone update
            if command.phone and command.phone != user.phone:
                await self._validate_phone_update(command.phone, user)
                changes['phone'] = command.phone
                
                if not command.skip_verification and command.updated_by == user.id:
                    verification_needed['phone'] = command.phone
                else:
                    user.phone = command.phone
                    user.phone_verified = command.skip_verification
            
            # 5. Process secondary email
            if command.secondary_email is not None:
                if command.secondary_email:
                    await self._validate_secondary_email(command.secondary_email, user)
                changes['secondary_email'] = command.secondary_email
                user.secondary_email = command.secondary_email
            
            # 6. Process secondary phone
            if command.secondary_phone is not None:
                if command.secondary_phone:
                    await self._validate_secondary_phone(command.secondary_phone, user)
                changes['secondary_phone'] = command.secondary_phone
                user.secondary_phone = command.secondary_phone
            
            # 7. Check if any changes
            if not changes:
                return ContactInfoResponse(
                    email=user.email,
                    phone=user.phone,
                    secondary_email=user.secondary_email,
                    secondary_phone=user.secondary_phone,
                    email_verified=user.email_verified,
                    phone_verified=user.phone_verified,
                    success=True,
                    message="No changes to update"
                )
            
            # 8. Send verification requests
            if verification_needed:
                await self._send_verification_requests(
                    user=user,
                    verification_needed=verification_needed
                )
            
            # 9. Update user record
            old_contact_info = {
                'email': user.email,
                'phone': user.phone,
                'secondary_email': user.secondary_email,
                'secondary_phone': user.secondary_phone
            }
            
            user.updated_at = datetime.now(UTC)
            await self._user_repository.update(user)
            
            # 10. Log administrative update
            if command.updated_by != user.id:
                await self._log_admin_update(
                    user=user,
                    changes=changes,
                    updated_by=command.updated_by,
                    reason=command.reason
                )
            
            # 11. Send notifications
            await self._send_update_notifications(
                user=user,
                changes=changes,
                old_contact_info=old_contact_info
            )
            
            # 12. Clear caches
            await self._clear_user_caches(command.user_id)
            
            # 13. Publish event
            await self._event_bus.publish(
                UserContactInfoUpdated(
                    aggregate_id=user.id,
                    old_contact_info=old_contact_info,
                    new_contact_info={
                        'email': user.email,
                        'phone': user.phone,
                        'secondary_email': user.secondary_email,
                        'secondary_phone': user.secondary_phone
                    },
                    changes=changes,
                    updated_by=command.updated_by,
                    verification_pending=verification_needed
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return ContactInfoResponse(
                email=user.email,
                phone=user.phone,
                secondary_email=user.secondary_email,
                secondary_phone=user.secondary_phone,
                email_verified=user.email_verified,
                phone_verified=user.phone_verified,
                pending_email=verification_needed.get('email'),
                pending_phone=verification_needed.get('phone'),
                verification_sent=bool(verification_needed),
                success=True,
                message=self._build_success_message(changes, verification_needed)
            )
    
    async def _validate_email_update(self, email: str, user: User) -> None:
        """Validate email update."""
        # Validate format
        if not await self._email_service.validate_email_format(email):
            raise ValidationError("Invalid email format")
        
        # Check for duplicates
        existing_spec = self._specifications.with_email(email)
        existing = await self._user_repository.find_by_specification(existing_spec)
        
        if any(u.id != user.id for u in existing):
            raise DuplicateResourceError("Email already in use")
        
        # Check if email is blocked
        if await self._security_service.is_email_blocked(email):
            raise InvalidOperationError("Email address is blocked")
    
    async def _validate_phone_update(self, phone: str, user: User) -> None:
        """Validate phone update."""
        # Validate format
        if not await self._phone_service.validate_phone_number(phone):
            raise ValidationError("Invalid phone number format")
        
        # Check for duplicates
        existing_spec = self._specifications.with_phone(phone)
        existing = await self._user_repository.find_by_specification(existing_spec)
        
        if any(u.id != user.id for u in existing):
            raise DuplicateResourceError("Phone number already in use")
    
    async def _validate_secondary_email(self, email: str, user: User) -> None:
        """Validate secondary email."""
        # Can't be same as primary
        if email == user.email:
            raise ValidationError("Secondary email cannot be same as primary")
        
        # Validate format
        if not await self._email_service.validate_email_format(email):
            raise ValidationError("Invalid secondary email format")
    
    async def _validate_secondary_phone(self, phone: str, user: User) -> None:
        """Validate secondary phone."""
        # Can't be same as primary
        if phone == user.phone:
            raise ValidationError("Secondary phone cannot be same as primary")
        
        # Validate format
        if not await self._phone_service.validate_phone_number(phone):
            raise ValidationError("Invalid secondary phone format")
    
    async def _send_verification_requests(
        self,
        user: User,
        verification_needed: dict[str, str]
    ) -> None:
        """Send verification requests for pending changes."""
        for field, value in verification_needed.items():
            if field == 'email':
                # Generate email verification token
                token = await self._security_service.generate_verification_token(
                    user_id=user.id,
                    email=value,
                    purpose='email_change'
                )
                
                # Store pending change
                await self._cache_service.set(
                    key=f"pending_email_change:{user.id}",
                    value={
                        'new_email': value,
                        'token': token,
                        'requested_at': datetime.now(UTC).isoformat()
                    },
                    ttl=86400  # 24 hours
                )
                
                # Send verification email
                await self._email_service.send_email(
                    EmailContext(
                        recipient=value,
                        template="email_change_verification",
                        subject="Verify your new email address",
                        variables={
                            "username": user.username,
                            "verification_link": f"https://app.example.com/verify-email-change?token={token}",
                            "expires_in": "24 hours"
                        },
                        priority="high"
                    )
                )
            
            elif field == 'phone':
                # Generate phone verification code
                code = await self._security_service.generate_secure_code(6)
                
                # Store pending change
                await self._cache_service.set(
                    key=f"pending_phone_change:{user.id}",
                    value={
                        'new_phone': value,
                        'code': code,
                        'attempts': 0,
                        'requested_at': datetime.now(UTC).isoformat()
                    },
                    ttl=3600  # 1 hour
                )
                
                # Send SMS verification
                await self._phone_service.send_sms(
                    phone_number=value,
                    message=f"Your verification code is: {code}. Valid for 1 hour."
                )
    
    async def _send_update_notifications(
        self,
        user: User,
        changes: dict[str, Any],
        old_contact_info: dict[str, Any]
    ) -> None:
        """Send notifications about contact info updates."""
        # Notify old email if email changed
        if 'email' in changes and old_contact_info['email']:
            await self._notification_service.notify_contact_change(
                recipient=old_contact_info['email'],
                user=user,
                change_type='email',
                new_value=changes['email']
            )
        
        # Notify old phone if phone changed
        if 'phone' in changes and old_contact_info['phone']:
            await self._notification_service.notify_contact_change(
                recipient=old_contact_info['phone'],
                user=user,
                change_type='phone',
                new_value=changes['phone']
            )
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear user-related caches."""
        cache_keys = [
            f"user:{user_id}",
            f"user_profile:{user_id}",
            f"user_contact:{user_id}"
        ]
        
        for key in cache_keys:
            await self._cache_service.delete(key)
    
    async def _log_admin_update(
        self,
        user: User,
        changes: dict[str, Any],
        updated_by: UUID,
        reason: str | None
    ) -> None:
        """Log administrative contact update."""
        await self._security_service.log_security_event(
            user_id=user.id,
            event_type="contact_info_updated_by_admin",
            details={
                "updated_by": str(updated_by),
                "changes": list(changes.keys()),
                "reason": reason,
                "verification_skipped": True
            }
        )
    
    def _build_success_message(
        self,
        changes: dict[str, Any],
        verification_needed: dict[str, str]
    ) -> str:
        """Build success message based on changes."""
        if verification_needed:
            pending = list(verification_needed.keys())
            return f"Contact info updated. Verification sent for: {', '.join(pending)}"
        updated = list(changes.keys())
        return f"Contact info updated: {', '.join(updated)}"