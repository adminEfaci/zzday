"""
Verify emergency contact command implementation.

Handles verifying emergency contacts using various verification methods.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import VerifyEmergencyContactRequest
from app.modules.identity.application.dtos.response import (
    EmergencyContactVerificationResponse,
)
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactStatus,
    ContactType,
    NotificationType,
    VerificationMethod,
    VerificationStatus,
)
from app.modules.identity.domain.events import EmergencyContactVerified
from app.modules.identity.domain.exceptions import (
    EmergencyContactNotFoundError,
    InvalidVerificationCodeError,
    TooManyVerificationAttemptsError,
    UserNotFoundError,
    VerificationExpiredError,
    VerificationNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import (
    IEmergencyContactRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
    ISMSService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
    IVerificationRepository,
)
    ContactVerificationService,
    SecurityService,
    ValidationService,
)


class VerifyEmergencyContactCommand(Command[EmergencyContactVerificationResponse]):
    """Command to verify an emergency contact."""
    
    def __init__(
        self,
        contact_id: UUID | None = None,
        verification_code: str | None = None,
        verification_token: str | None = None,
        verification_method: VerificationMethod = VerificationMethod.CODE,
        verified_by: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_info: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.contact_id = contact_id
        self.verification_code = verification_code.strip().upper() if verification_code else None
        self.verification_token = verification_token
        self.verification_method = verification_method
        self.verified_by = verified_by
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.device_info = device_info or {}
        self.metadata = metadata or {}


class VerifyEmergencyContactCommandHandler(CommandHandler[VerifyEmergencyContactCommand, EmergencyContactVerificationResponse]):
    """Handler for verifying emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        verification_repository: IVerificationRepository,
        validation_service: ValidationService,
        contact_verification_service: ContactVerificationService,
        security_service: SecurityService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._verification_repository = verification_repository
        self._validation_service = validation_service
        self._contact_verification_service = contact_verification_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_CONTACT_VERIFIED,
        resource_type="emergency_contact",
        include_request=True,
        include_response=True
    )
    @validate_request(VerifyEmergencyContactRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='ip'
    )
    @require_permission("emergency_contacts.verify")
    async def handle(self, command: VerifyEmergencyContactCommand) -> EmergencyContactVerificationResponse:
        """
        Verify emergency contact with comprehensive validation.
        
        Process:
        1. Load contact and validation
        2. Find verification record
        3. Validate verification attempt
        4. Check rate limits
        5. Verify code/token
        6. Update contact status
        7. Send notifications
        8. Log verification
        
        Returns:
            EmergencyContactVerificationResponse with verification details
            
        Raises:
            EmergencyContactNotFoundError: If contact not found
            VerificationNotFoundError: If verification not found
            VerificationExpiredError: If verification expired
            InvalidVerificationCodeError: If code invalid
            TooManyVerificationAttemptsError: If too many attempts
        """
        async with self._unit_of_work:
            # 1. Load contact
            contact = await self._emergency_contact_repository.find_by_id(command.contact_id)
            if not contact:
                raise EmergencyContactNotFoundError(f"Emergency contact {command.contact_id} not found")
            
            # 2. Load user
            user = await self._user_repository.find_by_id(contact.user_id)
            if not user:
                raise UserNotFoundError(f"User {contact.user_id} not found")
            
            # 3. Find verification record
            verification = await self._find_active_verification(
                contact.id,
                command.verification_method
            )
            
            if not verification:
                raise VerificationNotFoundError("No active verification found for this contact")
            
            # 4. Check if verification is expired
            if verification.expires_at and verification.expires_at < datetime.now(UTC):
                await self._mark_verification_expired(verification)
                raise VerificationExpiredError("Verification code has expired")
            
            # 5. Check rate limits for verification attempts
            await self._check_verification_rate_limits(
                contact.id,
                command.ip_address,
                verification.id
            )
            
            # 6. Validate verification code/token
            verification_valid = await self._validate_verification(
                verification,
                command
            )
            
            if not verification_valid:
                await self._record_failed_verification_attempt(
                    verification,
                    command
                )
                raise InvalidVerificationCodeError("Invalid verification code")
            
            # 7. Check if already verified
            if contact.is_verified:
                return EmergencyContactVerificationResponse(
                    contact_id=contact.id,
                    user_id=contact.user_id,
                    verification_status=VerificationStatus.ALREADY_VERIFIED,
                    verified_at=contact.verified_at,
                    verification_method=command.verification_method,
                    message="Emergency contact was already verified"
                )
            
            # 8. Mark contact as verified
            contact.is_verified = True
            contact.verified_at = datetime.now(UTC)
            contact.verified_by = command.verified_by
            contact.status = ContactStatus.VERIFIED
            contact.verification_method = command.verification_method
            
            # Update metadata
            contact.metadata.update({
                "verification_ip": command.ip_address,
                "verification_user_agent": command.user_agent,
                "verification_device_info": command.device_info
            })
            
            await self._emergency_contact_repository.update(contact)
            
            # 9. Mark verification as used
            verification.status = VerificationStatus.USED
            verification.used_at = datetime.now(UTC)
            verification.used_by_ip = command.ip_address
            await self._verification_repository.update(verification)
            
            # 10. Invalidate other pending verifications for this contact
            await self._invalidate_other_verifications(contact.id, verification.id)
            
            # 11. Send verification success notifications
            await self._send_verification_success_notifications(
                user,
                contact,
                command
            )
            
            # 12. Check if this makes contact primary eligible
            if not contact.is_primary:
                await self._check_primary_contact_eligibility(contact)
            
            # 13. Log security event for manual verifications
            if command.verified_by != contact.user_id:
                await self._log_manual_verification(
                    user,
                    contact,
                    command.verified_by,
                    command
                )
            
            # 14. Update user's emergency contact verification status
            await self._update_user_emergency_contact_status(user)
            
            # 15. Publish domain event
            await self._event_bus.publish(
                EmergencyContactVerified(
                    aggregate_id=contact.id,
                    user_id=contact.user_id,
                    contact_type=contact.contact_type,
                    contact_value=self._mask_contact_value(contact.contact_value),
                    verification_method=command.verification_method,
                    verified_by=command.verified_by,
                    is_primary=contact.is_primary
                )
            )
            
            # 16. Commit transaction
            await self._unit_of_work.commit()
            
            # 17. Return response
            return EmergencyContactVerificationResponse(
                contact_id=contact.id,
                user_id=contact.user_id,
                verification_status=VerificationStatus.VERIFIED,
                verified_at=contact.verified_at,
                verification_method=command.verification_method,
                is_primary=contact.is_primary,
                contact_type=contact.contact_type,
                contact_value=self._mask_contact_value(contact.contact_value),
                message="Emergency contact verified successfully"
            )
    
    async def _find_active_verification(
        self,
        contact_id: UUID,
        method: VerificationMethod
    ) -> Any | None:
        """Find active verification for contact."""
        return await self._verification_repository.find_active_by_contact_and_method(
            contact_id,
            method
        )
    
    async def _check_verification_rate_limits(
        self,
        contact_id: UUID,
        ip_address: str | None,
        verification_id: UUID
    ) -> None:
        """Check rate limits for verification attempts."""
        # Check attempts per contact
        contact_attempts = await self._verification_repository.count_attempts_by_contact(
            contact_id,
            window_minutes=60
        )
        
        if contact_attempts >= 10:
            raise TooManyVerificationAttemptsError(
                "Too many verification attempts for this contact"
            )
        
        # Check attempts per IP
        if ip_address:
            ip_attempts = await self._verification_repository.count_attempts_by_ip(
                ip_address,
                window_minutes=60
            )
            
            if ip_attempts >= 20:
                raise TooManyVerificationAttemptsError(
                    "Too many verification attempts from this IP address"
                )
        
        # Check attempts for this specific verification
        verification_attempts = await self._verification_repository.count_attempts_by_verification(
            verification_id
        )
        
        if verification_attempts >= 5:
            await self._mark_verification_expired(verification_id)
            raise TooManyVerificationAttemptsError(
                "Too many attempts for this verification code"
            )
    
    async def _validate_verification(
        self,
        verification: Any,
        command: VerifyEmergencyContactCommand
    ) -> bool:
        """Validate verification code or token."""
        if command.verification_method == VerificationMethod.CODE:
            return await self._contact_verification_service.verify_code(
                verification.id,
                command.verification_code
            )
        
        if command.verification_method == VerificationMethod.LINK:
            return await self._contact_verification_service.verify_token(
                verification.id,
                command.verification_token
            )
        
        # Manual verification by authorized personnel
        return command.verification_method == VerificationMethod.MANUAL
    
    async def _record_failed_verification_attempt(
        self,
        verification: Any,
        command: VerifyEmergencyContactCommand
    ) -> None:
        """Record failed verification attempt."""
        await self._verification_repository.record_attempt(
            verification.id,
            success=False,
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            attempted_code=command.verification_code,
            failure_reason="Invalid code"
        )
    
    async def _mark_verification_expired(self, verification: Any) -> None:
        """Mark verification as expired."""
        verification.status = VerificationStatus.EXPIRED
        verification.expired_at = datetime.now(UTC)
        await self._verification_repository.update(verification)
    
    async def _invalidate_other_verifications(
        self,
        contact_id: UUID,
        exclude_verification_id: UUID
    ) -> None:
        """Invalidate other pending verifications for contact."""
        other_verifications = await self._verification_repository.find_pending_by_contact(
            contact_id,
            exclude_verification_id
        )
        
        for verification in other_verifications:
            verification.status = VerificationStatus.SUPERSEDED
            verification.superseded_at = datetime.now(UTC)
            await self._verification_repository.update(verification)
    
    async def _send_verification_success_notifications(
        self,
        user: User,
        contact: EmergencyContact,
        command: VerifyEmergencyContactCommand
    ) -> None:
        """Send notifications about successful verification."""
        # Notify the verified contact
        if contact.contact_type == ContactType.EMAIL:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_verified",
                    subject="Emergency Contact Verified Successfully",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "user_email": user.email,
                        "verification_date": contact.verified_at.isoformat(),
                        "contact_role": contact.relationship.value,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_verified",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "verification_date": contact.verified_at.strftime("%Y-%m-%d %H:%M")
                    }
                )
            )
        
        # Notify user about successful verification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.EMERGENCY_CONTACT_VERIFIED,
                channel="in_app",
                template_id="emergency_contact_verified_user",
                template_data={
                    "contact_name": contact.contact_name,
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "verification_method": command.verification_method.value,
                    "is_primary": contact.is_primary
                },
                priority="medium"
            )
        )
        
        # Send email to user if different from contact
        if user.email_verified and user.email != contact.contact_value:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="emergency_contact_verified_notification",
                    subject="Emergency Contact Verified",
                    variables={
                        "username": user.username,
                        "contact_name": contact.contact_name,
                        "contact_type": contact.contact_type.value,
                        "contact_value": self._mask_contact_value(contact.contact_value),
                        "verification_method": command.verification_method.value,
                        "manage_contacts_link": "https://app.example.com/settings/emergency-contacts"
                    }
                )
            )
    
    async def _check_primary_contact_eligibility(self, contact: EmergencyContact) -> None:
        """Check if verified contact should become primary."""
        # Get other contacts of same type
        same_type_contacts = await self._emergency_contact_repository.find_by_user_and_type(
            contact.user_id,
            contact.contact_type
        )
        
        # If no primary contact exists, make this one primary
        has_primary = any(c.is_primary for c in same_type_contacts if c.id != contact.id)
        
        if not has_primary and contact.priority <= 3:  # High priority contacts
            contact.is_primary = True
            await self._emergency_contact_repository.update(contact)
    
    async def _log_manual_verification(
        self,
        user: User,
        contact: EmergencyContact,
        verified_by: UUID,
        command: VerifyEmergencyContactCommand
    ) -> None:
        """Log manual verification by admin."""
        await self._audit_service.log_administrative_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACT_VERIFIED,
                actor_id=verified_by,
                target_user_id=user.id,
                resource_type="emergency_contact",
                resource_id=contact.id,
                details={
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "verification_method": command.verification_method.value,
                    "manual_verification": True,
                    "ip_address": command.ip_address,
                    "user_agent": command.user_agent
                },
                risk_level="medium"
            )
        )
    
    async def _update_user_emergency_contact_status(self, user: User) -> None:
        """Update user's overall emergency contact verification status."""
        verified_contacts = await self._emergency_contact_repository.count_verified_by_user(user.id)
        total_contacts = await self._emergency_contact_repository.count_active_by_user(user.id)
        
        # Update user metadata
        user.metadata["emergency_contacts"] = {
            "total": total_contacts,
            "verified": verified_contacts,
            "verification_complete": verified_contacts > 0,
            "last_verification": datetime.now(UTC).isoformat()
        }
        
        await self._user_repository.update(user)
    
    def _mask_contact_value(self, contact_value: str) -> str:
        """Mask contact value for logging/display purposes."""
        if "@" in contact_value:  # Email
            parts = contact_value.split("@")
            if len(parts[0]) > 3:
                masked_local = parts[0][:2] + "*" * (len(parts[0]) - 4) + parts[0][-2:]
            else:
                masked_local = parts[0][0] + "*" * (len(parts[0]) - 1)
            return f"{masked_local}@{parts[1]}"
        # Phone
        if len(contact_value) > 4:
            return contact_value[:2] + "*" * (len(contact_value) - 4) + contact_value[-2:]
        return "*" * len(contact_value)